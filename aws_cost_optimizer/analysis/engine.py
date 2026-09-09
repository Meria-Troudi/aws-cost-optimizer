"""
Analysis engine.


"""

from __future__ import annotations

from typing import Any

from . import analyzers as _analyzers  # noqa: F401
from .base import Analyzer
from .billing import billing_usage_types_conflict
from .context import AnalysisContext
from .financial import (
    calculate_savings,
    normalize_financial_impact,
)
from .finding import Finding
from .registry import get_analyzers


class AnalysisEngine:

    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
    ) -> None:

        self.analyzers = analyzers if analyzers is not None else get_analyzers()

    def analyze(
        self,
        resources: list[dict[str, Any]],
        *,
        scan_id: int | str | None = None,
        account_id: str | None = None,
        billing_contexts: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> list[Finding]:

        findings: list[Finding] = []
        stats: dict[str, dict[str, Any]] = {}

        for resource in resources:

            if not isinstance(
                resource,
                dict,
            ):
                continue

            resolved_billing = None

            if billing_contexts:

                entry = billing_contexts.get(
                    (
                        str(resource.get("resource_type") or "unknown"),
                        str(resource.get("resource_id") or "unknown"),
                    )
                )

                if isinstance(entry, dict):
                    resolved_billing = entry.get("billing")

            context = self._build_context(
                resource=resource,
                scan_id=scan_id,
                account_id=account_id,
                cost_context=(
                    resolved_billing
                    if resolved_billing is not None
                    else resource.get("cost_context")
                ),
            )

            for analyzer in self.analyzers:

                stat = stats.setdefault(
                    analyzer.name,
                    {
                        "examined": 0,
                        "supported": 0,
                        "errors": 0,
                        "findings": 0,
                        "last_error": None,
                    },
                )

                stat["examined"] += 1

                try:

                    if not analyzer.supports(context):
                        continue

                except Exception as exc:

                    stat["errors"] += 1
                    stat["last_error"] = f"supports(): {type(exc).__name__}: {exc}"

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} support check failed "
                        f"for {context.resource_id}: {exc}"
                    )

                    continue

                stat["supported"] += 1

                try:

                    results = analyzer.analyze(context)

                except Exception as exc:

                    stat["errors"] += 1
                    stat["last_error"] = f"analyze(): {type(exc).__name__}: {exc}"

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} failed "
                        f"for {context.resource_id}: {exc}"
                    )

                    continue

                if not isinstance(
                    results,
                    list,
                ):

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} returned "
                        "non-list result"
                    )

                    continue

                try:

                    outcome, classify_reason = analyzer.classify(
                        context,
                        results,
                    )

                except Exception as exc:

                    # classify() is a diagnostic hook; a defect in one
                    # overridden implementation must not abort the scan.
                    # Fall back to the conservative default.
                    outcome = (
                        "finding_generated" if results else "no_optimization_match"
                    )
                    classify_reason = None

                outcomes = stat.setdefault(
                    "outcomes",
                    {},
                )
                outcomes[outcome] = (
                    outcomes.get(
                        outcome,
                        0,
                    )
                    + 1
                )

                if outcome == "insufficient_evidence" and classify_reason:

                    reasons = stat.setdefault(
                        "insufficient_reasons",
                        [],
                    )

                    reason_text = str(classify_reason)

                    if reason_text not in reasons:
                        reasons.append(reason_text)

                for finding in results:

                    if not isinstance(
                        finding,
                        Finding,
                    ):

                        print(
                            "[ERROR] Analyzer "
                            f"{analyzer.name} returned "
                            "invalid finding object"
                        )

                        continue

                    self._normalize_finding(
                        finding=finding,
                        context=context,
                        account_id=account_id,
                    )

                    stat["findings"] += 1

                    findings.append(finding)

        self._report_analyzer_health(stats)

        return self._deduplicate_findings(findings)

    @staticmethod
    def _aggregate_analyzer_outcome(
        stat: dict[str, Any],
    ) -> str | None:

        outcomes = stat.get(
            "outcomes",
            {},
        )

        # Any resource for which required evidence was missing wins:
        # the analyzer genuinely could not make a safe decision.
        if outcomes.get("insufficient_evidence"):
            return "insufficient_evidence"

        if outcomes.get("finding_generated"):
            return "finding_generated"

        if outcomes.get("no_optimization_match"):
            return "no_optimization_match"

        return None

    @staticmethod
    def _report_analyzer_health(
        stats: dict[str, dict[str, Any]],
    ) -> None:

        broken: list[str] = []

        for name, stat in sorted(stats.items()):

            examined = stat["examined"]
            errors = stat["errors"]
            supported = stat["supported"]
            found = stat["findings"]

            if examined and errors == examined:
                broken.append(
                    f"  - {name}: failed on all {examined} "
                    f"resource(s); last error -> "
                    f"{stat['last_error']}"
                )
                continue

            outcome = AnalysisEngine._aggregate_analyzer_outcome(stat)

            if outcome == "insufficient_evidence":

                reasons = stat.get("insufficient_reasons") or []

                line = "[WARNING] Analyzer " f"{name}: INSUFFICIENT_EVIDENCE"

                if reasons:
                    line += f" reason: {reasons[0]}"

                print(line)

            elif outcome == "no_optimization_match" and supported and not found:

                print(
                    "[INFO] Analyzer "
                    f"{name} analyzed {supported} resource(s), "
                    "0 findings, status: NO_OPTIMIZATION_MATCH, "
                    "reason: no optimization rule qualified with "
                    "available evidence."
                )

        if broken:

            raise RuntimeError(
                "Analyzer contract failure -- the following "
                "analyzer(s) raised on every resource they were "
                "given and produced no findings:\n"
                + "\n".join(broken)
                + "\nThis is a code defect (wrong signature, "
                "missing attribute, bad argument), not bad data."
            )

    @staticmethod
    def _normalize_finding(
        *,
        finding: Finding,
        context: AnalysisContext,
        account_id: str | None,
    ) -> None:
        if not finding.resource_id:

            finding.resource_id = context.resource_id or "unknown"

        if not finding.resource_type:

            finding.resource_type = context.resource_type or "unknown"
        if not finding.account_id:

            finding.account_id = str(account_id) if account_id is not None else None
        if context.region:

            finding.metadata.setdefault(
                "region",
                context.region,
            )

        if account_id:

            finding.metadata.setdefault(
                "account_id",
                str(account_id),
            )

        billing = context.billing()

        billing_service = billing.get("service")

        if billing_service:

            finding.metadata.setdefault(
                "service",
                str(billing_service),
            )

            finding.metadata.setdefault(
                "billing_service",
                str(billing_service),
            )

        usage_type = billing.get("usage_type")

        if usage_type:

            finding.metadata.setdefault(
                "billing_usage_type",
                str(usage_type),
            )

        if not finding.impact:

            configuration = context.configuration()

            resource_usage_type = (
                configuration.get("billing_usage_type")
                if isinstance(configuration, dict)
                else None
            )

            if billing_usage_types_conflict(
                resource_usage_type,
                billing.get("usage_type"),
            ):
                bucket_amount = billing.get("amount")

                impact = {
                    "observed_monthly_cost": (
                        round(float(bucket_amount), 2)
                        if isinstance(bucket_amount, (int, float))
                        else None
                    ),
                    "estimated_monthly_savings": None,
                    "savings_confidence": None,
                    "savings_basis": "billing_usage_type_mismatch",
                }

                finding.limitations.append(
                    (
                        "The collection plan's billing usage type "
                        f"({billing.get('usage_type')}) does not match "
                        f"this resource's own billing classification "
                        f"({resource_usage_type}), so the observed cost "
                        "is a shared bucket total, not this resource's "
                        "own isolated cost."
                    )
                )
            else:
                # Cost Explorer cost != resource cost. Only a
                # reconciliation-proven claimable_resource_cost may
                # become this finding's observed_monthly_cost; plan /
                # service / historical amounts stay contextual
                # evidence with an explicit basis.
                attributed = (
                    billing.get("attribution_scope") == "resource"
                    and billing.get("resource_cost_attributed") is True
                    and isinstance(
                        billing.get("claimable_resource_cost"),
                        (int, float),
                    )
                    and not isinstance(
                        billing.get("claimable_resource_cost"),
                        bool,
                    )
                )

                if not attributed:

                    bucket_amount = billing.get("amount")

                    impact = {
                        "observed_monthly_cost": (
                            round(float(bucket_amount), 2)
                            if isinstance(bucket_amount, (int, float))
                            else None
                        ),
                        "estimated_monthly_savings": None,
                        "savings_confidence": None,
                        "savings_basis": "cost_not_resource_attributed",
                    }

                else:

                    impact = calculate_savings(
                        billing.get("claimable_resource_cost"),
                        confidence=finding.confidence,
                        attribution_scope="resource",
                        full_elimination=(
                            finding.cost_optimization_type == "elimination"
                        ),
                    )

            currency = billing.get("currency")

            if currency:
                impact["currency"] = str(currency)

            finding.impact = normalize_financial_impact(impact)

        finding.finding_key = finding.finding_key or finding.build_finding_key()

        finding.finding_id = finding.build_stable_id()

    @staticmethod
    def _deduplicate_findings(
        findings: list[Finding],
    ) -> list[Finding]:

        result: list[Finding] = []

        seen: set[
            tuple[
                str,
                str,
                str,
                str,
                str,
            ]
        ] = set()

        for finding in findings:

            key = (
                str(finding.account_id or "unknown"),
                str(finding.finding_key or finding.finding_type),
                str(finding.resource_type or "unknown"),
                str(finding.resource_id or "unknown"),
                str(finding._region() or "unknown"),
            )

            if key in seen:
                continue

            seen.add(key)

            result.append(finding)

        return result

    @staticmethod
    def _build_context(
        resource: dict[str, Any],
        scan_id: int | str | None,
        account_id: str | None,
        cost_context: dict[str, Any] | None = None,
    ) -> AnalysisContext:

        return AnalysisContext(
            resource=resource,
            scan_id=scan_id,
            account_id=account_id,
            observation_period=(resource.get("observation_period")),
            cost_context=(
                cost_context
                if cost_context is not None
                else resource.get("cost_context")
            ),
        )
