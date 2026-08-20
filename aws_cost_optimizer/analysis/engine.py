"""
Analysis engine.

Responsibilities
----------------
- execute analyzers
- normalize raw findings
- ensure stable resource identity
- perform deterministic raw deduplication

Important
---------
This engine NEVER decides aggregation scope.

Each Finding produced here remains a raw resource-level fact,
but `aggregation_scope` is left unset.

FindingAggregator is responsible for deciding whether raw findings
are reported per resource, region, account, or service.
"""

from __future__ import annotations

from typing import Any

from . import analyzers as _analyzers  # noqa: F401
from .base import Analyzer
from .context import AnalysisContext
from .finding import Finding
from .registry import get_analyzers


class AnalysisEngine:

    def __init__(
        self,
        analyzers: list[Analyzer] | None = None,
    ) -> None:

        self.analyzers = (
            analyzers
            if analyzers is not None
            else get_analyzers()
        )
    def analyze(
        self,
        resources: list[dict[str, Any]],
        *,
        scan_id: int | str | None = None,
        account_id: str | None = None,
    ) -> list[Finding]:

        findings: list[Finding] = []

        # Per-analyzer health, used after the loop to turn a silent
        # total failure into a loud one. An analyzer that raises on
        # EVERY resource is a broken contract (wrong signature, missing
        # attribute, bad constructor kwarg), not bad data -- and it
        # would otherwise produce zero findings with no visible error.
        stats: dict[str, dict[str, Any]] = {}

        for resource in resources:

            if not isinstance(
                resource,
                dict,
            ):
                continue

            context = self._build_context(
                resource=resource,
                scan_id=scan_id,
                account_id=account_id,
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

                    if not analyzer.supports(
                        context
                    ):
                        continue

                except Exception as exc:

                    stat["errors"] += 1
                    stat["last_error"] = (
                        f"supports(): {type(exc).__name__}: {exc}"
                    )

                    print(
                        "[ERROR] Analyzer "
                        f"{analyzer.name} support check failed "
                        f"for {context.resource_id}: {exc}"
                    )

                    continue

                stat["supported"] += 1

                try:

                    results = analyzer.analyze(
                        context
                    )

                except Exception as exc:

                    stat["errors"] += 1
                    stat["last_error"] = (
                        f"analyze(): {type(exc).__name__}: {exc}"
                    )

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

                    findings.append(
                        finding
                    )

        self._report_analyzer_health(stats)

        return self._deduplicate_findings(
            findings
        )

    @staticmethod
    def _report_analyzer_health(
        stats: dict[str, dict[str, Any]],
    ) -> None:
        """
        Surface analyzers that failed silently.

        The per-resource handlers above deliberately swallow errors so
        one bad resource cannot abort a scan. That same behaviour hides
        a broken analyzer contract completely: it raises on every
        resource, contributes nothing, and the scan still reports
        success. Two signals are checked here:

        * raised on EVERY resource it saw   -> fatal, raise
        * supported resources but found none -> warn (legitimately
          possible, so never fatal)
        """

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

            if supported and not found and not errors:
                print(
                    f"[WARNING] Analyzer {name} supported "
                    f"{supported} resource(s) but produced no "
                    "findings. This is normal when nothing "
                    "qualifies, but check the analyzer if it is "
                    "unexpected."
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

            finding.resource_id = (
                context.resource_id
                or "unknown"
            )

        if not finding.resource_type:

            finding.resource_type = (
                context.resource_type
                or "unknown"
            )
        if not finding.account_id:

            finding.account_id = (
                str(account_id)
                if account_id is not None
                else None
            )
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

        # ----------------------------------------------------------
        # Billing service is a different axis than the AWS resource
        # type: a NAT Gateway is collected because of the
        # EU-NatGateway-Hours usage type, but bills under
        # "EC2 - Other". Recommendations are presented by billing
        # service, not by usage type, so preserve it here.
        # ----------------------------------------------------------

        billing = context.billing()

        billing_service = billing.get(
            "service"
        )

        if billing_service:

            finding.metadata.setdefault(
                "service",
                str(billing_service),
            )

            finding.metadata.setdefault(
                "billing_service",
                str(billing_service),
            )

        usage_type = billing.get(
            "usage_type"
        )

        if usage_type:

            finding.metadata.setdefault(
                "billing_usage_type",
                str(usage_type),
            )

        # ----------------------------------------------------------
        # IMPORTANT
        #
        # DO NOT set aggregation_scope here.
        #
        # None means:
        #     "the analyzer did not select report scope"
        #
        # The aggregator decides the report scope.
        # Finding identity
        #
        # Raw finding identity always includes resource_id.
        # ----------------------------------------------------------

        finding.finding_key = (
            finding.finding_key
            or finding.build_finding_key()
        )

        finding.finding_id = (
            finding.build_stable_id()
        )
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
                str(
                    finding.account_id
                    or "unknown"
                ),

                str(
                    finding.finding_key
                    or finding.finding_type
                ),

                str(
                    finding.resource_type
                    or "unknown"
                ),

                str(
                    finding.resource_id
                    or "unknown"
                ),

                str(
                    finding._region()
                    or "unknown"
                ),
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                finding
            )

        return result
    @staticmethod
    def _build_context(
        resource: dict[str, Any],
        scan_id: int | str | None,
        account_id: str | None,
    ) -> AnalysisContext:

        return AnalysisContext(
            resource=resource,

            scan_id=scan_id,

            account_id=account_id,

            observation_period=(
                resource.get(
                    "observation_period"
                )
            ),

            cost_context=(
                resource.get(
                    "cost_context"
                )
            ),
        )