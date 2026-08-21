"""
Contract tests for the analyzer layer.

Every failure mode covered here has actually happened in this codebase
and shipped silently, because AnalysisEngine catches per-analyzer
exceptions so a scan reports success while producing nothing.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest
import yaml

# Importing the package registers every analyzer via @register.
import analysis.analyzers  # noqa: F401
from analysis.context import AnalysisContext
from analysis.metrics import metric_summary
from analysis.registry import get_analyzers

ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = (
    ROOT
    / "aws_cost_optimizer"
    / "recommendations"
    / "recommendation_rules.yaml"
)

FINDING_TYPE_RE = re.compile(
    r"finding_type\s*=\s*\(?\s*[\"']([a-z0-9_]+)[\"']"
)

# Analyzers that set recommendation_eligible once in a shared finding
# builder rather than per detector call.
#
# Keys are the analyzer module basename (the analyzers now live in
# domain/subdomain folders, so discovery walks the whole tree).
CENTRAL_ELIGIBILITY = {
    "public_ipv4.py": True,
    "vpc_endpoint.py": False,
    "load_balancer.py": True,
    "nat_gateway.py": True,
}


def _rules() -> dict:
    with open(RULES_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _registered_analyzer_files() -> list[Path]:
    """Source files backing currently-registered analyzers.

    Scanning the whole analyzers/ tree would also pick up scaffolding
    that exists on disk but is never imported/registered (e.g. a
    collector-side resource type not yet wired into the catalog) --
    files that can never emit a finding at runtime. Deriving the file
    set from the live registry keeps this test about what actually
    runs.
    """

    seen: set[Path] = set()
    files: list[Path] = []

    for analyzer in get_analyzers():
        path = Path(inspect.getfile(type(analyzer)))

        if path not in seen:
            seen.add(path)
            files.append(path)

    return sorted(files)


def _emitted_finding_types() -> dict[str, bool | None]:
    """Map finding_type -> recommendation_eligible, parsed from source."""

    emitted: dict[str, bool | None] = {}

    for path in _registered_analyzer_files():
        source = path.read_text(encoding="utf-8")

        for match in FINDING_TYPE_RE.finditer(source):
            tail = source[match.end(): match.end() + 2600]
            flag = re.search(
                r"recommendation_eligible\s*=\s*\(?\s*(True|False)",
                tail,
            )

            if flag:
                eligible = flag.group(1) == "True"
            else:
                eligible = CENTRAL_ELIGIBILITY.get(path.name)

            emitted[match.group(1)] = eligible

    return emitted


@pytest.mark.parametrize(
    "analyzer",
    get_analyzers(),
    ids=lambda a: a.name,
)
def test_analyzer_takes_an_analysis_context(analyzer):
    """
    supports()/analyze() must accept an AnalysisContext.

    The NAT analyzer was once rewritten to take a raw dict. Because the
    engine swallows the resulting AttributeError, every NAT finding
    disappeared from scans with no error message at all.
    """

    empty = AnalysisContext(resource={})

    assert analyzer.supports(empty) in (True, False)


@pytest.mark.parametrize(
    "analyzer",
    get_analyzers(),
    ids=lambda a: a.name,
)
def test_analyzer_returns_a_list(analyzer):
    """analyze() must return a list even for a resource it ignores."""

    result = analyzer.analyze(
        AnalysisContext(resource={"resource_type": "__none__"})
    )

    assert isinstance(result, list)


@pytest.mark.parametrize(
    "analyzer",
    get_analyzers(),
    ids=lambda a: a.name,
)
def test_analyzer_is_registered_with_a_name(analyzer):
    assert analyzer.name and analyzer.name != "unknown"


def test_every_eligible_finding_type_has_a_recommendation_route():
    """
    A recommendation-eligible finding with no route produces a finding
    the UI can never turn into a recommendation -- silently. This broke
    twice when detectors were renamed without updating the catalog.
    """

    routes = _rules().get("routes", {}) or {}

    unrouted = sorted(
        finding_type
        for finding_type, eligible in _emitted_finding_types().items()
        if eligible and finding_type not in routes
    )

    assert not unrouted, (
        "recommendation_eligible findings with no route in "
        f"recommendation_rules.yaml: {unrouted}"
    )


def test_no_route_points_at_a_finding_nobody_emits():
    """A route with no emitter is dead configuration."""

    routes = _rules().get("routes", {}) or {}
    emitted = _emitted_finding_types()

    dead = sorted(r for r in routes if r not in emitted)

    assert not dead, f"routes with no analyzer emitting them: {dead}"


def test_every_route_resolves_to_a_real_variant():
    rules = _rules()
    routes = rules.get("routes", {}) or {}
    catalog = rules.get("recommendations", {}) or {}

    broken = []

    for name, route in routes.items():
        key = route.get("recommendation_key")
        variant = route.get("variant_key")
        definition = catalog.get(key)

        if definition is None:
            broken.append(f"{name}: unknown recommendation_key {key!r}")
            continue

        if variant and variant not in (definition.get("variants") or {}):
            broken.append(f"{name}: unknown variant_key {variant!r}")

    assert not broken, broken


def test_reason_templates_only_use_supported_placeholders():
    """
    RecommendationEngine substitutes {count} and {plural} only. Any
    other placeholder raises KeyError, which is caught -- and the raw
    unrendered template is shown to the user.
    """

    catalog = _rules().get("recommendations", {}) or {}
    allowed = {"count", "plural"}
    bad = []

    for key, definition in catalog.items():
        for variant_key, variant in (
            definition.get("variants") or {}
        ).items():
            for field in ("title", "reason", "action"):
                for placeholder in re.findall(
                    r"\{([a-z_]+)\}",
                    str(variant.get(field) or ""),
                ):
                    if placeholder not in allowed:
                        bad.append(
                            f"{key}.{variant_key}.{field}: "
                            f"{{{placeholder}}}"
                        )

    assert not bad, f"unsupported placeholders: {bad}"


def test_metric_summary_exposes_average_maximum_minimum():
    """
    RDS reads metric.get("maximum") off metric_summary(). While that key
    was missing, cpu_maximum was always None and the null-guard in the
    idle/oversized checks meant they could never produce a finding.
    """

    summary = metric_summary(
        {
            "metric_name": "CPUUtilization",
            "status": "ok",
            "has_data": True,
            "value": 12.5,
            "average": 12.5,
            "maximum": 45.0,
            "minimum": 1.0,
        }
    )

    assert summary["value"] == 12.5
    assert summary["average"] == 12.5
    assert summary["maximum"] == 45.0
    assert summary["minimum"] == 1.0


def test_metric_summary_missing_metric_has_the_same_keys():
    populated = metric_summary({"metric_name": "x", "status": "ok"})
    missing = metric_summary(None)

    for key in ("value", "average", "maximum", "minimum"):
        assert key in populated
        assert key in missing
        assert missing[key] is None
