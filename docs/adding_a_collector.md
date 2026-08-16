# Adding a New Collector and Its Analyzer

This guide explains how to add a new AWS service to the cost optimizer.

## 1. The pipeline you plug into

```
AWS Cost Explorer
        ↓
CostRecord
        ↓
CollectionPlanner  ── reads resource_catalog.yaml
        ↓
Service Collector  ── discovers current resources + metrics
        ↓
Common Reconciliation  (analysis/reconciliation.py)
        ↓
Validation findings  (collection/validation.py)
        ↓
FindingEngine  ── runs service analyzers on current resources
        ↓
RecommendationEngine
        ↓
UI / summary.txt
```

Key rule: **a collector only reports what exists now. It never decides
whether something deserves a finding or recommendation.** That decision
belongs to the reconciliation layer and the service analyzer.

## 2. Files you create

For a service called `my_service` with resource type `my_service_resource`:

| File | Purpose |
|------|---------|
| `aws_cost_optimizer/collectors/services/my_service.py` | AWS discovery + metrics |
| `aws_cost_optimizer/analysis/analyzers/my_service.py` | Optimization rules on current resources |

## 3. Files you edit

| File | Change |
|------|--------|
| `aws_cost_optimizer/planner/resource_catalog.yaml` | Map billing patterns → collector |
| `aws_cost_optimizer/recommendations/engine.py` | Add a recommendation handler (optional) |
| `aws_cost_optimizer/inspection/exporter.py` | Add a finding title (optional) |
| `backend/api/services/finding_presentation.py` | Add a finding title (optional) |
| `frontend/src/data/findings.js` | Add a finding title (optional) |

## 4. Step 1 — Write the collector

Create `aws_cost_optimizer/collectors/services/my_service.py`:

```python
"""
MyService collector.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register
from collectors.metrics.cloudwatch import CloudWatchMetricCollector


@register
class MyServiceCollector(BaseCollector):

    key = "my_service"                 # must match resource_catalog.yaml collector.key
    resource_type = "my_service_resource"

    CLOUDWATCH_METRICS = [
        {
            "name": "SomeMetric",
            "statistic": "Average",
            "unit": "Count",
            "key": "some_metric",
        },
    ]

    def __init__(self, scan, region=None, profile=None):
        super().__init__(scan=scan, region=region, profile=profile)
        self.client = get_client("myservice", self.region)
        self._metric_collector = CloudWatchMetricCollector(
            get_client("cloudwatch", self.region)
        )

    def discover(self) -> List[Dict[str, Any]]:
        # Return raw AWS API items (e.g. describe_* responses).
        return []

    def get_resource_id(self, resource: Dict[str, Any]) -> str:
        # Return a stable unique identifier for the resource.
        return resource.get("arn") or resource.get("id")

    def collect_identity(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": resource.get("name"),
            "arn": resource.get("arn"),
            "status": resource.get("status"),
        }

    def collect_configuration(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        # Return the configuration the analyzer will inspect.
        return {
            "instance_type": resource.get("instanceType"),
            "region": self.region,
        }
```

The `BaseCollector` contract (see `collectors/base.py`) drives the rest:
discovery, identity, configuration, metrics, and topology are combined by
`CollectorManager` into a resource dict with this shape:

```python
{
    "resource_id": "...",
    "resource_type": "my_service_resource",
    "region": "eu-west-1",
    "configuration": {...},   # from collect_configuration
    "observations": {
        "cloudwatch": {"metrics": {...}},
        "data_quality": {...},
    },
    "topology": {...},
    "cost_context": {...},    # injected by main.py from the collection plan
}
```

## 5. Step 2 — Register the collector in the planner

Add an entry to `aws_cost_optimizer/planner/resource_catalog.yaml`:

```yaml
my_service_resource:
  category: compute
  billing:
    services:
      - Amazon MyService
    usage_patterns:
      - "*MyService*"
  collector:
    key: my_service
    resource_type: my_service_resource
```

The `CollectionPlanner` will now create a collection plan whenever the
billing service/usage type matches, and `CollectorManager` will run your
collector automatically.

## 6. Step 3 — Write the analyzer

Create `aws_cost_optimizer/analysis/analyzers/my_service.py`:

```python
"""
MyService optimization analyzer.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import AnalysisContext
from ..finding import Finding
from ..base import Analyzer
from ..registry import register


@register
class MyServiceAnalyzer(Analyzer):

    name = "my_service"
    version = "1.0"
    resource_type = "my_service_resource"

    def supports(self, context: AnalysisContext) -> bool:
        return context.resource_type in ("my_service_resource",)

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        if not self.supports(context):
            return []

        raw_findings = self._run_checks(context.resource)
        return [
            self._to_finding(context, raw)
            for raw in raw_findings
        ]

    def _run_checks(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Example: flag an idle resource.
        cpu = self._metric_value(resource, "SomeMetric")
        if cpu is not None and cpu <= 5.0:
            findings.append(self._finding(
                finding_type="my_service_idle",
                severity="MEDIUM",
                confidence="HIGH",
                resource=resource,
                reason="The MyService resource shows very low activity.",
                conditions=[{
                    "name": "metric_low",
                    "expected": "> 5.0",
                    "actual": cpu,
                    "status": "PASS",
                }],
            ))

        return findings
```

### Analyzer helpers

Use the `AnalysisContext` (see `analysis/context.py`) for safe access:

```python
context.metric_value("SomeMetric")      # float | None
context.metric_available("SomeMetric")  # bool
context.metric_is_zero("SomeMetric")    # bool
context.configuration()                 # dict
context.topology()                      # dict
context.data_quality()                  # dict (alias of collector_data_quality)
context.billing()                       # normalized billing context
```

### The `_finding` and `_to_finding` pattern

Copy the `_finding` / `_to_finding` / `_condition_to_statement` /
`_observation_period` helpers from `analysis/analyzers/rds.py`. They build
the raw finding dict and convert it into a `Finding` with proper evidence.

Important: set `recommendation_eligible` on each finding. The
`RecommendationEngine` only generates a recommendation when this is
explicitly `True`.

## 7. Step 4 — Add a recommendation handler (optional)

If a finding should produce a recommendation, add a rule in
`aws_cost_optimizer/recommendations/engine.py`:

```python
RULES = {
    ...
    "my_service_idle": "_my_service_idle",
}

def _my_service_idle(self, finding):
    return self._build(
        finding=finding,
        title="Review idle MyService resource",
        action="Validate whether the resource is still required before removing it.",
    )
```

The engine already skips findings where `recommendation_eligible is not True`,
so reconciliation-only findings never produce recommendations.

## 8. Step 5 — Add a `title` to each finding

The analyzer owns the finding's semantic meaning, including its
human-readable title. Add `title` in the raw finding dict:

```python
findings.append(self._finding(
    finding_type="my_service_idle",
    title="Idle MyService resource",   # ← human-readable label
    ...
))
```

The `_finding` builder in `rds.py` and `_to_finding()` will pass the
`title` into the `Finding` dataclass automatically. The exporter and
frontend simply print `finding["title"]` — no registry needed.

## 9. How reconciliation treats your service automatically

You do **not** need to write reconciliation logic. The common layer in
`analysis/reconciliation.py` handles every service:

| Situation | Reconciliation status | Analyzer runs? | Recommendation? |
|-----------|----------------------|----------------|-----------------|
| Current resource matches billing identity | `current` | Yes | Yes if eligible |
| Current resource exists but billing identity differs (e.g. `db.t3.large` vs `db.r6g.large`) | `current_mismatch` | Yes (current resource still analyzed) | Yes if eligible |
| Billing exists but no current resource (e.g. deleted EKS cluster) | `historical` | No | No |
| No positive billing amount | `no_cost` | Yes if resources exist | Yes if eligible |
| Cannot classify | `unknown` | No | No |

The `collection/validation.py` layer turns these statuses into
reconciliation findings automatically. Your analyzer only ever sees
**current resources** that passed the `resources_for_analysis` filter.

## 10. Testing checklist

1. Run a scan: `py aws_cost_optimizer/main.py --region eu-west-1`
2. Confirm the collector appears in `COLLECTOR RESULTS` in `scans/scan_*/summary.txt`.
3. Confirm the analyzer findings appear in `FINDINGS`.
4. Confirm eligible findings produce recommendations in `RECOMMENDATIONS`.
5. Confirm a service with zero current resources produces a `historical`
   reconciliation finding and **no** recommendation.