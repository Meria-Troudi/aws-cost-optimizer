# NAT Gateway Architecture Changes - v8.0

## Summary of Changes

This document describes the architectural changes made to remove cost/billing data from resource-level findings and establish proper separation of concerns.

## Core Principles

1. **Resource findings describe usage, configuration, topology, and utilization** - NOT cost
2. **Billing remains a separate dataset** at the account/region/usage-type level
3. **Analyzer answers**: "What is happening?"
4. **Recommendation answers**: "What should be investigated?"
5. **Cost engine answers**: "How much could this save?" (future layer)

## Model Changes

### Evidence Model (`aws_cost_optimizer/analysis/evidence.py`)

**Before:**
```python
@dataclass(slots=True)
class Evidence:
    metrics: dict[str, Any]
    configuration: dict[str, Any]
    topology: dict[str, Any]
    billing: dict[str, Any]  # ❌ REMOVED
    resource: dict[str, Any]
    derived: dict[str, Any]
    data_quality: dict[str, Any]
```

**After:**
```python
@dataclass(slots=True)
class Evidence:
    metrics: dict[str, Any]
    configuration: dict[str, Any]
    topology: dict[str, Any]
    resource: dict[str, Any]
    derived: dict[str, Any]
    data_quality: dict[str, Any]
```

### Finding Model (`aws_cost_optimizer/analysis/finding.py`)

**Before:**
```python
@dataclass(slots=True)
class Finding:
    # ... other fields ...
    cost_context: dict[str, Any]  # ❌ REMOVED
    metadata: dict[str, Any]
```

**After:**
```python
@dataclass(slots=True)
class Finding:
    # ... other fields ...
    metadata: dict[str, Any]
```

## NAT Gateway Analyzer Changes

### Metrics Reduction: 10 → 5

**Before (10 metrics):**
- BytesInFromSource, BytesOutToDestination, BytesInFromDestination, BytesOutToSource
- ActiveConnectionCount, ConnectionAttemptCount, ConnectionEstablishedCount
- PacketsDropCount, ErrorPortAllocation, PeakBytesPerSecond

**After (5 essential metrics):**
```python
NAT_GATEWAY_METRICS = {
    "BytesOutToDestination": "Sum",      # Outbound traffic
    "BytesOutToSource": "Sum",           # Return traffic
    "ActiveConnectionCount": "Maximum",  # Active connections
    "ConnectionAttemptCount": "Sum",     # Connection attempts
    "ConnectionEstablishedCount": "Sum", # Established connections
}
```

### Removed Methods

- `_build_cost_drivers()` - No longer builds cost information into findings
- `_billing_summary()` - No longer includes billing context in reason strings
- `_detect_multiple_gateways()` - Removed as a separate finding type

### Finding Types

**Before (6 types):**
1. `nat_gateway_no_observed_activity`
2. `nat_gateway_low_utilization`
3. `nat_gateway_high_traffic` (disabled)
4. `nat_gateway_aws_service_traffic`
5. `nat_gateway_cross_az`
6. `nat_gateway_multiple_gateways` ❌ REMOVED

**After (4 types):**
1. `nat_gateway_no_observed_activity` - Means exactly "no observed activity", NOT "safe to delete"
2. `nat_gateway_low_utilization` - Separate finding for low usage
3. `nat_gateway_aws_service_traffic` - AWS services via NAT
4. `nat_gateway_cross_az` - Cross-AZ routing

## Aggregation Changes

### FindingAggregator (`aws_cost_optimizer/analysis/aggregation.py`)

**Removed:**
- `cost_contexts` field from aggregated output
- `cost_total` from `_aggregate_evidence()`
- All cost-related aggregation logic

**Now aggregates:**
- Traffic metrics (bytes, GiB)
- Resource counts
- Traffic availability/activity status

### FindingStore (`aws_cost_optimizer/analysis/finding_store.py`)

**Replaced with:**
```python
class FindingStore:
    def __init__(self) -> None:
        raise NotImplementedError(
            "FindingStore has been removed. "
            "Use FindingAggregator for aggregation."
        )
```

## Recommendation Engine Changes

### Removed Assumptions

**Before:**
- Calculated `estimated_monthly_savings`
- Included specific cost implications based on resource-level billing
- Had `nat_gateway_multiple_gateways` recommendation

**After:**
- `estimated_monthly_savings: None` - Savings not calculated at resource level
- Cost implications state: "must be calculated separately using applicable billing data"
- Focus on validation steps and architecture review

### Updated Rules

```python
RULES = {
    "nat_gateway_no_activity": "_nat_no_activity",
    "nat_gateway_low_utilization": "_nat_low_utilization",
    "nat_gateway_aws_service_traffic": "_nat_aws_service",
    "nat_gateway_cross_az": "_nat_cross_az",
}
```

## Collector Changes

### NAT Gateway Collector (`aws_cost_optimizer/collectors/services/nat_gateway.py`)

**Added:**
```python
NAT_GATEWAY_METRICS = {
    "BytesOutToDestination": "Sum",
    "BytesOutToSource": "Sum",
    "ActiveConnectionCount": "Maximum",
    "ConnectionAttemptCount": "Sum",
    "ConnectionEstablishedCount": "Sum",
}
```

**Added required persistence fields:**
```python
metrics.append({
    "metric_name": metric_name,
    "value": value,
    "statistic": statistic,
    "namespace": namespace,
    "unit": self._unit(metric_name),
    "has_data": value is not None,
    "metric_start": start.isoformat(),  # ✅ ADDED
    "metric_end": end.isoformat(),      # ✅ ADDED
    "period": requested_period,         # ✅ ADDED
})
```

## Data Flow (New Architecture)

```
┌─────────────────────────────────────────────────────────────┐
│ AWS ACCOUNT                                                  │
└─────────────────────────────────────────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
      COST COLLECTORS             RESOURCE COLLECTORS
            │                           │
            ▼                           ▼
      Billing Dataset             Resource Dataset
            │                           │
            │                 ┌─────────┼─────────┐
            │                 │         │         │
            │              Metrics  Config    Topology
            │                 │         │         │
            │                 └────┬────┴─────────┘
            │                      │
            │                      ▼
            │               ANALYSIS ENGINE
            │                      │
            │                   Finding
            │                 (NO COST DATA)
            │                      │
            │                      ▼
            │              FINDING AGGREGATOR
            │                      │
            │                      ▼
            │             RECOMMENDATION ENGINE
            │                 (NO SAVINGS)
            │                      │
            └──────────────┬───────┘
                           ▼
                  COST / SAVINGS ENGINE
                 (Future - joins billing
                  with findings)
```

## Key Behavioral Changes

### No Activity Finding

**Before:** "NAT Gateway has no traffic. Billing context: EU-NatGateway-Hours = $463.25. Safe to delete."

**After:** "NAT Gateway had no observed NAT traffic during the observation period."

**Limitations now include:**
- "No observed activity does not prove that the NAT Gateway is unnecessary."
- "The observation period may not include scheduled or intermittent workloads."
- "Route tables, private subnets and dependent workloads must be checked before removal."

### Evidence Structure

**Before:**
```python
{
    "metrics": {...},
    "configuration": {...},
    "topology": {...},
    "billing": {...},        # ❌ REMOVED
    "resource": {...},
    "derived": {
        "cost_drivers": [...] # ❌ REMOVED
    },
    "data_quality": {...}
}
```

**After:**
```python
{
    "metrics": {...},
    "configuration": {...},
    "topology": {...},
    "resource": {...},
    "derived": {
        "outbound_bytes": ...,
        "return_bytes": ...,
        "traffic_bytes": ...,
        "traffic_gib": ...,
        "traffic_observed": ...,
        "traffic_available": ...,
        "traffic_source": ...,
        "connection_observed": ...,
        "aws_service_destinations": [...],
        "existing_vpc_endpoint_services": [...],
        "cross_az": ...,
        "private_subnet_count": ...
    },
    "data_quality": {...}
}
```

## Testing

All tests pass:
```bash
py test_nat_analysis.py
```

**Test coverage:**
- ✅ Idle detection (no traffic)
- ✅ Low utilization detection
- ✅ AWS service traffic detection
- ✅ Cross-AZ detection
- ✅ Missing metrics handling
- ✅ Traffic calculation (outbound + inbound)
- ✅ No billing in findings
- ✅ Five metrics only
- ✅ Recommendation generation
- ✅ Evidence structure validation

## Migration Guide

### For Analyzers

**Before:**
```python
def _finding(..., cost_context: dict[str, Any]):
    return Finding(
        ...
        cost_context=cost_context,  # ❌ REMOVED
        ...
    )
```

**After:**
```python
def _finding(...):
    return Finding(
        ...
        # No cost_context parameter
        ...
    )
```

### For Recommendations

**Before:**
```python
cost_implication = (
    f"Potential savings: ${cost} per month"
)
```

**After:**
```python
cost_implication = (
    "Potential savings must be calculated "
    "separately using the applicable billing data."
)
```

## Benefits

1. **Cleaner separation of concerns** - Analysis doesn't need billing data
2. **More accurate findings** - No false precision from attaching costs to resources
3. **Easier testing** - No need to mock billing data for analyzer tests
4. **Flexible cost analysis** - Can join billing with findings in multiple ways
5. **Better architecture** - Each layer has a single responsibility

## Future Enhancements

1. **Cost/Savings Engine** - Separate layer that joins:
   - Billing dataset (service, usage_type, region, amount)
   - Findings dataset (resource_id, finding_type, traffic_gib)
   - Calculates savings based on billing scope

2. **Additional Metrics** (when needed):
   - `PacketsDropCount` - For reliability analysis
   - `ErrorPortAllocation` - For troubleshooting
   - `PeakBytesPerSecond` - For performance analysis

3. **High Traffic Rule** - Re-enable when:
   - Observation period normalization is implemented
   - Cost modeling is available
   - Economic thresholds are defined