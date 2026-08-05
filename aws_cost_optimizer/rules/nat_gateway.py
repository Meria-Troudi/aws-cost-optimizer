"""
NAT Gateway Rule - evaluates NAT Gateway contexts for optimization opportunities.

Returns finding + recommendation dicts in the new format.
"""


class NATGatewayRule:
    key = "nat_gateway"

    def _to_number(self, val):
        """
        Coerce various metric value shapes into a numeric scalar.
        Handles: int/float, dicts with numeric entries (Sum, Value, value, sum),
        nested dicts, and lists of numeric values (sums them).
        Returns 0 when no numeric value can be extracted.
        """
        if val is None:
            return 0
        if isinstance(val, (int, float)):
            return val
        if isinstance(val, dict):
            # check common keys
            for k in ("value", "Value", "sum", "Sum", "SumBytes", "sumBytes", "Bytes"):
                if k in val and isinstance(val[k], (int, float)):
                    return val[k]
            # otherwise, try to find any numeric in nested values
            for nested in val.values():
                num = self._to_number(nested)
                if num:
                    return num
            return 0
        if isinstance(val, (list, tuple)):
            total = 0
            for item in val:
                total += self._to_number(item)
            return total
        # fallback: can't coerce
        return 0

    def evaluate(self, context):
        """
        Evaluate NAT Gateway context.

        Args:
            context: EvaluationContext with:
                - cost: Monthly cost
                - resources: List of resource dicts with metrics
                - service, region, usage_type: Cost dimensions

        Returns:
            List of finding dicts, each with an optional 'recommendation' key
        """
        findings = []
        cost = context.cost
        resources = context.resources

        if cost < context.cost_threshold:
            return findings

        gateway_count = len(resources)
        total_bytes_out = 0
        total_bytes_in = 0
        active_connections = 0

        for resource in resources:
            metrics = resource.get("metrics", {})
            
            # Metrics are now a dict {metric_name: value}
            if isinstance(metrics, dict):
                bytes_out = self._to_number(metrics.get("BytesOutToDestination", 0))
                bytes_in = self._to_number(metrics.get("BytesInFromSource", 0))
                connections = self._to_number(metrics.get("ActiveConnectionCount", 0))

                total_bytes_out += bytes_out
                total_bytes_in += bytes_in
                active_connections += connections
            else:
                # Backward compatibility: handle list format
                for metric_data in metrics:
                    metric_name = metric_data.get("metric_name")
                    value = metric_data.get("value", 0)
                    
                    if metric_name == "BytesOutToDestination":
                        total_bytes_out += value if value else 0
                    elif metric_name == "BytesInFromSource":
                        total_bytes_in += value if value else 0
                    elif metric_name == "ActiveConnectionCount":
                        active_connections += value if value else 0

        # Determine severity based on metrics
        if total_bytes_out == 0 and total_bytes_in == 0:
            severity = "high"
            priority = "critical"
        elif gateway_count > 3:
            severity = "medium"
            priority = "high"
        else:
            severity = "low"
            priority = "medium"

        evidence = {
            "service": context.service,
            "region": context.region,
            "usage_type": context.usage_type,
            "monthly_cost": cost,
            "gateway_count": gateway_count,
            "bytes_out": total_bytes_out,
            "bytes_in": total_bytes_in,
            "active_connections": active_connections,
            "resources": [r.get("resource_id") for r in resources],
        }

        findings.append({
            "finding_type": "cost_optimization",
            "title": f"High NAT Gateway cost detected ({gateway_count} gateways, ${cost:.2f}/month)",
            "description": (
                f"{gateway_count} NAT Gateway(s) in {context.region} "
                f"costing ${cost:.2f}/month. "
                f"Bytes out: {total_bytes_out}, Bytes in: {total_bytes_in}, "
                f"Active connections: {active_connections}."
            ),
            "severity": severity,
            "evidence": evidence,
        })

        return findings