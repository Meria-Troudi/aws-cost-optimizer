"""
CloudWatch metric semantics for analysis.
"""

from __future__ import annotations

from typing import Any


def metric_status(metric: dict[str, Any] | None) -> str:
    """
    Return a simple metric state.

    observed -> metric has datapoints and a numeric value
    zero     -> metric has datapoints and numeric value is zero
    missing  -> metric has no observed datapoints
    unknown  -> metric exists but cannot be evaluated
    """
    if not metric:
        return "missing"

    if metric.get("status") != "ok":
        return "missing"

    if metric.get("has_data") is not True:
        return "missing"

    value = metric.get("value")

    if not isinstance(value, (int, float)):
        return "unknown"

    if float(value) == 0:
        return "zero"

    return "observed"


def metric_has_observed_data(
    metric: dict[str, Any] | None,
) -> bool:
    if not metric:
        return False

    return (
        metric.get("status") == "ok"
        and metric.get("has_data") is True
        and isinstance(metric.get("value"), (int, float))
    )


def metric_is_zero(
    metric: dict[str, Any] | None,
) -> bool:
    if not metric_has_observed_data(metric):
        return False

    return float(metric["value"]) == 0.0


def metric_is_detected(
    metric: dict[str, Any] | None,
) -> bool:
    """True when the metric has confirmed datapoints with a non-zero value."""
    return metric_status(metric) == "observed"


def metric_numeric_value(
    metric: dict[str, Any] | None,
) -> float | None:

    if not metric_has_observed_data(metric):
        return None

    value = metric.get("value")

    if isinstance(value, (int, float)):
        return float(value)

    return None


def metric_datapoint_count(
    metric: dict[str, Any] | None,
) -> int:

    if not metric:
        return 0

    datapoints = metric.get("datapoints")

    if isinstance(datapoints, int):
        return datapoints

    raw = metric.get("raw_datapoints")

    if isinstance(raw, list):
        return len(raw)

    return 0


def all_metrics_observed(
    metrics: dict[str, Any],
    names: list[str],
) -> bool:

    return all(
        metric_has_observed_data(
            metrics.get(name)
        )
        for name in names
    )


def any_metric_observed(
    metrics: dict[str, Any],
    names: list[str],
) -> bool:

    return any(
        metric_has_observed_data(
            metrics.get(name)
        )
        for name in names
    )


def all_metrics_zero(
    metrics: dict[str, Any],
    names: list[str],
) -> bool:

    return all(
        metric_is_zero(
            metrics.get(name)
        )
        for name in names
    )


def any_metric_zero(
    metrics: dict[str, Any],
    names: list[str],
) -> bool:

    return any(
        metric_is_zero(
            metrics.get(name)
        )
        for name in names
    )


def sum_observed_values(
    metrics: dict[str, Any],
    names: list[str],
) -> float | None:

    values = [
        metric_numeric_value(
            metrics.get(name)
        )
        for name in names
    ]

    if any(value is None for value in values):
        return None

    return float(sum(values))


def metric_statistic(
    metric: dict[str, Any] | None,
) -> str | None:

    if not metric:
        return None

    value = metric.get("statistic")

    return str(value) if value else None


def metric_is_sum(
    metric: dict[str, Any] | None,
) -> bool:

    return metric_statistic(metric) == "Sum"


def metric_sum_value(
    metric: dict[str, Any] | None,
) -> float | None:

    if not metric_has_observed_data(metric):
        return None

    if not metric_is_sum(metric):
        return None

    return metric_numeric_value(metric)


def sum_sum_metrics(
    metrics: dict[str, Any],
    names: list[str],
) -> float | None:

    values = [
        metric_sum_value(
            metrics.get(name)
        )
        for name in names
    ]

    if any(value is None for value in values):
        return None

    return float(sum(values))


def count_persistable_metrics(
    metrics: dict[str, Any] | list[Any],
) -> int:

    if isinstance(metrics, dict):
        metric_list = list(metrics.values())
    else:
        metric_list = list(metrics or [])

    return sum(
        1
        for metric in metric_list
        if metric_has_observed_data(metric)
    )


def metric_summary(
    metric: dict[str, Any] | None,
) -> dict[str, Any]:

    if not metric:
        return {
            "status": "missing",
            "has_data": False,
            "value": None,
            "datapoints": 0,
        }

    return {
        "status": metric_status(metric),
        "has_data": metric_has_observed_data(metric),
        "value": (
            metric.get("value")
            if metric_has_observed_data(metric)
            else None
        ),
        "datapoints": metric_datapoint_count(metric),
        "requested_period": metric.get(
            "requested_period"
        ),
        "effective_period": metric.get(
            "effective_period"
        ),
        "metric_start": (
            metric.get("metric_start")
            or metric.get("start")
        ),
        "metric_end": (
            metric.get("metric_end")
            or metric.get("end")
        ),
    }