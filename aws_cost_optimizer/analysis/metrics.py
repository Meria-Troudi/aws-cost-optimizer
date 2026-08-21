"""
CloudWatch metric semantics.
"""

from __future__ import annotations

from typing import Any


def metric_status(
    metric: dict[str, Any] | None,
) -> str:

    if not isinstance(metric, dict):
        return "missing"

    status = metric.get("status")

    if status == "error":
        return "error"

    if status == "invalid_data":
        return "unknown"

    if status in {
        "no_data",
        "missing",
    }:
        return "missing"

    if metric.get("has_data") is not True:
        return "missing"

    value = metric.get("value")

    if not isinstance(
        value,
        (int, float),
    ):
        return "unknown"

    if float(value) == 0.0:
        return "zero"

    return "observed"


def metric_was_queried(
    metric: dict[str, Any] | None,
) -> bool:

    if not isinstance(metric, dict):
        return False

    return bool(
        metric.get("metric_name")
    )


def metric_query_succeeded(
    metric: dict[str, Any] | None,
) -> bool:

    if not metric_was_queried(metric):
        return False

    return (
        metric.get("status")
        != "error"
    )


def metric_has_observed_data(
    metric: dict[str, Any] | None,
) -> bool:

    if not isinstance(metric, dict):
        return False

    # metric_summary() output already carries the correct verdict
    # under "observed", using its own "observed"/"zero"/"missing"/
    # "unknown"/"error" vocabulary -- its "status" is never "ok",
    # so the raw-shape check below would silently return False for
    # every summary, including fully-observed ones. Detect the
    # summary shape (the raw collector output never has this key)
    # and trust its own verdict instead of re-deriving it.
    if "observed" in metric:
        return metric.get("observed") is True

    return (
        metric.get("status") == "ok"
        and metric.get("has_data") is True
        and isinstance(
            metric.get("value"),
            (int, float),
        )
    )


def metric_has_no_observed_data(
    metric: dict[str, Any] | None,
) -> bool:

    return (
        metric_query_succeeded(metric)
        and not metric_has_observed_data(
            metric
        )
    )


def metric_is_zero(
    metric: dict[str, Any] | None,
) -> bool:

    return (
        metric_has_observed_data(metric)
        and float(
            metric["value"]
        ) == 0.0
    )


def metric_is_detected(
    metric: dict[str, Any] | None,
) -> bool:

    return (
        metric_status(metric)
        == "observed"
    )


def metric_numeric_value(
    metric: dict[str, Any] | None,
) -> float | None:

    if not metric_has_observed_data(metric):
        return None

    value = metric.get("value")

    if isinstance(
        value,
        (int, float),
    ):
        return float(value)

    return None


def metric_statistic(
    metric: dict[str, Any] | None,
) -> str | None:

    if not isinstance(metric, dict):
        return None

    value = metric.get(
        "statistic"
    )

    return str(value) if value else None


def metric_is_sum(
    metric: dict[str, Any] | None,
) -> bool:

    return (
        metric_statistic(metric)
        == "Sum"
    )


def metric_sum_value(
    metric: dict[str, Any] | None,
) -> float | None:

    if not metric_has_observed_data(metric):
        return None

    if not metric_is_sum(metric):
        return None

    return metric_numeric_value(metric)


def metric_datapoint_count(
    metric: dict[str, Any] | None,
) -> int:

    if not isinstance(metric, dict):
        return 0

    datapoints = metric.get(
        "datapoints"
    )

    if isinstance(datapoints, int):
        return datapoints

    raw = metric.get(
        "raw_datapoints"
    )

    if isinstance(raw, list):
        return len(raw)

    return 0


def _metric_list(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> list[dict[str, Any]]:

    if isinstance(metrics, dict):

        return [
            metric
            for metric in metrics.values()
            if isinstance(metric, dict)
        ]

    if isinstance(metrics, list):

        return [
            metric
            for metric in metrics
            if isinstance(metric, dict)
        ]

    return []


def count_queried_metrics(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> int:

    return sum(
        metric_was_queried(metric)
        for metric in _metric_list(metrics)
    )


def count_observed_metrics(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> int:

    return sum(
        metric_has_observed_data(metric)
        for metric in _metric_list(metrics)
    )


def count_zero_metrics(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> int:

    return sum(
        metric_is_zero(metric)
        for metric in _metric_list(metrics)
    )


def count_missing_metrics(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> int:

    return sum(
        metric_has_no_observed_data(metric)
        for metric in _metric_list(metrics)
    )


def count_metric_errors(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> int:

    return sum(
        metric_status(metric) == "error"
        for metric in _metric_list(metrics)
    )


def count_persistable_metrics(
    metrics:
        dict[str, Any]
        | list[Any]
        | None,
) -> int:

    return count_observed_metrics(metrics)


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

    values = [
        value
        for value in values
        if value is not None
    ]

    if not values:
        return None

    return float(sum(values))


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

    values = [
        value
        for value in values
        if value is not None
    ]

    if not values:
        return None

    return float(sum(values))


def metric_summary(
    metric: dict[str, Any] | None,
) -> dict[str, Any]:

    if not isinstance(metric, dict):

        return {
            "status": "missing",
            "state": "missing",
            "queried": False,
            "query_succeeded": False,
            "has_data": False,
            "observed": False,
            "zero": False,
            "value": None,
            "average": None,
            "maximum": None,
            "minimum": None,
            "datapoints": 0,
            "statistic": None,
            "unit": None,
        }

    state = metric_status(metric)

    observed = metric_has_observed_data(
        metric
    )

    return {
        "status": state,
        "state": state,

        "queried":
            metric_was_queried(metric),

        "query_succeeded":
            metric_query_succeeded(metric),

        "has_data":
            observed,

        "observed":
            observed,

        "zero":
            metric_is_zero(metric),

        "value":
            metric.get("value")
            if observed
            else None,

        "average":
            metric.get("average")
            if observed
            else None,

        "maximum":
            metric.get("maximum")
            if observed
            else None,

        "minimum":
            metric.get("minimum")
            if observed
            else None,

        "statistic":
            metric.get("statistic"),

        "unit":
            metric.get("unit"),

        "datapoints":
            metric_datapoint_count(metric),

        "requested_period":
            metric.get("requested_period"),

        "effective_period":
            metric.get("effective_period"),

        "coverage_ratio":
            metric.get("coverage_ratio"),

        "coverage_percent":
            metric.get("coverage_percent"),

        "data_quality":
            metric.get("data_quality"),

        "metric_start":
            (
                metric.get("metric_start")
                or metric.get("start")
            ),

        "metric_end":
            (
                metric.get("metric_end")
                or metric.get("end")
            ),

        "error":
            metric.get("error"),
    }