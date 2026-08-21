"""
Reusable CloudWatch metric collector.

The analysis window (start/end) is controlled by the caller.
The CloudWatch metric period is a separate concern.

Examples:

    1 month selected by user:
        start = 2026-07-01
        end   = 2026-08-01

    3 months selected by user:
        start = 2026-05-01
        end   = 2026-08-01

The collector does NOT assume a fixed reporting window.

CloudWatch period rules:
    - data newer than 15 days: period >= 60 seconds
    - data older than 15 days: period >= 300 seconds
    - data older than 63 days: period >= 3600 seconds

Long windows are split into multiple requests rather than
automatically reducing the requested resolution.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


class CloudWatchMetricCollector:
    """
    Collect CloudWatch metrics for an arbitrary analysis window.

    Important distinction:

        analysis_start / analysis_end
            = what the user wants to analyze

        requested_period
            = resolution requested by the caller

        effective_period
            = resolution actually used after applying
              CloudWatch's retention/granularity rules
    """

    SUPPORTED_STATISTICS = {
        "Average",
        "Sum",
        "Minimum",
        "Maximum",
        "SampleCount",
    }

    STATISTIC_ALIASES = {
        "avg": "Average",
        "average": "Average",
        "sum": "Sum",
        "min": "Minimum",
        "minimum": "Minimum",
        "max": "Maximum",
        "maximum": "Maximum",
        "samplecount": "SampleCount",
        "sample_count": "SampleCount",
        "sample-count": "SampleCount",
    }

    # CloudWatch GetMetricStatistics supports at most
    # 1,440 datapoints per request.
    MAX_DATAPOINTS_PER_REQUEST = 1440

    # CloudWatch retention/granularity boundaries.
    FIFTEEN_DAYS = timedelta(days=15)
    SIXTY_THREE_DAYS = timedelta(days=63)

    MINUTE = 60
    FIVE_MINUTES = 300
    HOUR = 3600

    COMPLETE_THRESHOLD = 0.95
    GOOD_THRESHOLD = 0.80
    PARTIAL_THRESHOLD = 0.50

    def __init__(self, cloudwatch):
        self.cloudwatch = cloudwatch

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(
        self,
        namespace: str,
        dimensions: List[Dict[str, str]],
        metric_specs: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
        requested_period: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Collect metrics for the exact requested analysis window.

        Parameters
        ----------
        namespace:
            CloudWatch namespace.

        dimensions:
            CloudWatch metric dimensions.

        metric_specs:
            Metric definitions.

        start:
            User-selected analysis start.

        end:
            User-selected analysis end.

        requested_period:
            Desired CloudWatch resolution in seconds.

            None:
                Automatically select a valid period based on
                the selected analysis window.

            Example:
                60    = 1 minute
                300   = 5 minutes
                3600  = 1 hour

        Returns
        -------
        List[Dict[str, Any]]
            Normalized metric results.
        """

        start = self._normalize_datetime(start)
        end = self._normalize_datetime(end)

        if start >= end:
            raise ValueError(
                "end must be later than start"
            )

        normalized_requested_period = (
            self._normalize_requested_period(
                requested_period
            )
        )

        effective_period = (
            self._calculate_effective_period(
                start=start,
                requested_period=(
                    normalized_requested_period
                ),
            )
        )

        period_adjusted = (
            effective_period
            != normalized_requested_period
        )

        expected_datapoints = (
            self._expected_datapoints(
                start=start,
                end=end,
                period=effective_period,
            )
        )

        results: List[Dict[str, Any]] = []

        for metric_spec in metric_specs or []:

            if not isinstance(metric_spec, dict):
                raise ValueError(
                    "Every CloudWatch metric specification "
                    "must be a mapping"
                )

            metric_name = str(
                metric_spec.get("name", "")
            ).strip()

            if not metric_name:
                raise ValueError(
                    "CloudWatch metric name cannot be empty"
                )

            raw_statistic = metric_spec.get(
                "statistic",
                "Average",
            )

            statistic = self.normalize_statistic(
                raw_statistic
            )

            configured_unit = metric_spec.get(
                "unit"
            )

            # Some AWS metrics should be queried without
            # specifying Unit.
            omit_unit = bool(
                metric_spec.get(
                    "omit_unit",
                    False,
                )
            )

            unit = (
                None
                if omit_unit
                else configured_unit
            )

            metric_key = (
                metric_spec.get("key")
                or metric_name
            )

            response = self._get_datapoints(
                namespace=namespace,
                metric_name=metric_name,
                dimensions=dimensions,
                start=start,
                end=end,
                period=effective_period,
                statistic=statistic,
                unit=unit,
            )

            common = {
                "metric_key": metric_key,
                "metric_name": metric_name,
                "namespace": namespace,

                "statistic": statistic,
                "requested_statistic": raw_statistic,

                "requested_unit": configured_unit,
                "unit": unit,
                "unit_parameter_sent": (
                    unit is not None
                ),

                "dimensions": dimensions,

                # Exact user-selected analysis window.
                "analysis_start": self._isoformat(start),
                "analysis_end": self._isoformat(end),

                # Metric collection window.
                "metric_start": self._isoformat(start),
                "metric_end": self._isoformat(end),

                # Backward-compatible fields.
                "start": self._isoformat(start),
                "end": self._isoformat(end),

                # Period information.
                "requested_period": (
                    normalized_requested_period
                ),
                "effective_period": effective_period,
                "period": effective_period,
                "period_adjusted": period_adjusted,

                "expected_datapoints": (
                    expected_datapoints
                ),

                "request_count": response.get(
                    "request_count",
                    0,
                ),
            }

            if response["status"] == "error":
                results.append(
                    {
                        **common,
                        "status": "error",
                        "available": False,
                        "has_data": False,
                        "samples": 0,
                        "datapoints": 0,
                        "value": None,
                        "total": None,
                        "average": None,
                        "maximum": None,
                        "minimum": None,
                        "coverage_ratio": 0.0,
                        "coverage_percent": 0.0,
                        "complete": False,
                        "data_quality": "error",
                        "error": response.get("error"),
                        "raw_datapoints": [],
                    }
                )

                continue

            results.append(
                self._build_result(
                    common=common,
                    datapoints=response.get(
                        "datapoints",
                        [],
                    ),
                    statistic=statistic,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Batched collection
    # ------------------------------------------------------------------

    # CloudWatch GetMetricData accepts at most 500 MetricDataQueries
    # per request.
    MAX_QUERIES_PER_BATCH = 500

    def collect_batch(
        self,
        requests: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
        requested_period: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Batched equivalent of collect() covering many (resource,
        metric) pairs via GetMetricData (up to 500 MetricDataQueries
        per call) instead of one GetMetricStatistics call per metric
        per resource.

        Parameters
        ----------
        requests:
            List of
                {
                    "resource_key": str,
                    "namespace": str,
                    "dimensions": List[Dict[str, str]],
                    "metric_specs": List[Dict[str, Any]],
                }
            one entry per resource needing collection in this batch.

        start, end, requested_period:
            Same meaning as collect() -- shared across the whole
            batch (a batch is one scan's analysis window).

        Returns
        -------
        Dict[str, List[Dict[str, Any]]]
            resource_key -> list of normalized metric results, same
            per-metric shape collect() returns for one resource.

        Note: when a metric_spec omits its Unit (omit_unit=True),
        collect() would report whatever unit CloudWatch's
        GetMetricStatistics chose natively per datapoint;
        GetMetricData does not surface that, so raw_datapoints[].unit
        is None for omitted-unit metrics here instead. Every other
        field (value, has_data, status, coverage, etc.) is
        unaffected -- CloudWatch always returns the exact requested
        unit's values when Unit IS specified, which is the common
        case.
        """

        start = self._normalize_datetime(start)
        end = self._normalize_datetime(end)

        if start >= end:
            raise ValueError(
                "end must be later than start"
            )

        normalized_requested_period = (
            self._normalize_requested_period(
                requested_period
            )
        )

        effective_period = (
            self._calculate_effective_period(
                start=start,
                requested_period=(
                    normalized_requested_period
                ),
            )
        )

        period_adjusted = (
            effective_period
            != normalized_requested_period
        )

        expected_datapoints = (
            self._expected_datapoints(
                start=start,
                end=end,
                period=effective_period,
            )
        )

        queries: List[Dict[str, Any]] = []
        query_meta: Dict[str, Dict[str, Any]] = {}
        results_by_resource: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        counter = 0

        for request in requests or []:

            resource_key = request.get(
                "resource_key"
            )

            namespace = request.get(
                "namespace"
            )

            dimensions = (
                request.get("dimensions")
                or []
            )

            metric_specs = (
                request.get("metric_specs")
                or []
            )

            results_by_resource.setdefault(
                resource_key,
                [],
            )

            for metric_spec in metric_specs:

                if not isinstance(
                    metric_spec,
                    dict,
                ):
                    raise ValueError(
                        "Every CloudWatch metric specification "
                        "must be a mapping"
                    )

                metric_name = str(
                    metric_spec.get(
                        "name",
                        "",
                    )
                ).strip()

                if not metric_name:
                    raise ValueError(
                        "CloudWatch metric name cannot be empty"
                    )

                raw_statistic = (
                    metric_spec.get(
                        "statistic",
                        "Average",
                    )
                )

                statistic = (
                    self.normalize_statistic(
                        raw_statistic
                    )
                )

                configured_unit = (
                    metric_spec.get("unit")
                )

                omit_unit = bool(
                    metric_spec.get(
                        "omit_unit",
                        False,
                    )
                )

                unit = (
                    None
                    if omit_unit
                    else configured_unit
                )

                metric_key = (
                    metric_spec.get("key")
                    or metric_name
                )

                query_id = f"q{counter}"
                counter += 1

                metric_stat: Dict[
                    str,
                    Any,
                ] = {
                    "Metric": {
                        "Namespace": namespace,
                        "MetricName": metric_name,
                        "Dimensions": dimensions,
                    },
                    "Period": effective_period,
                    "Stat": statistic,
                }

                if unit is not None:
                    metric_stat["Unit"] = unit

                queries.append(
                    {
                        "Id": query_id,
                        "MetricStat": metric_stat,
                        "ReturnData": True,
                    }
                )

                query_meta[query_id] = {
                    "resource_key": resource_key,
                    "namespace": namespace,
                    "dimensions": dimensions,
                    "metric_key": metric_key,
                    "metric_name": metric_name,
                    "statistic": statistic,
                    "raw_statistic": raw_statistic,
                    "configured_unit": configured_unit,
                    "unit": unit,
                }

        if not queries:
            return results_by_resource

        raw_by_id: Dict[str, Dict[str, Any]] = {}
        request_count = 0
        fetch_error: Optional[str] = None

        try:

            for chunk_start in range(
                0,
                len(queries),
                self.MAX_QUERIES_PER_BATCH,
            ):

                chunk = queries[
                    chunk_start:
                    chunk_start
                    + self.MAX_QUERIES_PER_BATCH
                ]

                next_token: Optional[str] = None

                while True:

                    kwargs: Dict[str, Any] = {
                        "MetricDataQueries": chunk,
                        "StartTime": start,
                        "EndTime": end,
                        "ScanBy": "TimestampAscending",
                    }

                    if next_token:
                        kwargs["NextToken"] = next_token

                    response = (
                        self.cloudwatch
                        .get_metric_data(
                            **kwargs
                        )
                    )

                    request_count += 1

                    for result in response.get(
                        "MetricDataResults",
                        [],
                    ):

                        result_id = result.get(
                            "Id"
                        )

                        if not result_id:
                            continue

                        entry = raw_by_id.setdefault(
                            result_id,
                            {
                                "Timestamps": [],
                                "Values": [],
                            },
                        )

                        entry["Timestamps"].extend(
                            result.get(
                                "Timestamps",
                                [],
                            )
                        )

                        entry["Values"].extend(
                            result.get(
                                "Values",
                                [],
                            )
                        )

                    next_token = response.get(
                        "NextToken"
                    )

                    if not next_token:
                        break

        except Exception as exc:
            fetch_error = str(exc)

        for query_id, meta in query_meta.items():

            common = {
                "metric_key": meta["metric_key"],
                "metric_name": meta["metric_name"],
                "namespace": meta["namespace"],

                "statistic": meta["statistic"],
                "requested_statistic": (
                    meta["raw_statistic"]
                ),

                "requested_unit": (
                    meta["configured_unit"]
                ),
                "unit": meta["unit"],
                "unit_parameter_sent": (
                    meta["unit"] is not None
                ),

                "dimensions": meta["dimensions"],

                "analysis_start": self._isoformat(start),
                "analysis_end": self._isoformat(end),

                "metric_start": self._isoformat(start),
                "metric_end": self._isoformat(end),

                "start": self._isoformat(start),
                "end": self._isoformat(end),

                "requested_period": (
                    normalized_requested_period
                ),
                "effective_period": effective_period,
                "period": effective_period,
                "period_adjusted": period_adjusted,

                "expected_datapoints": (
                    expected_datapoints
                ),

                # Total GetMetricData calls for the whole batch
                # (this metric's individual share isn't meaningful
                # once requests are batched together).
                "request_count": request_count,
            }

            if fetch_error is not None:

                results_by_resource[
                    meta["resource_key"]
                ].append(
                    {
                        **common,
                        "status": "error",
                        "available": False,
                        "has_data": False,
                        "samples": 0,
                        "datapoints": 0,
                        "value": None,
                        "total": None,
                        "average": None,
                        "maximum": None,
                        "minimum": None,
                        "coverage_ratio": 0.0,
                        "coverage_percent": 0.0,
                        "complete": False,
                        "data_quality": "error",
                        "error": fetch_error,
                        "raw_datapoints": [],
                    }
                )

                continue

            raw = raw_by_id.get(
                query_id,
                {
                    "Timestamps": [],
                    "Values": [],
                },
            )

            datapoints: List[
                Dict[str, Any]
            ] = []

            for timestamp, value in zip(
                raw["Timestamps"],
                raw["Values"],
            ):

                normalized_ts = (
                    self._normalize_datetime(
                        timestamp
                    )
                )

                if not (
                    start
                    <= normalized_ts
                    < end
                ):
                    continue

                datapoints.append(
                    {
                        "Timestamp": normalized_ts,
                        meta["statistic"]: value,
                        "Unit": meta["unit"],
                    }
                )

            datapoints = (
                self._deduplicate_datapoints(
                    datapoints
                )
            )

            results_by_resource[
                meta["resource_key"]
            ].append(
                self._build_result(
                    common=common,
                    datapoints=datapoints,
                    statistic=meta["statistic"],
                )
            )

        return results_by_resource

    # ------------------------------------------------------------------
    # Statistic handling
    # ------------------------------------------------------------------

    @classmethod
    def normalize_statistic(
        cls,
        statistic: Any,
    ) -> str:
        if statistic is None:
            return "Average"

        value = str(statistic).strip()

        if not value:
            return "Average"

        if value in cls.SUPPORTED_STATISTICS:
            return value

        canonical = cls.STATISTIC_ALIASES.get(
            value.lower()
        )

        if canonical:
            return canonical

        raise ValueError(
            "Unsupported CloudWatch statistic: "
            f"{statistic}"
        )

    # ------------------------------------------------------------------
    # Period handling
    # ------------------------------------------------------------------

    @classmethod
    def _normalize_requested_period(
        cls,
        period: Optional[int],
    ) -> int:
        """
        Normalize the caller's requested period.

        None means automatic period selection.

        The default automatic resolution is 1 hour rather
        than 1 minute because the collector is intended for
        cost-optimization analysis rather than high-frequency
        operational monitoring.
        """

        if period is None:
            return cls.HOUR

        try:
            period = int(period)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "requested_period must be an integer"
            ) from exc

        if period <= 0:
            raise ValueError(
                "requested_period must be greater than zero"
            )

        if period < cls.MINUTE:
            return cls.MINUTE

        if period % cls.MINUTE == 0:
            return period

        return cls._round_up_to_minute(period)

    @classmethod
    def _calculate_effective_period(
        cls,
        start: datetime,
        requested_period: int,
    ) -> int:
        """
        Calculate the minimum CloudWatch-compatible period
        for the selected analysis window.

        The oldest timestamp controls the minimum resolution
        because the requested window may contain historical data.

        Examples:

            last 7 days:
                minimum = 60 seconds

            1 month:
                minimum = 300 seconds

            3 months:
                minimum = 3600 seconds

        The caller's requested period is never made smaller.
        """

        start = cls._normalize_datetime(start)

        now = datetime.now(timezone.utc)

        age = now - start

        if age >= cls.SIXTY_THREE_DAYS:
            minimum_period = cls.HOUR

        elif age >= cls.FIFTEEN_DAYS:
            minimum_period = cls.FIVE_MINUTES

        else:
            minimum_period = cls.MINUTE

        return max(
            requested_period,
            minimum_period,
        )

    @classmethod
    def _round_up_to_minute(
        cls,
        seconds: int,
    ) -> int:
        return (
            (
                seconds
                + cls.MINUTE
                - 1
            )
            // cls.MINUTE
        ) * cls.MINUTE

    # ------------------------------------------------------------------
    # Expected datapoints
    # ------------------------------------------------------------------

    @classmethod
    def _expected_datapoints(
        cls,
        start: datetime,
        end: datetime,
        period: int,
    ) -> int:
        duration_seconds = (
            end - start
        ).total_seconds()

        return max(
            1,
            int(
                (
                    duration_seconds
                    + period
                    - 1
                )
                // period
            ),
        )

    # ------------------------------------------------------------------
    # Request chunking
    # ------------------------------------------------------------------

    @classmethod
    def _calculate_chunk_duration(
        cls,
        period: int,
    ) -> timedelta:
        """
        Keep every CloudWatch request within the
        1,440-datapoint limit.

        Example:

            period = 60 seconds
            chunk = 24 hours

            period = 300 seconds
            chunk = 5 days

            period = 3600 seconds
            chunk = 60 days
        """

        return timedelta(
            seconds=(
                period
                * cls.MAX_DATAPOINTS_PER_REQUEST
            )
        )

    def _get_datapoints(
        self,
        namespace: str,
        metric_name: str,
        dimensions: List[Dict[str, str]],
        start: datetime,
        end: datetime,
        period: int,
        statistic: str,
        unit: Optional[str],
    ) -> Dict[str, Any]:

        chunk_duration = (
            self._calculate_chunk_duration(
                period
            )
        )

        all_datapoints: List[
            Dict[str, Any]
        ] = []

        request_count = 0

        current_start = start

        try:
            while current_start < end:

                current_end = min(
                    current_start + chunk_duration,
                    end,
                )

                kwargs: Dict[str, Any] = {
                    "Namespace": namespace,
                    "MetricName": metric_name,
                    "Dimensions": dimensions,
                    "StartTime": current_start,
                    "EndTime": current_end,
                    "Period": period,
                    "Statistics": [statistic],
                }

                # Do not send Unit when it is intentionally omitted.
                if unit is not None:
                    kwargs["Unit"] = unit

                response = (
                    self.cloudwatch
                    .get_metric_statistics(
                        **kwargs
                    )
                )

                request_count += 1

                points = response.get(
                    "Datapoints",
                    [],
                )

                if isinstance(points, list):
                    all_datapoints.extend(points)

                if current_end <= current_start:
                    break

                current_start = current_end

            filtered: List[
                Dict[str, Any]
            ] = []

            for point in all_datapoints:

                if not isinstance(point, dict):
                    continue

                timestamp = point.get(
                    "Timestamp"
                )

                if timestamp is None:
                    continue

                timestamp = (
                    self._normalize_datetime(
                        timestamp
                    )
                )

                # Exact analysis window.
                if (
                    start
                    <= timestamp
                    < end
                ):
                    filtered.append(point)

            filtered = (
                self._deduplicate_datapoints(
                    filtered
                )
            )

            return {
                "status": "ok",
                "datapoints": filtered,
                "error": None,
                "request_count": request_count,
            }

        except Exception as exc:
            return {
                "status": "error",
                "datapoints": [],
                "error": str(exc),
                "request_count": request_count,
            }

    # ------------------------------------------------------------------
    # Result building
    # ------------------------------------------------------------------

    def _build_result(
        self,
        common: Dict[str, Any],
        datapoints: List[Dict[str, Any]],
        statistic: str,
    ) -> Dict[str, Any]:

        result = {
            **common,

            "status": "no_data",
            "available": False,
            "has_data": False,

            "samples": 0,
            "datapoints": 0,

            "value": None,
            "total": None,
            "average": None,
            "maximum": None,
            "minimum": None,

            "coverage_ratio": 0.0,
            "coverage_percent": 0.0,

            "complete": False,
            "data_quality": "no_data",

            "error": None,
            "raw_datapoints": [],
        }

        if not datapoints:
            return result

        values: List[float] = []

        weighted_sum = 0.0
        weighted_count = 0.0

        raw_datapoints: List[
            Dict[str, Any]
        ] = []

        for point in datapoints:

            if not isinstance(point, dict):
                continue

            if statistic not in point:
                continue

            raw_value = point.get(
                statistic
            )

            if raw_value is None:
                continue

            try:
                value = float(raw_value)
            except (
                TypeError,
                ValueError,
            ):
                continue

            timestamp = point.get(
                "Timestamp"
            )

            if timestamp is None:
                continue

            timestamp = (
                self._normalize_datetime(
                    timestamp
                )
            )

            values.append(value)

            sample_count = point.get(
                "SampleCount"
            )

            try:
                sample_count = (
                    float(sample_count)
                    if sample_count is not None
                    else None
                )
            except (
                TypeError,
                ValueError,
            ):
                sample_count = None

            if (
                statistic == "Average"
                and sample_count is not None
                and sample_count > 0
            ):
                weighted_sum += (
                    value
                    * sample_count
                )

                weighted_count += (
                    sample_count
                )

            raw_datapoints.append(
                {
                    "timestamp":
                        self._isoformat(
                            timestamp
                        ),

                    "value":
                        value,

                    "statistic":
                        statistic,

                    "unit":
                        point.get("Unit"),

                    "sample_count":
                        sample_count,
                }
            )

        if not values:

            result.update(
                {
                    "status": "invalid_data",
                    "available": True,
                    "has_data": False,
                    "data_quality": "invalid",
                    "raw_datapoints":
                        raw_datapoints,
                }
            )

            return result

        datapoint_count = len(values)

        expected_datapoints = max(
            int(
                common.get(
                    "expected_datapoints",
                    datapoint_count,
                )
                or datapoint_count
            ),
            1,
        )

        coverage_ratio = min(
            datapoint_count
            / expected_datapoints,
            1.0,
        )

        coverage_percent = (
            coverage_ratio
            * 100.0
        )

        complete = (
            coverage_ratio
            >= self.COMPLETE_THRESHOLD
        )

        data_quality = (
            self._determine_data_quality(
                coverage_ratio
            )
        )

        total = sum(values)

        if (
            statistic == "Average"
            and weighted_count > 0
        ):
            average = (
                weighted_sum
                / weighted_count
            )
        else:
            average = (
                total
                / datapoint_count
            )

        maximum = max(values)
        minimum = min(values)

        selected_value = (
            self._select_metric_value(
                statistic=statistic,
                values=values,
                weighted_average=average,
            )
        )

        result.update(
            {
                "status": "ok",
                "available": True,
                "has_data": True,

                "samples":
                    datapoint_count,

                "datapoints":
                    datapoint_count,

                "value":
                    self._round(
                        selected_value
                    ),

                "total":
                    self._round(
                        total
                    ),

                "average":
                    self._round(
                        average
                    ),

                "maximum":
                    self._round(
                        maximum
                    ),

                "minimum":
                    self._round(
                        minimum
                    ),

                "coverage_ratio":
                    round(
                        coverage_ratio,
                        4,
                    ),

                "coverage_percent":
                    round(
                        coverage_percent,
                        2,
                    ),

                "complete":
                    complete,

                "data_quality":
                    data_quality,

                "raw_datapoints":
                    raw_datapoints,
            }
        )

        return result

    # ------------------------------------------------------------------
    # Value selection
    # ------------------------------------------------------------------

    @classmethod
    def _select_metric_value(
        cls,
        statistic: str,
        values: List[float],
        weighted_average: Optional[float] = None,
    ) -> float:

        if not values:
            return 0.0

        if statistic == "Sum":
            return sum(values)

        if statistic == "Average":

            if weighted_average is not None:
                return weighted_average

            return (
                sum(values)
                / len(values)
            )

        if statistic == "Maximum":
            return max(values)

        if statistic == "Minimum":
            return min(values)

        if statistic == "SampleCount":
            return sum(values)

        return (
            sum(values)
            / len(values)
        )

    # ------------------------------------------------------------------
    # Data quality
    # ------------------------------------------------------------------

    @classmethod
    def _determine_data_quality(
        cls,
        coverage_ratio: float,
    ) -> str:

        if (
            coverage_ratio
            >= cls.COMPLETE_THRESHOLD
        ):
            return "complete"

        if (
            coverage_ratio
            >= cls.GOOD_THRESHOLD
        ):
            return "good"

        if (
            coverage_ratio
            >= cls.PARTIAL_THRESHOLD
        ):
            return "partial"

        return "poor"

    # ------------------------------------------------------------------
    # Datapoint deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_datapoints(
        datapoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        seen: Dict[
            datetime,
            Dict[str, Any],
        ] = {}

        for point in datapoints:

            if not isinstance(point, dict):
                continue

            timestamp = point.get(
                "Timestamp"
            )

            if timestamp is None:
                continue

            timestamp = (
                CloudWatchMetricCollector
                ._normalize_datetime(
                    timestamp
                )
            )

            seen[timestamp] = point

        return sorted(
            seen.values(),
            key=lambda point:
                CloudWatchMetricCollector
                ._normalize_datetime(
                    point["Timestamp"]
                ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _round(
        value: Optional[float],
    ) -> Optional[float]:

        if value is None:
            return None

        return round(
            float(value),
            6,
        )

    @staticmethod
    def _normalize_datetime(
        value: datetime,
    ) -> datetime:

        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(
            timezone.utc
        )

    @classmethod
    def _isoformat(
        cls,
        value: datetime,
    ) -> str:

        return cls._normalize_datetime(
            value
        ).isoformat()