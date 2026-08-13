"""
Reusable CloudWatch metric collector.

Responsibilities:
- Preserve the exact analysis window.
- Select a CloudWatch-compatible effective period.
- Split large requests into safe chunks.
- Handle CloudWatch period/retention rules.
- Filter returned datapoints to the requested window.
- Preserve raw datapoints.
- Calculate data coverage and quality.
- Correctly aggregate supported CloudWatch statistics.
- Avoid treating missing datapoints as zero.
- Make requested/effective periods and query boundaries explicit.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


class CloudWatchMetricCollector:

    SUPPORTED_STATISTICS = {
        "Average",
        "Sum",
        "Minimum",
        "Maximum",
        "SampleCount",
    }

    # CloudWatch GetMetricStatistics limit.
    MAX_DATAPOINTS_PER_REQUEST = 1440

    # CloudWatch standard-resolution retention rules.
    FIFTEEN_DAYS = timedelta(days=15)
    SIXTY_THREE_DAYS = timedelta(days=63)

    MINUTE = 60
    FIVE_MINUTES = 300
    HOUR = 3600

    # Data quality thresholds.
    COMPLETE_THRESHOLD = 0.95
    GOOD_THRESHOLD = 0.80
    PARTIAL_THRESHOLD = 0.50

    def __init__(self, cloudwatch):
        self.cloudwatch = cloudwatch

       # PUBLIC API
   
    def collect(
        self,
        namespace: str,
        dimensions: List[Dict[str, str]],
        metric_specs: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
        requested_period: int = 3600,
    ) -> List[Dict[str, Any]]:
        """
        Collect metrics for the exact requested analysis window.

        The caller's window is never silently changed.

        Example:

            start = 2026-03-01 00:00 UTC
            end   = 2026-07-01 00:00 UTC

        The result explicitly contains:

            analysis_start
            analysis_end
            query_start
            query_end
            requested_period
            effective_period
            period_adjusted
            coverage
            data_quality
        """

        start = self._normalize_datetime(start)
        end = self._normalize_datetime(end)

        if start >= end:
            raise ValueError(
                "end must be later than start"
            )

        if requested_period <= 0:
            raise ValueError(
                "requested_period must be greater than zero"
            )

        requested_period = self._normalize_requested_period(
            requested_period
        )

        effective_period = self._calculate_effective_period(
            start=start,
            requested_period=requested_period,
        )

        period_adjusted = (
            effective_period != requested_period
        )

        expected_datapoints = self._expected_datapoints(
            start=start,
            end=end,
            period=effective_period,
        )

        results: List[Dict[str, Any]] = []

        for metric_spec in metric_specs:

            if "name" not in metric_spec:
                raise ValueError(
                    "Every CloudWatch metric specification "
                    "must contain 'name'"
                )

            metric_name = metric_spec["name"]

            statistic = metric_spec.get(
                "statistic",
                "Average",
            )

            unit = metric_spec.get("unit")

            metric_key = metric_spec.get(
                "key",
                metric_name,
            )

            if statistic not in self.SUPPORTED_STATISTICS:
                raise ValueError(
                    f"Unsupported CloudWatch statistic: "
                    f"{statistic}"
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
                "unit": unit,

                "dimensions": dimensions,

                # Exact requested analysis window.
                "analysis_start": self._isoformat(start),
                "analysis_end": self._isoformat(end),

                # Backwards-compatible aliases.
                "metric_start": self._isoformat(start),
                "metric_end": self._isoformat(end),

                "start": self._isoformat(start),
                "end": self._isoformat(end),

                # Period requested by caller.
                "requested_period": requested_period,

                # Period actually sent to CloudWatch.
                "effective_period": effective_period,

                "period": effective_period,

                "period_adjusted": period_adjusted,

                "expected_datapoints": expected_datapoints,

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

                        "error": response["error"],

                        "raw_datapoints": [],
                    }
                )

                continue

            results.append(
                self._build_result(
                    common=common,
                    datapoints=response["datapoints"],
                    statistic=statistic,
                )
            )

        return results

       # PERIOD HANDLING
   
    @classmethod
    def _normalize_requested_period(
        cls,
        period: int,
    ) -> int:
    

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
      
        now = datetime.now(timezone.utc)

        age = now - start

        if age > cls.SIXTY_THREE_DAYS:
            minimum_period = cls.HOUR

        elif age > cls.FIFTEEN_DAYS:
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
            (seconds + cls.MINUTE - 1)
            // cls.MINUTE
        ) * cls.MINUTE

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
                (duration_seconds + period - 1)
                // period
            ),
        )

    @classmethod
    def _calculate_chunk_duration(
        cls,
        period: int,
    ) -> timedelta:

        return timedelta(
            seconds=(
                period
                * cls.MAX_DATAPOINTS_PER_REQUEST
            )
        )

       # CLOUDWATCH REQUEST
   
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
            self._calculate_chunk_duration(period)
        )

        all_datapoints: List[Dict[str, Any]] = []

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

                if unit:
                    kwargs["Unit"] = unit

                response = (
                    self.cloudwatch
                    .get_metric_statistics(**kwargs)
                )

                request_count += 1

                all_datapoints.extend(
                    response.get(
                        "Datapoints",
                        [],
                    )
                )

                current_start = current_end

             # Filter to the EXACT requested analysis window.
 
            filtered = []

            for point in all_datapoints:

                timestamp = point.get(
                    "Timestamp"
                )

                if timestamp is None:
                    continue

                timestamp = self._normalize_datetime(
                    timestamp
                )

                if start <= timestamp < end:
                    filtered.append(point)

             # Sort.
 
            filtered = self._sort_datapoints(
                filtered
            )

             # Deduplicate.
 
            filtered = self._deduplicate_datapoints(
                filtered
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
                "datapoints": all_datapoints,
                "error": str(exc),
                "request_count": request_count,
            }

       # DATAPOINT PROCESSING
   
    @classmethod
    def _sort_datapoints(
        cls,
        datapoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        return sorted(
            datapoints,
            key=lambda point: (
                cls._normalize_datetime(
                    point["Timestamp"]
                )
                if point.get("Timestamp")
                else datetime.min.replace(
                    tzinfo=timezone.utc
                )
            ),
        )

    @classmethod
    def _deduplicate_datapoints(
        cls,
        datapoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        deduplicated: Dict[
            datetime,
            Dict[str, Any],
        ] = {}

        for point in datapoints:

            timestamp = point.get(
                "Timestamp"
            )

            if timestamp is None:
                continue

            timestamp = cls._normalize_datetime(
                timestamp
            )

            deduplicated[timestamp] = point

        return cls._sort_datapoints(
            list(
                deduplicated.values()
            )
        )
    def _build_result(
        self,
        common: Dict[str, Any],
        datapoints: List[Dict[str, Any]],
        statistic: str,
    ) -> Dict[str, Any]:

        result = {
            **common,

            "samples": 0,
            "datapoints": 0,

            "available": False,
            "has_data": False,

            "value": None,
            "total": None,
            "average": None,
            "maximum": None,
            "minimum": None,

            "coverage_ratio": 0.0,
            "coverage_percent": 0.0,

            "complete": False,

            "data_quality": "no_data",

            "status": "no_data",

            "error": None,

            "raw_datapoints": [],
        }

        values: List[float] = []

        weighted_sum = 0.0
        weighted_count = 0.0

        raw_datapoints: List[Dict[str, Any]] = []

        for point in datapoints:

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

            timestamp = self._normalize_datetime(
                timestamp
            )

            values.append(value)

            # CloudWatch may provide SampleCount.
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
                    value * sample_count
                )

                weighted_count += sample_count

            raw_datapoints.append(
                {
                    "timestamp": self._isoformat(
                        timestamp
                    ),

                    "value": value,

                    "unit": point.get(
                        "Unit",
                        common.get("unit"),
                    ),

                    "sample_count": (
                        sample_count
                    ),
                }
            )

        if not values:
            return result

        datapoint_count = len(values)

        expected_datapoints = max(
            common.get(
                "expected_datapoints",
                datapoint_count,
            ),
            1,
        )

        coverage_ratio = min(
            datapoint_count
            / expected_datapoints,
            1.0,
        )

        coverage_percent = (
            coverage_ratio * 100
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
                "samples": datapoint_count,
                "datapoints": datapoint_count,

                "available": True,
                "has_data": True,

                "value": self._round(
                    selected_value
                ),

                "total": self._round(
                    total
                ),

                "average": self._round(
                    average
                ),

                "maximum": self._round(
                    maximum
                ),

                "minimum": self._round(
                    minimum
                ),

                "coverage_ratio": round(
                    coverage_ratio,
                    4,
                ),

                "coverage_percent": round(
                    coverage_percent,
                    2,
                ),

                "complete": complete,

                "data_quality": data_quality,

                "status": "ok",

                "raw_datapoints":
                    raw_datapoints,
            }
        )

        return result

       # AGGREGATION
   
    @classmethod
    def _select_metric_value(
        cls,
        statistic: str,
        values: List[float],
        weighted_average: Optional[float] = None,
    ) -> float:
        """
        Aggregate datapoints according to their CloudWatch statistic.

        Important:

        Sum
            Sum of period sums.

        Average
            Weighted average when SampleCount is available.

        Maximum
            Maximum observed period value.

        Minimum
            Minimum observed period value.

        SampleCount
            Sum of sample counts.

        This does not attempt to manufacture values for
        missing datapoints.
        """

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

       # DATA QUALITY
   
    @classmethod
    def _determine_data_quality(
        cls,
        coverage_ratio: float,
    ) -> str:

        if coverage_ratio >= cls.COMPLETE_THRESHOLD:
            return "complete"

        if coverage_ratio >= cls.GOOD_THRESHOLD:
            return "good"

        if coverage_ratio >= cls.PARTIAL_THRESHOLD:
            return "partial"

        return "poor"

       # ROUNDING
   
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