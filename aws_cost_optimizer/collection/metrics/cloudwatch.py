"""
Reusable CloudWatch metric collector.

Responsibilities
----------------
- Retrieve CloudWatch metrics for an exact caller-selected analysis window.
- Respect CloudWatch retention/granularity rules.
- Split GetMetricStatistics requests when the 1,440 datapoint limit requires it.
- Batch GetMetricData requests up to the AWS 500-query limit.
- Preserve per-query CloudWatch retrieval status.
- Never confuse:
      no data
      partial data
      retrieval error
      invalid returned data
      valid zero-valued data
- Avoid interpreting sparse metrics as incomplete merely because
  CloudWatch did not publish a datapoint for every theoretical period.

"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

DEFAULT_CLOUDWATCH_PERIOD = 3600


class CloudWatchMetricCollector:
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
    MAX_DATAPOINTS_PER_REQUEST = 1440
    # AWS CloudWatch retention / minimum period boundaries.
    FIFTEEN_DAYS = timedelta(days=15)
    SIXTY_THREE_DAYS = timedelta(days=63)
    MINUTE = 60
    FIVE_MINUTES = 300
    HOUR = 3600
    MAX_QUERIES_PER_BATCH = 500

    def __init__(self, cloudwatch):
        self.cloudwatch = cloudwatch

    def collect(
        self,
        namespace: str,
        dimensions: List[Dict[str, str]],
        metric_specs: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
        requested_period: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        start = self._normalize_datetime(start)
        end = self._normalize_datetime(end)

        if start >= end:
            raise ValueError("end must be later than start")

        requested_period_normalized = self._normalize_requested_period(requested_period)

        effective_period = self._calculate_effective_period(
            start=start,
            requested_period=requested_period_normalized,
        )

        period_adjusted = effective_period != requested_period_normalized

        results: List[Dict[str, Any]] = []

        for metric_spec in metric_specs or []:
            if not isinstance(metric_spec, dict):
                raise ValueError(
                    "Every CloudWatch metric specification must be a mapping"
                )

            metric_name = str(metric_spec.get("name", "")).strip()

            if not metric_name:
                raise ValueError("CloudWatch metric name cannot be empty")

            raw_statistic = metric_spec.get("statistic", "Average")
            statistic = self.normalize_statistic(raw_statistic)

            configured_unit = metric_spec.get("unit")

            omit_unit = bool(metric_spec.get("omit_unit", False))
            unit = None if omit_unit else configured_unit

            metric_key = metric_spec.get("key") or metric_name

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

            common = self._build_common_metadata(
                metric_key=metric_key,
                metric_name=metric_name,
                namespace=namespace,
                statistic=statistic,
                requested_statistic=raw_statistic,
                requested_unit=configured_unit,
                unit=unit,
                dimensions=dimensions,
                start=start,
                end=end,
                requested_period=requested_period_normalized,
                effective_period=effective_period,
                period_adjusted=period_adjusted,
                request_count=response.get("request_count", 0),
            )

            if response.get("status") == "error":
                results.append(
                    self._build_error_result(
                        common=common,
                        error=response.get("error"),
                    )
                )
                continue

            result = self._build_result(
                common=common,
                datapoints=response.get("datapoints", []),
                statistic=statistic,
                retrieval_status=response.get("retrieval_status"),
                retrieval_messages=response.get("messages"),
            )

            results.append(result)

        return results

    def collect_batch(
        self,
        requests: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
        requested_period: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        start = self._normalize_datetime(start)
        end = self._normalize_datetime(end)

        if start >= end:
            raise ValueError("end must be later than start")

        requested_period_normalized = self._normalize_requested_period(requested_period)

        effective_period = self._calculate_effective_period(
            start=start,
            requested_period=requested_period_normalized,
        )

        period_adjusted = effective_period != requested_period_normalized

        results_by_resource: Dict[str, List[Dict[str, Any]]] = {}

        queries: List[Dict[str, Any]] = []
        query_meta: Dict[str, Dict[str, Any]] = {}

        query_counter = 0

        for request in requests or []:
            resource_key = request.get("resource_key")

            namespace = str(request.get("namespace") or "").strip()
            if not namespace:
                raise ValueError("CloudWatch namespace cannot be empty")

            dimensions = request.get("dimensions") or []
            metric_specs = request.get("metric_specs") or []

            results_by_resource.setdefault(resource_key, [])

            for metric_spec in metric_specs:
                if not isinstance(metric_spec, dict):
                    raise ValueError(
                        "Every CloudWatch metric specification must be a mapping"
                    )

                metric_name = str(metric_spec.get("name", "")).strip()

                if not metric_name:
                    raise ValueError("CloudWatch metric name cannot be empty")

                raw_statistic = metric_spec.get("statistic", "Average")
                statistic = self.normalize_statistic(raw_statistic)

                configured_unit = metric_spec.get("unit")

                omit_unit = bool(metric_spec.get("omit_unit", False))
                unit = None if omit_unit else configured_unit

                metric_key = metric_spec.get("key") or metric_name

                query_id = f"q{query_counter}"
                query_counter += 1

                metric_stat: Dict[str, Any] = {
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
        responses_by_query: Dict[str, Dict[str, Any]] = {}

        for chunk_start in range(
            0,
            len(queries),
            self.MAX_QUERIES_PER_BATCH,
        ):
            chunk = queries[chunk_start : chunk_start + self.MAX_QUERIES_PER_BATCH]

            chunk_query_ids = {query["Id"] for query in chunk}

            next_token: Optional[str] = None

            try:
                while True:
                    kwargs: Dict[str, Any] = {
                        "MetricDataQueries": chunk,
                        "StartTime": start,
                        "EndTime": end,
                        "ScanBy": "TimestampAscending",
                        # AWS caps GetMetricData at 100,800 datapoints
                        # per request.  Setting it explicitly makes the
                        # pagination behaviour deterministic instead of
                        # depending on the service default.
                        "MaxDatapoints": 100800,
                    }

                    if next_token:
                        kwargs["NextToken"] = next_token

                    response = self.cloudwatch.get_metric_data(**kwargs)

                    for result in response.get("MetricDataResults", []):
                        result_id = result.get("Id")

                        if not result_id:
                            continue

                        if result_id not in chunk_query_ids:
                            continue

                        existing = responses_by_query.get(
                            result_id,
                            {
                                "Timestamps": [],
                                "Values": [],
                                "StatusCode": None,
                                "Messages": [],
                            },
                        )

                        existing["Timestamps"].extend(
                            result.get("Timestamps", []) or []
                        )
                        existing["Values"].extend(result.get("Values", []) or [])

                        status_code = result.get("StatusCode")

                        # Preserve the strongest/most concerning status
                        # observed for this query.
                        if status_code:
                            existing["StatusCode"] = self._merge_status(
                                existing.get("StatusCode"),
                                status_code,
                            )

                        existing["Messages"].extend(result.get("Messages", []) or [])

                        responses_by_query[result_id] = existing

                    next_token = response.get("NextToken")
                    if not next_token:
                        break
            except Exception as exc:
                error_text = str(exc)

                for query in chunk:
                    query_id = query["Id"]

                    responses_by_query[query_id] = {
                        "Timestamps": [],
                        "Values": [],
                        "StatusCode": "InternalError",
                        "Messages": [
                            {
                                "Code": "REQUEST_ERROR",
                                "Value": error_text,
                            }
                        ],
                        "request_error": error_text,
                    }
        request_count = (
            len(queries) + self.MAX_QUERIES_PER_BATCH - 1
        ) // self.MAX_QUERIES_PER_BATCH

        for query_id, meta in query_meta.items():
            raw = responses_by_query.get(
                query_id,
                {
                    "Timestamps": [],
                    "Values": [],
                    "StatusCode": "InternalError",
                    "Messages": [
                        {
                            "Code": "MISSING_RESULT",
                            "Value": "CloudWatch returned no MetricDataResult for query",
                        }
                    ],
                },
            )

            common = self._build_common_metadata(
                metric_key=meta["metric_key"],
                metric_name=meta["metric_name"],
                namespace=meta["namespace"],
                statistic=meta["statistic"],
                requested_statistic=meta["raw_statistic"],
                requested_unit=meta["configured_unit"],
                unit=meta["unit"],
                dimensions=meta["dimensions"],
                start=start,
                end=end,
                requested_period=requested_period_normalized,
                effective_period=effective_period,
                period_adjusted=period_adjusted,
                request_count=request_count,
            )

            datapoints: List[Dict[str, Any]] = []

            timestamps = raw.get("Timestamps") or []
            values = raw.get("Values") or []

            for timestamp, value in zip(timestamps, values):
                normalized_ts = self._normalize_datetime(timestamp)
                if not (start <= normalized_ts < end):
                    continue

                datapoints.append(
                    {
                        "Timestamp": normalized_ts,
                        meta["statistic"]: value,
                        "Unit": meta["unit"],
                    }
                )

            datapoints = self._deduplicate_datapoints(datapoints)

            retrieval_status = raw.get("StatusCode")
            messages = raw.get("Messages") or []

            if raw.get("request_error"):
                result = self._build_error_result(
                    common=common,
                    error=raw["request_error"],
                    retrieval_status=retrieval_status,
                    retrieval_messages=messages,
                )
            else:
                result = self._build_result(
                    common=common,
                    datapoints=datapoints,
                    statistic=meta["statistic"],
                    retrieval_status=retrieval_status,
                    retrieval_messages=messages,
                )

            results_by_resource[meta["resource_key"]].append(result)

        return results_by_resource

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

        canonical = cls.STATISTIC_ALIASES.get(value.lower())

        if canonical:
            return canonical

        raise ValueError(f"Unsupported CloudWatch statistic: {statistic}")

    @classmethod
    def _normalize_requested_period(
        cls,
        period: Optional[int],
    ) -> int:
        if period is None:
            return cls.HOUR

        try:
            period = int(period)
        except (TypeError, ValueError) as exc:
            raise ValueError("requested_period must be an integer") from exc

        if period <= 0:
            raise ValueError("requested_period must be greater than zero")

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
        return ((seconds + cls.MINUTE - 1) // cls.MINUTE) * cls.MINUTE

    @classmethod
    def _build_common_metadata(
        cls,
        *,
        metric_key: str,
        metric_name: str,
        namespace: str,
        statistic: str,
        requested_statistic: Any,
        requested_unit: Optional[str],
        unit: Optional[str],
        dimensions: List[Dict[str, str]],
        start: datetime,
        end: datetime,
        requested_period: int,
        effective_period: int,
        period_adjusted: bool,
        request_count: int,
    ) -> Dict[str, Any]:
        expected_datapoints = cls._expected_datapoints(
            start=start,
            end=end,
            period=effective_period,
        )

        return {
            "metric_key": metric_key,
            "metric_name": metric_name,
            "namespace": namespace,
            "statistic": statistic,
            "requested_statistic": requested_statistic,
            "requested_unit": requested_unit,
            "unit": unit,
            "unit_parameter_sent": unit is not None,
            "dimensions": dimensions,
            # Exact caller-selected analysis window.
            "analysis_start": cls._isoformat(start),
            "analysis_end": cls._isoformat(end),
            # Metric collection window.
            "metric_start": cls._isoformat(start),
            "metric_end": cls._isoformat(end),
            # Backward-compatible aliases.
            "start": cls._isoformat(start),
            "end": cls._isoformat(end),
            # Period information.
            "requested_period": requested_period,
            "effective_period": effective_period,
            "period": effective_period,
            "period_adjusted": period_adjusted,
            "expected_datapoints": expected_datapoints,
            "request_count": request_count,
        }

    @classmethod
    def _calculate_chunk_duration(
        cls,
        period: int,
    ) -> timedelta:
        return timedelta(seconds=period * cls.MAX_DATAPOINTS_PER_REQUEST)

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
        chunk_duration = self._calculate_chunk_duration(period)

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

                if unit is not None:
                    kwargs["Unit"] = unit

                response = self.cloudwatch.get_metric_statistics(**kwargs)

                request_count += 1

                points = response.get("Datapoints", [])

                if isinstance(points, list):
                    all_datapoints.extend(points)

                if current_end <= current_start:
                    break

                current_start = current_end

            filtered: List[Dict[str, Any]] = []

            for point in all_datapoints:
                if not isinstance(point, dict):
                    continue

                timestamp = point.get("Timestamp")

                if timestamp is None:
                    continue

                timestamp = self._normalize_datetime(timestamp)

                if start <= timestamp < end:
                    filtered.append(point)

            filtered = self._deduplicate_datapoints(filtered)

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

    def _build_result(
        self,
        common: Dict[str, Any],
        datapoints: List[Dict[str, Any]],
        statistic: str,
        retrieval_status: Optional[str] = None,
        retrieval_messages: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        messages = retrieval_messages or []

        normalized_status = retrieval_status or "Complete"

        result: Dict[str, Any] = {
            **common,
            # Retrieval state.
            "status": "no_data",
            "retrieval_status": normalized_status,
            "retrieval_messages": messages,
            # Data state.
            "available": False,
            "has_data": False,
            "samples": 0,
            "datapoints": 0,
            # Aggregates.
            "value": None,
            "total": None,
            "average": None,
            "maximum": None,
            "minimum": None,
            "coverage_ratio": None,
            "coverage_percent": None,
            "complete": False,
            # Quality.
            "data_quality": "no_data",
            "error": None,
            "raw_datapoints": [],
        }

        if normalized_status in {"InternalError", "Forbidden"}:
            return self._apply_retrieval_failure(
                result=result,
                status=normalized_status,
                messages=messages,
            )

        datapoint_values: List[float] = []

        weighted_sum = 0.0
        weighted_count = 0.0

        raw_datapoints: List[Dict[str, Any]] = []

        for point in datapoints:
            if not isinstance(point, dict):
                continue

            if statistic not in point:
                continue

            raw_value = point.get(statistic)

            if raw_value is None:
                continue

            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue

            timestamp = point.get("Timestamp")

            if timestamp is None:
                continue

            timestamp = self._normalize_datetime(timestamp)

            datapoint_values.append(value)

            sample_count = point.get("SampleCount")

            try:
                sample_count = float(sample_count) if sample_count is not None else None
            except (TypeError, ValueError):
                sample_count = None

            if statistic == "Average" and sample_count is not None and sample_count > 0:
                weighted_sum += value * sample_count
                weighted_count += sample_count

            raw_datapoints.append(
                {
                    "timestamp": self._isoformat(timestamp),
                    "value": value,
                    "statistic": statistic,
                    "unit": point.get("Unit"),
                    "sample_count": sample_count,
                }
            )
        if not datapoint_values:
            if normalized_status == "PartialData":
                result.update(
                    {
                        "status": "partial_data",
                        "available": True,
                        "has_data": False,
                        "data_quality": "partial",
                        "raw_datapoints": raw_datapoints,
                        "complete": False,
                    }
                )
            else:
                result.update(
                    {
                        "status": "no_data",
                        "available": True,
                        "has_data": False,
                        "data_quality": "no_data",
                        "raw_datapoints": raw_datapoints,
                        # No datapoints is not evidence of complete
                        # inactivity.
                        "complete": False,
                    }
                )

            return result

        datapoint_count = len(datapoint_values)

        total = sum(datapoint_values)

        if statistic == "Average" and weighted_count > 0:
            average = weighted_sum / weighted_count
        else:
            average = total / datapoint_count if datapoint_count > 0 else None

        maximum = max(datapoint_values)
        minimum = min(datapoint_values)

        selected_value = self._select_metric_value(
            statistic=statistic,
            values=datapoint_values,
            weighted_average=average,
        )
        if normalized_status == "PartialData":
            status = "partial_data"
            quality = "partial"
            complete = False
        else:
            status = "ok"
            quality = "complete"
            complete = True

        result.update(
            {
                "status": status,
                "available": True,
                "has_data": True,
                "samples": datapoint_count,
                "datapoints": datapoint_count,
                "value": self._round(selected_value),
                "total": self._round(total),
                "average": self._round(average),
                "maximum": self._round(maximum),
                "minimum": self._round(minimum),
                # No fabricated coverage percentage.
                "coverage_ratio": None,
                "coverage_percent": None,
                "complete": complete,
                "data_quality": quality,
                "raw_datapoints": raw_datapoints,
            }
        )

        return result

    def _build_error_result(
        self,
        common: Dict[str, Any],
        error: Optional[str],
        retrieval_status: Optional[str] = "InternalError",
        retrieval_messages: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        return {
            **common,
            "status": "error",
            "retrieval_status": retrieval_status,
            "retrieval_messages": retrieval_messages or [],
            "available": False,
            "has_data": False,
            "samples": 0,
            "datapoints": 0,
            "value": None,
            "total": None,
            "average": None,
            "maximum": None,
            "minimum": None,
            "coverage_ratio": None,
            "coverage_percent": None,
            "complete": False,
            "data_quality": "error",
            "error": error,
            "raw_datapoints": [],
        }

    @staticmethod
    def _apply_retrieval_failure(
        result: Dict[str, Any],
        status: str,
        messages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        error_text = CloudWatchMetricCollector._messages_to_error(messages)

        result.update(
            {
                "status": "error",
                "available": False,
                "has_data": False,
                "complete": False,
                "data_quality": "error",
                "error": error_text,
            }
        )

        return result

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

            return sum(values) / len(values)

        if statistic == "Maximum":
            return max(values)

        if statistic == "Minimum":
            return min(values)

        if statistic == "SampleCount":
            return sum(values)

        return sum(values) / len(values)

    @classmethod
    def _expected_datapoints(
        cls,
        start: datetime,
        end: datetime,
        period: int,
    ) -> int:
        duration_seconds = (end - start).total_seconds()

        return max(
            1,
            int((duration_seconds + period - 1) // period),
        )

    @staticmethod
    def _merge_status(
        existing: Optional[str],
        incoming: Optional[str],
    ) -> Optional[str]:

        if incoming is None:
            return existing

        rank = {
            "InternalError": 4,
            "Forbidden": 4,
            "PartialData": 3,
            "Complete": 1,
        }

        if existing is None:
            return incoming

        if rank.get(incoming, 2) > rank.get(existing, 2):
            return incoming

        return existing

    @staticmethod
    def _messages_to_error(
        messages: List[Dict[str, Any]],
    ) -> str:
        parts: List[str] = []

        for message in messages:
            if not isinstance(message, dict):
                continue

            code = message.get("Code")
            value = message.get("Value")

            if code and value:
                parts.append(f"{code}: {value}")
            elif value:
                parts.append(str(value))
            elif code:
                parts.append(str(code))

        if parts:
            return "; ".join(parts)

        return "CloudWatch metric retrieval failed"

    @staticmethod
    def _deduplicate_datapoints(
        datapoints: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        seen: Dict[datetime, Dict[str, Any]] = {}

        for point in datapoints:
            if not isinstance(point, dict):
                continue

            timestamp = point.get("Timestamp")

            if timestamp is None:
                continue

            timestamp = CloudWatchMetricCollector._normalize_datetime(timestamp)

            normalized_point = dict(point)
            normalized_point["Timestamp"] = timestamp

            seen[timestamp] = normalized_point

        return sorted(
            seen.values(),
            key=lambda point: (
                CloudWatchMetricCollector._normalize_datetime(point["Timestamp"])
            ),
        )

    @staticmethod
    def _round(
        value: Optional[float],
    ) -> Optional[float]:
        if value is None:
            return None

        return round(float(value), 6)

    @staticmethod
    def _normalize_datetime(
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    @classmethod
    def _isoformat(
        cls,
        value: datetime,
    ) -> str:
        return cls._normalize_datetime(value).isoformat()
