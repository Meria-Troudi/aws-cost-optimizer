"""
Amazon S3 cost optimization analyzer.

Purpose
-------
Generate evidence-backed S3 cost-optimization findings.

Supported findings
------------------
1. s3_lifecycle_missing
2. s3_incomplete_multipart_uploads
3. s3_intelligent_tiering_candidate
4. s3_standard_ia_candidate
5. s3_glacier_candidate
6. s3_replication_cost_exposure

Important semantics
-------------------
- Missing telemetry is never treated as zero.
- Optional telemetry does not invalidate core findings.
- No savings are calculated.
- No S3 configuration is modified.
- Candidates are recommendations for review, not automatic decisions.
"""

from __future__ import annotations

from typing import Any

from ...base import Analyzer
from ...context import AnalysisContext
from ...condition import EvidenceStatement
from ...evidence import Evidence
from ...finding import Finding, ObservationPeriod
from ...registry import register


@register
class S3Analyzer(Analyzer):

    name = "s3_optimization"
    version = "1.1"

    # A low GET share means requests are not dominated by reads.
    # This is only a candidate signal.
    LOW_GET_RATIO_THRESHOLD = 0.05

    # These are deliberately conservative.
    # They are not AWS pricing thresholds.
    STANDARD_IA_MIN_STORAGE_GIB = 1.0
    GLACIER_MIN_STORAGE_GIB = 1.0

    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:

        resource_type = (
            context.resource_type or ""
        ).lower()

        return resource_type in {
            "s3",
            "s3_bucket",
            "bucket",
        }

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        if not self.supports(context):
            return []

        evidence = self._evidence_from_context(context)

        if not evidence:
            return []

        findings: list[Finding] = []

        detectors = (
            self._check_lifecycle_missing,
            self._check_incomplete_multipart_uploads,
            self._check_intelligent_tiering_candidate,
            self._check_standard_ia_candidate,
            self._check_glacier_candidate,
            self._check_replication_cost_exposure,
        )

        for detector in detectors:
            finding = detector(
                context,
                evidence,
            )

            if finding:
                findings.append(finding)

        return findings

    # ==================================================================
    # EVIDENCE HELPERS
    # ==================================================================

    def _evidence_from_context(
        self,
        context: AnalysisContext,
    ) -> dict[str, Any] | None:

        resource = context.resource or {}

        data = resource.get(
            "optimization_evidence"
        )

        if isinstance(data, dict) and data:
            return data

        return None

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _bucket_name(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> str:

        configuration = self._dict(
            evidence.get("configuration")
        )

        bucket_name = configuration.get(
            "bucket_name"
        )

        if (
            isinstance(bucket_name, str)
            and bucket_name.strip()
        ):
            return bucket_name

        return (
            context.resource_id
            or "unknown"
        )

    def _storage_section(
        self,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return self._dict(
            evidence.get("storage")
        )

    def _requests_section(
        self,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:

        return self._dict(
            evidence.get("requests")
        )

    def _storage_complete(
        self,
        evidence: dict[str, Any],
    ) -> bool:

        storage = self._storage_section(
            evidence
        )

        return (
            storage.get("available") is True
            and storage.get("complete") is True
            and storage.get("semantics_valid") is not False
        )

    def _requests_complete(
        self,
        evidence: dict[str, Any],
    ) -> bool:

        requests = self._requests_section(
            evidence
        )

        return (
            requests.get("available") is True
            and requests.get("complete") is True
            and requests.get("semantics_valid") is not False
        )

    def _storage_size_gib(
        self,
        evidence: dict[str, Any],
    ) -> float | None:

        storage = self._storage_section(
            evidence
        )

        # Preferred representation.
        classes_bytes = storage.get(
            "classes_bytes"
        )

        if isinstance(classes_bytes, dict):

            values = []

            for value in classes_bytes.values():

                if (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and value >= 0
                ):
                    values.append(
                        float(value)
                    )

            if values:
                return sum(values) / (
                    1024 ** 3
                )

        # Fallback to aggregate bucket size.
        bucket_size = storage.get(
            "bucket_size_bytes"
        )

        if (
            isinstance(bucket_size, (int, float))
            and not isinstance(bucket_size, bool)
            and bucket_size >= 0
        ):
            return float(bucket_size) / (
                1024 ** 3
            )

        return None

    def _get_request_ratio(
        self,
        evidence: dict[str, Any],
    ) -> float | None:

        requests = self._requests_section(
            evidence
        )

        total = requests.get("total")
        get_count = requests.get("get")

        if (
            not isinstance(total, (int, float))
            or isinstance(total, bool)
            or total <= 0
        ):
            return None

        if (
            not isinstance(get_count, (int, float))
            or isinstance(get_count, bool)
            or get_count < 0
            or get_count > total
        ):
            return None

        return float(get_count) / float(total)

    # ==================================================================
    # 1. LIFECYCLE
    # ==================================================================

    def _check_lifecycle_missing(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Finding | None:

        configuration = self._dict(
            evidence.get("configuration")
        )

        lifecycle_enabled = configuration.get(
            "lifecycle_enabled"
        )

        # Unknown != disabled.
        if lifecycle_enabled is not False:
            return None

        if not self._storage_complete(
            evidence
        ):
            return None

        storage = self._storage_section(
            evidence
        )

        size_gib = self._storage_size_gib(
            evidence
        )

        # Do not report a lifecycle opportunity
        # when we have complete telemetry proving
        # there is no stored data.
        if (
            storage.get("zero") is True
            and (
                size_gib is None
                or size_gib <= 0
            )
        ):
            return None

        # Missing request telemetry is not zero traffic: the
        # s3_apply_lifecycle_policy route requires an observed access
        # pattern, so no finding is produced without it.
        if not self._requests_complete(
            evidence
        ):
            return None

        bucket = self._bucket_name(
            context,
            evidence,
        )

        storage_description = (
            f"{size_gib:.1f} GiB of storage was observed."
            if size_gib is not None
            else "Stored data was observed."
        )

        conditions = [
            EvidenceStatement(
                name="lifecycle configuration",
                value=False,
                description=(
                    "No S3 lifecycle configuration is "
                    "currently configured for the bucket."
                ),
                source=[
                    "S3 GetBucketLifecycleConfiguration"
                ],
                evidence_keys=[
                    "configuration.lifecycle_enabled"
                ],
            ),
            EvidenceStatement(
                name="storage usage",
                value=size_gib,
                unit="GiB",
                description=storage_description,
                source=[
                    "CloudWatch S3 Storage Metrics"
                ],
                evidence_keys=[
                    "storage.bucket_size_bytes"
                ],
                observed=True,
            ),
        ]

        requests = self._requests_section(
            evidence
        )

        total = requests.get("total")

        conditions.append(
            EvidenceStatement(
                name="request activity",
                value=total,
                description=(
                    "Request telemetry is available "
                    "for the bucket."
                ),
                source=[
                    "CloudWatch S3 Request Metrics"
                ],
                evidence_keys=[
                    "requests.total"
                ],
                observed=True,
            )
        )

        return Finding(
            finding_type="s3_lifecycle_missing",
            title="S3 bucket is missing a lifecycle policy",
            resource_type=(
                context.resource_type
                or "s3_bucket"
            ),
            resource_id=bucket,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="high",
            reason=(
                f"S3 bucket {bucket} has no lifecycle "
                f"configuration and contains stored data. "
                f"{storage_description} "
                "Lifecycle transitions or expiration should "
                "be reviewed against the bucket's retention "
                "requirements."
            ),
            conditions=conditions,
            evidence=self._build_evidence(
                context,
                evidence,
                configuration={
                    "lifecycle_enabled": False,
                },
            ),
            observation_period=ObservationPeriod(
                start=None,
                end=None,
            ),
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="configuration",
            category="cost_optimization",
            status="active",
            impact={
                "observed_monthly_cost": None,
                "estimated_monthly_savings": None,
            },
            account_id=context.account_id,
            metadata={
                "region": context.region,
                "service": "Amazon S3",
            },
        )

    # ==================================================================
    # 2. INCOMPLETE MULTIPART UPLOADS
    # ==================================================================

    def _check_incomplete_multipart_uploads(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Finding | None:

        configuration = self._dict(
            evidence.get("configuration")
        )

        uploads_configuration = self._dict(
            configuration.get(
                "incomplete_multipart_uploads"
            )
        )

        multipart = self._dict(
            evidence.get("multipart_uploads")
        )

        upload_count = None

        if uploads_configuration:
            # Explicit inventory shape: status "ok" means the upload
            # listing succeeded; "error" or anything unknown means the
            # inventory is not trustworthy, so no conclusion is drawn.
            status = str(
                uploads_configuration.get("status") or ""
            ).strip().lower()

            if status != "ok":
                return None

            candidate = uploads_configuration.get("count")

            if (
                isinstance(candidate, int)
                and not isinstance(candidate, bool)
                and candidate > 0
            ):
                upload_count = candidate

        elif multipart:
            # Dedicated telemetry section shape.
            # Missing multipart telemetry is not zero.
            if multipart.get("available") is not True:
                return None

            if multipart.get("complete") is not True:
                return None

            candidate = multipart.get(
                "incomplete_upload_count"
            )

            if (
                isinstance(candidate, int)
                and not isinstance(candidate, bool)
                and candidate > 0
            ):
                upload_count = candidate

        else:
            return None

        if upload_count is None:
            return None

        bucket = self._bucket_name(
            context,
            evidence,
        )

        bytes_pending = multipart.get(
            "pending_bytes"
        )

        if (
            isinstance(bytes_pending, (int, float))
            and not isinstance(bytes_pending, bool)
            and bytes_pending >= 0
        ):
            pending_gib = (
                float(bytes_pending)
                / (1024 ** 3)
            )

            description = (
                f"{upload_count} incomplete multipart "
                f"upload(s) were observed, representing "
                f"approximately {pending_gib:.2f} GiB "
                "of uploaded parts."
            )
        else:
            pending_gib = None

            description = (
                f"{upload_count} incomplete multipart "
                "upload(s) were observed."
            )

        conditions = [
            EvidenceStatement(
                name="incomplete multipart uploads",
                value=upload_count,
                description=description,
                source=[
                    "S3 ListMultipartUploads",
                    "S3 ListParts",
                ],
                evidence_keys=[
                    "multipart_uploads.incomplete_upload_count"
                ],
                observed=True,
            ),
            EvidenceStatement(
                name="incomplete upload status",
                value="observed",
                description=(
                    "The multipart upload inventory was "
                    "retrieved successfully and incomplete "
                    "uploads were observed."
                ),
                source=[
                    "S3 ListMultipartUploads"
                ],
                evidence_keys=[
                    "configuration.incomplete_multipart_uploads"
                ],
                observed=True,
            ),
        ]

        if pending_gib is not None:
            conditions.append(
                EvidenceStatement(
                    name="pending multipart storage",
                    value=pending_gib,
                    unit="GiB",
                    description=(
                        "Uploaded multipart parts remain "
                        "associated with incomplete uploads."
                    ),
                    source=[
                        "S3 ListParts"
                    ],
                    evidence_keys=[
                        "multipart_uploads.pending_bytes"
                    ],
                    observed=True,
                )
            )

        return Finding(
            finding_type="s3_incomplete_multipart_uploads",
            title=(
                "S3 bucket has incomplete multipart uploads"
            ),
            resource_type=(
                context.resource_type
                or "s3_bucket"
            ),
            resource_id=bucket,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="medium",
            confidence="high",
            reason=description,
            conditions=conditions,
            evidence=self._build_evidence(
                context,
                evidence,
                configuration={
                    "incomplete_multipart_uploads": True,
                },
            ),
            observation_period=ObservationPeriod(
                start=None,
                end=None,
            ),
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="storage",
            category="cost_optimization",
            status="active",
            impact={
                "observed_monthly_cost": None,
                "estimated_monthly_savings": None,
            },
            account_id=context.account_id,
            metadata={
                "region": context.region,
                "service": "Amazon S3",
            },
        )

    # ==================================================================
    # 3. INTELLIGENT TIERING
    # ==================================================================

    def _check_intelligent_tiering_candidate(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Finding | None:

        configuration = self._dict(
            evidence.get("configuration")
        )

        if configuration.get(
            "intelligent_tiering_enabled"
        ) is not False:
            return None

        if not self._storage_complete(
            evidence
        ):
            return None

        if not self._requests_complete(
            evidence
        ):
            return None

        ratio = self._get_request_ratio(
            evidence
        )

        if ratio is None:
            return None

        if ratio >= self.LOW_GET_RATIO_THRESHOLD:
            return None

        size_gib = self._storage_size_gib(
            evidence
        )

        if size_gib is None or size_gib <= 0:
            return None

        bucket = self._bucket_name(
            context,
            evidence,
        )

        percentage = ratio * 100

        conditions = [
            EvidenceStatement(
                name="Intelligent-Tiering configuration",
                value=False,
                description=(
                    "The bucket is not currently configured "
                    "with S3 Intelligent-Tiering."
                ),
                source=[
                    "S3 ListBucketIntelligentTieringConfigurations"
                ],
                evidence_keys=[
                    "configuration.intelligent_tiering_enabled"
                ],
            ),
            EvidenceStatement(
                name="storage size",
                value=size_gib,
                unit="GiB",
                description=(
                    "Stored data is present in the bucket."
                ),
                source=[
                    "CloudWatch S3 Storage Metrics"
                ],
                evidence_keys=[
                    "storage.bucket_size_bytes"
                ],
                observed=True,
            ),
            EvidenceStatement(
                name="GET request ratio",
                value=ratio,
                description=(
                    f"GET requests represent approximately "
                    f"{percentage:.2f}% of observed requests."
                ),
                source=[
                    "CloudWatch S3 Request Metrics"
                ],
                evidence_keys=[
                    "requests.get",
                    "requests.total",
                ],
                observed=True,
            ),
        ]

        return Finding(
            finding_type="s3_intelligent_tiering_candidate",
            title=(
                "S3 bucket may be a candidate for Intelligent-Tiering"
            ),
            resource_type=(
                context.resource_type
                or "s3_bucket"
            ),
            resource_id=bucket,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="low",
            confidence="medium",
            reason=(
                f"S3 bucket {bucket} stores approximately "
                f"{size_gib:.1f} GiB and has a low observed "
                f"GET-request ratio of {percentage:.2f}%. "
                "Intelligent-Tiering may be worth evaluating "
                "if object access patterns are variable or "
                "unpredictable."
            ),
            conditions=conditions,
            evidence=self._build_evidence(
                context,
                evidence,
                configuration={
                    "intelligent_tiering_enabled": False,
                    "get_request_ratio": ratio,
                },
            ),
            observation_period=ObservationPeriod(
                start=None,
                end=None,
            ),
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="storage",
            category="cost_optimization",
            status="active",
            impact={
                "observed_monthly_cost": None,
                "estimated_monthly_savings": None,
            },
            account_id=context.account_id,
            metadata={
                "region": context.region,
                "service": "Amazon S3",
            },
        )

    # ==================================================================
    # 4. STANDARD-IA
    # ==================================================================

    def _check_standard_ia_candidate(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Finding | None:

        storage_classes = self._dict(
            self._storage_section(
                evidence
            ).get("classes_bytes")
        )

        standard_bytes = self._numeric(
            storage_classes.get("STANDARD")
        )

        ia_bytes = self._numeric(
            storage_classes.get("STANDARD_IA")
        )

        # We need class-level evidence.
        if standard_bytes is None:
            return None

        if ia_bytes is not None and ia_bytes > 0:
            return None

        if not self._storage_complete(
            evidence
        ):
            return None

        standard_gib = (
            standard_bytes / (1024 ** 3)
        )

        if (
            standard_gib
            < self.STANDARD_IA_MIN_STORAGE_GIB
        ):
            return None

        bucket = self._bucket_name(
            context,
            evidence,
        )

        conditions = [
            EvidenceStatement(
                name="STANDARD storage",
                value=standard_gib,
                unit="GiB",
                description=(
                    "The bucket has observed storage in "
                    "the S3 STANDARD storage class."
                ),
                source=[
                    "CloudWatch S3 Storage Metrics"
                ],
                evidence_keys=[
                    "storage.classes_bytes.STANDARD"
                ],
                observed=True,
            ),
            EvidenceStatement(
                name="STANDARD_IA storage",
                value=0,
                unit="GiB",
                description=(
                    "No STANDARD_IA storage was observed "
                    "in the collected storage-class telemetry."
                ),
                source=[
                    "CloudWatch S3 Storage Metrics"
                ],
                evidence_keys=[
                    "storage.classes_bytes.STANDARD_IA"
                ],
                observed=True,
            ),
        ]

        return Finding(
            finding_type="s3_standard_ia_candidate",
            title=(
                "S3 bucket may contain data suitable for Standard-IA"
            ),
            resource_type=(
                context.resource_type
                or "s3_bucket"
            ),
            resource_id=bucket,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="low",
            confidence="low",
            reason=(
                f"Approximately {standard_gib:.1f} GiB is "
                "currently stored in STANDARD and no "
                "STANDARD_IA storage was observed. "
                "Object access frequency and minimum-storage "
                "duration requirements should be validated "
                "before changing storage class."
            ),
            conditions=conditions,
            evidence=self._build_evidence(
                context,
                evidence,
                configuration={
                    "standard_storage_gib": standard_gib,
                },
            ),
            observation_period=ObservationPeriod(
                start=None,
                end=None,
            ),
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="storage",
            category="cost_optimization",
            status="active",
            impact={
                "observed_monthly_cost": None,
                "estimated_monthly_savings": None,
            },
            account_id=context.account_id,
            metadata={
                "region": context.region,
                "service": "Amazon S3",
            },
        )

    # ==================================================================
    # 5. GLACIER / ARCHIVE
    # ==================================================================

    def _check_glacier_candidate(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Finding | None:

        storage_classes = self._dict(
            self._storage_section(
                evidence
            ).get("classes_bytes")
        )

        standard_bytes = self._numeric(
            storage_classes.get("STANDARD")
        )

        if standard_bytes is None:
            return None

        if not self._storage_complete(
            evidence
        ):
            return None

        archive_classes = (
            "GLACIER",
            "DEEP_ARCHIVE",
        )

        archive_bytes = sum(
            self._numeric(
                storage_classes.get(name)
            ) or 0
            for name in archive_classes
        )

        standard_gib = (
            standard_bytes / (1024 ** 3)
        )

        archive_gib = (
            archive_bytes / (1024 ** 3)
        )

        # If a meaningful amount is already archived,
        # this detector has no evidence that STANDARD
        # should also be archived.
        if archive_gib > 0:
            return None

        if (
            standard_gib
            < self.GLACIER_MIN_STORAGE_GIB
        ):
            return None

        bucket = self._bucket_name(
            context,
            evidence,
        )

        conditions = [
            EvidenceStatement(
                name="STANDARD storage",
                value=standard_gib,
                unit="GiB",
                description=(
                    "Data is currently observed in STANDARD "
                    "rather than an archive storage class."
                ),
                source=[
                    "CloudWatch S3 Storage Metrics"
                ],
                evidence_keys=[
                    "storage.classes_bytes.STANDARD"
                ],
                observed=True,
            ),
            EvidenceStatement(
                name="archive storage",
                value=archive_gib,
                unit="GiB",
                description=(
                    "No GLACIER or DEEP_ARCHIVE storage was "
                    "observed in the collected telemetry."
                ),
                source=[
                    "CloudWatch S3 Storage Metrics"
                ],
                evidence_keys=[
                    "storage.classes_bytes.GLACIER",
                    "storage.classes_bytes.DEEP_ARCHIVE",
                ],
                observed=True,
            ),
        ]

        return Finding(
            finding_type="s3_glacier_candidate",
            title=(
                "S3 bucket may contain data suitable for archival storage"
            ),
            resource_type=(
                context.resource_type
                or "s3_bucket"
            ),
            resource_id=bucket,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="low",
            confidence="low",
            reason=(
                f"Approximately {standard_gib:.1f} GiB is "
                "stored in STANDARD and no archive-class "
                "storage was observed. Object retention, "
                "retrieval requirements, and access frequency "
                "must be validated before archival transition."
            ),
            conditions=conditions,
            evidence=self._build_evidence(
                context,
                evidence,
                configuration={
                    "standard_storage_gib": standard_gib,
                },
            ),
            observation_period=ObservationPeriod(
                start=None,
                end=None,
            ),
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="storage",
            category="cost_optimization",
            status="active",
            impact={
                "observed_monthly_cost": None,
                "estimated_monthly_savings": None,
            },
            account_id=context.account_id,
            metadata={
                "region": context.region,
                "service": "Amazon S3",
            },
        )

    # ==================================================================
    # 6. REPLICATION
    # ==================================================================

    def _check_replication_cost_exposure(
        self,
        context: AnalysisContext,
        evidence: dict[str, Any],
    ) -> Finding | None:

        replication = self._dict(
            evidence.get("replication")
        )

        configuration = self._dict(
            evidence.get("configuration")
        )

        enabled = replication.get(
            "enabled"
        )

        if enabled is not True:
            enabled = configuration.get(
                "replication_enabled"
            )

        if enabled is not True:
            return None

        rule_count = replication.get(
            "rule_count"
        )

        if not isinstance(
            rule_count,
            int,
        ):
            rule_count = configuration.get(
                "replication_rule_count"
            )

        if (
            not isinstance(rule_count, int)
            or rule_count <= 1
        ):
            return None

        bucket = self._bucket_name(
            context,
            evidence,
        )

        conditions = [
            EvidenceStatement(
                name="replication enabled",
                value=True,
                description=(
                    "S3 replication is configured for the bucket."
                ),
                source=[
                    "S3 GetBucketReplication"
                ],
                evidence_keys=[
                    "replication.enabled"
                ],
            ),
            EvidenceStatement(
                name="replication rules",
                value=rule_count,
                description=(
                    f"{rule_count} replication rules are "
                    "currently configured."
                ),
                source=[
                    "S3 GetBucketReplication"
                ],
                evidence_keys=[
                    "replication.rule_count"
                ],
                observed=True,
            ),
        ]

        return Finding(
            finding_type="s3_replication_cost_exposure",
            title=(
                "S3 bucket has multiple replication rules"
            ),
            resource_type=(
                context.resource_type
                or "s3_bucket"
            ),
            resource_id=bucket,
            analyzer=self.name,
            analyzer_version=self.version,
            severity="low",
            confidence="medium",
            reason=(
                f"S3 bucket {bucket} has {rule_count} "
                "replication rules. Replication can introduce "
                "additional storage, request, and data-transfer "
                "charges. Review whether every rule and destination "
                "is still required."
            ),
            conditions=conditions,
            evidence=self._build_evidence(
                context,
                evidence,
                configuration={
                    "replication_enabled": True,
                    "replication_rule_count": rule_count,
                },
            ),
            observation_period=ObservationPeriod(
                start=None,
                end=None,
            ),
            recommendation_eligible=True,
            aggregation_scope="resource",
            cost_optimization_type="configuration",
            category="cost_optimization",
            status="active",
            impact={
                "observed_monthly_cost": None,
                "estimated_monthly_savings": None,
            },
            account_id=context.account_id,
            metadata={
                "region": context.region,
                "service": "Amazon S3",
            },
        )

    # ==================================================================
    # NUMERIC HELPER
    # ==================================================================

    def _build_evidence(
        self,
        context: AnalysisContext,
        raw_evidence: dict[str, Any],
        configuration: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Structured evidence for an S3 finding.

        Completeness information is carried through verbatim: missing
        telemetry is represented as None / absent keys, never as zero.
        """

        storage = self._storage_section(raw_evidence)
        requests = self._requests_section(raw_evidence)

        merged_configuration = {
            **self._dict(raw_evidence.get("configuration")),
            **self._dict(configuration),
        }

        metrics: dict[str, Any] = {}

        if requests.get("available") is True:
            metrics["requests_total"] = requests.get("total")
            metrics["requests_get"] = requests.get("get")

        derived: dict[str, Any] = {}

        if storage:
            derived["storage_usage"] = {
                "classes_bytes": storage.get("classes_bytes"),
                "bucket_size_bytes": storage.get("bucket_size_bytes"),
                "number_of_objects": storage.get("number_of_objects"),
                "size_gib": self._storage_size_gib(raw_evidence),
            }

        if requests.get("available") is True:
            derived["access_pattern"] = {
                "total_requests": requests.get("total"),
                "get_requests": requests.get("get"),
                "get_ratio": self._get_request_ratio(raw_evidence),
            }

        replication = raw_evidence.get("replication")

        if isinstance(replication, dict) and replication:
            derived["replication"] = replication

        return Evidence(
            configuration=merged_configuration,
            resource={
                "bucket_name": self._bucket_name(context, raw_evidence),
                "region": context.region,
            },
            metrics=metrics,
            derived=derived,
            data_quality=self._dict(raw_evidence.get("data_quality")),
        )

    @staticmethod
    def _numeric(

        value: Any,
    ) -> float | None:

        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
        ):
            return float(value)

        return None