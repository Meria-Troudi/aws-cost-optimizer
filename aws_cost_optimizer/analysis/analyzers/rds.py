"""
RDS optimization analyzer.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..billing_consistency import extract_rds_class
from ..condition import EvidenceStatement
from ..context import AnalysisContext
from ..evidence import Evidence
from ..finding import Finding, ObservationPeriod
from ..metrics import metric_summary
from .base import Analyzer
from .registry import register


RDS_CONFIGURATION_FIELDS = (
    "instance_class",
    "engine",
    "engine_version",
    "multi_az",
    "availability_zone",
    "backup_retention_days",
    "publicly_accessible",
    "performance_insights_enabled",
    "storage_type",
    "allocated_storage_gib",
)


@register
class RDSAnalyzer(Analyzer):

    name = "rds"
    version = "1.0"
    resource_type = "rds_instance"

    IDLE_CPU_PERCENT = 5.0
    LOW_CPU_PERCENT = 15.0
    IDLE_CONNECTIONS = 0.0
    LOW_CONNECTIONS = 2.0
    LOW_READ_IOPS = 1.0
    LOW_WRITE_IOPS = 1.0
    LOW_NETWORK_BYTES_PER_SECOND = 1024.0

 
    LOW_MEMORY_FREE_RATIO = 0.15
    HIGH_BACKUP_RETENTION_DAYS = 14
    HIGH_STORAGE_UTILIZATION = 0.80


    OLD_INSTANCE_FAMILIES = (
        "db.t2.",
        "db.m3.",
        "db.m4.",
        "db.r3.",
        "db.r4.",
    )


    def supports(
        self,
        context: AnalysisContext,
    ) -> bool:
        return context.resource_type in (
            "rds_instance",
            "rds",
        )

    def analyze(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:
        if not self.supports(context):
            return []

        raw_findings = self._run_checks(context.resource)
        return [
            self._to_finding(context, raw)
            for raw in raw_findings
        ]

    def _run_checks(self, resource: Dict[str, Any],) -> List[Dict[str, Any]]:
        if not self._is_rds_resource(resource):
            return []
        findings: List[Dict[str, Any]] = []
        idle = self._check_idle_instance( resource)

        if idle:
            findings.append(idle)
        oversized = self._check_oversized_instance( resource)

        if oversized:
            findings.append(oversized)

        multi_az = self._check_multi_az( resource)
        if multi_az:
            findings.append(multi_az)

        backup = self._check_backup_retention(resource)

        if backup:
            findings.append(backup)


        performance_insights = ( self._check_performance_insights( resource))
        if performance_insights:
            findings.append(performance_insights)


        high_io = self._check_high_io( resource)

        if high_io:
            findings.append(high_io)

        old_generation = (self._check_old_generation(resource ) )
        if old_generation:
            findings.append(old_generation)

        replica = self._check_read_replica( resource )
        if replica:
            findings.append(replica)

        aurora = self._check_aurora_context( resource )
        if aurora:
            findings.append(aurora)

        public = self._check_public_accessibility( resource)
        if public:
            findings.append(public)
        return findings

    @classmethod
    def _is_rds_resource(cls, resource: Dict[str, Any]) -> bool:

        resource_type = resource.get( "resource_type")
        if resource_type == cls.resource_type:
            return True
        if resource_type == "rds":
            return True
        if resource.get("type") == "rds_instance":
            return True

        return False

    @staticmethod
    def _resource_id(
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource.get( "resource_id")
            or resource.get("id")
            or resource.get("configuration",{}, ).get( "db_instance_identifier","unknown", )
        )
    @staticmethod
    def _configuration(
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = resource.get( "configuration", {}, )
        if not isinstance(configuration, dict):
            return {}
        return configuration

    @staticmethod
    def _observations(
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations = resource.get( "observations", {}, )
        if not isinstance(observations, dict):
            return {}

        return observations

    @classmethod
    def _metrics(
        cls,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations = cls._observations(resource)
        cloudwatch = observations.get("cloudwatch", {}, )    
        if not isinstance(cloudwatch, dict):
            return {}

        metrics = cloudwatch.get("metrics", {}, )
        if not isinstance(metrics, dict):
            return {}

        return metrics

  
    @classmethod
    def _metric_value(
        cls,
        resource: Dict[str, Any],
        metric_name: str,
    ) -> Optional[float]:

        metrics = cls._metrics(resource)
        metric = metrics.get(metric_name)
        if not isinstance(
            metric,
            dict,
        ):
            return None

        value = metric.get(
            "value"
        )

        if value is None:
            return None

        try:
            return float(value)

        except (
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _has_metric(
        cls,
        resource: Dict[str, Any],
        metric_name: str,
    ) -> bool:

        return (
            cls._metric_value(
                resource,
                metric_name,
            )
            is not None
        )

    @staticmethod
    def _billing_context(
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        context = resource.get(
            "cost_context",
            {},
        )

        if not isinstance(
            context,
            dict,
        ):
            return {}

        return context

    @classmethod
    def _billing_usage_type(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[str]:

        context = cls._billing_context(
            resource
        )

        candidates = (
            "usage_type",
            "billing_usage_type",
        )

        for key in candidates:

            value = context.get(
                key
            )

            if value:
                return str(value)

        billing = context.get(
            "billing",
            {},
        )

        if isinstance(
            billing,
            dict,
        ):

            value = (
                billing.get(
                    "usage_type"
                )
            )

            if value:
                return str(value)

        return None

    @classmethod
    def _billing_instance_class(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[str]:

        usage_type = (
            cls._billing_usage_type(
                resource
            )
        )

        return extract_rds_class(usage_type)


    @classmethod
    def _check_billing_resource_mismatch(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Deprecated per-resource mismatch check.

        Billing attribution is validated at the collection-plan level.
        A billing usage type must not be attributed to a resource with a
        different instance class.
        """
        return None

 
    @classmethod
    def _check_idle_instance(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        cpu = cls._metric_value(
            resource,
            "CPUUtilization",
        )

        connections = cls._metric_value(
            resource,
            "DatabaseConnections",
        )

        read_iops = cls._metric_value(
            resource,
            "ReadIOPS",
        )

        write_iops = cls._metric_value(
            resource,
            "WriteIOPS",
        )

        network_rx = cls._metric_value(
            resource,
            "NetworkReceiveThroughput",
        )

        network_tx = cls._metric_value(
            resource,
            "NetworkTransmitThroughput",
        )
        if cpu is None:
            return None

        if connections is None:
            return None

        if read_iops is None:
            return None

        if write_iops is None:
            return None

      
        idle_compute = (
            cpu <= cls.IDLE_CPU_PERCENT
        )

        idle_connections = (
            connections <= cls.IDLE_CONNECTIONS
        )

        idle_io = (
            read_iops <= cls.LOW_READ_IOPS
            and
            write_iops <= cls.LOW_WRITE_IOPS
        )

        if not (
            idle_compute
            and idle_connections
            and idle_io
        ):
            return None

        network_idle = True

        if (
            network_rx is not None
            and network_tx is not None
        ):

            network_idle = (
                network_rx
                <= cls.LOW_NETWORK_BYTES_PER_SECOND
                and
                network_tx
                <= cls.LOW_NETWORK_BYTES_PER_SECOND
            )

        if not network_idle:
            return None

        return cls._finding(
            finding_type=(
                "rds_no_activity"
            ),

            severity="MEDIUM",

            confidence="HIGH",

            resource=resource,

            reason=(
                "The RDS instance shows very low "
                "CPU utilization, zero database "
                "connections, and negligible I/O "
                "during the observation period."
            ),

            conditions=[
                {
                    "name":
                        "cpu_low",

                    "expected":
                        f"<= {cls.IDLE_CPU_PERCENT}%",

                    "actual":
                        cpu,

                    "status":
                        "PASS",
                },

                {
                    "name":
                        "connections_low",

                    "expected":
                        f"<= {cls.IDLE_CONNECTIONS}",

                    "actual":
                        connections,

                    "status":
                        "PASS",
                },

                {
                    "name":
                        "read_iops_low",

                    "expected":
                        f"<= {cls.LOW_READ_IOPS}",

                    "actual":
                        read_iops,

                    "status":
                        "PASS",
                },

                {
                    "name":
                        "write_iops_low",

                    "expected":
                        f"<= {cls.LOW_WRITE_IOPS}",

                    "actual":
                        write_iops,

                    "status":
                        "PASS",
                },
            ],

            metadata={
                "cpu_percent":
                    cpu,

                "database_connections":
                    connections,

                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "network_receive_bytes_per_second":
                    network_rx,

                "network_transmit_bytes_per_second":
                    network_tx,
            },
        )

   
    @classmethod
    def _check_oversized_instance(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        instance_class = configuration.get(
            "instance_class"
        )

        if not instance_class:
            return None

        cpu = cls._metric_value(
            resource,
            "CPUUtilization",
        )

        connections = cls._metric_value(
            resource,
            "DatabaseConnections",
        )

        read_iops = cls._metric_value(
            resource,
            "ReadIOPS",
        )

        write_iops = cls._metric_value(
            resource,
            "WriteIOPS",
        )

        if cpu is None:
            return None

        if connections is None:
            return None

        if read_iops is None:
            return None

        if write_iops is None:
            return None

        if (
            cpu <= cls.IDLE_CPU_PERCENT
            and connections == 0
            and read_iops <= cls.LOW_READ_IOPS
            and write_iops <= cls.LOW_WRITE_IOPS
        ):
            return None

        low_utilization = (
            cpu <= cls.LOW_CPU_PERCENT
        )

        low_connections = (
            connections <= cls.LOW_CONNECTIONS
        )

        low_io = (
            read_iops <= 10.0
            and
            write_iops <= 10.0
        )

        if not (
            low_utilization
            and low_connections
            and low_io
        ):
            return None

  
      

        return cls._finding(
            finding_type=(
                "rds_instance_possible_oversized"
            ),

            severity="MEDIUM",

            confidence="MEDIUM",

            resource=resource,

            reason=(
                f"RDS instance {instance_class} "
                "shows consistently low CPU, "
                "low connections, and low I/O "
                "during the observation period. "
                "The instance size should be reviewed "
                "against workload requirements."
            ),

            conditions=[
                {
                    "name":
                        "cpu_low",

                    "expected":
                        f"<= {cls.LOW_CPU_PERCENT}%",

                    "actual":
                        cpu,

                    "status":
                        "PASS",
                },

                {
                    "name":
                        "connections_low",

                    "expected":
                        f"<= {cls.LOW_CONNECTIONS}",

                    "actual":
                        connections,

                    "status":
                        "PASS",
                },

                {
                    "name":
                        "io_low",

                    "expected":
                        "<= 10 IOPS",

                    "actual":
                        {
                            "read":
                                read_iops,

                            "write":
                                write_iops,
                        },

                    "status":
                        "PASS",
                },
            ],

            metadata={
                "instance_class":
                    instance_class,

                "cpu_percent":
                    cpu,

                "database_connections":
                    connections,

                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,
            },
        )

  
    @classmethod
    def _check_multi_az(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        multi_az = configuration.get(
            "multi_az"
        )

        if multi_az is not True:
            return None

        cpu = cls._metric_value(
            resource,
            "CPUUtilization",
        )

        connections = cls._metric_value(
            resource,
            "DatabaseConnections",
        )

        evidence: Dict[str, Any] = {
            "multi_az":
                True,
        }

        if cpu is not None:
            evidence["cpu_percent"] = cpu

        if connections is not None:
            evidence["database_connections"] = connections

        return cls._finding(
            finding_type=(
                "rds_multi_az_cost_review"
            ),

            severity="LOW",

            confidence="MEDIUM",

            resource=resource,

            reason=(
                "The RDS instance is configured for "
                "Multi-AZ. Review whether the workload "
                "requires the current availability "
                "configuration before considering a "
                "Single-AZ configuration."
            ),

            conditions=[
                {
                    "name":
                        "multi_az_enabled",

                    "expected":
                        False,

                    "actual":
                        True,

                    "status":
                        "INFO",
                }
            ],

            metadata=evidence,
        )

    @classmethod
    def _check_backup_retention(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        retention = configuration.get(
            "backup_retention_days"
        )

        if retention is None:
            return None

        try:
            retention = int(
                retention
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        if (
            retention
            <= cls.HIGH_BACKUP_RETENTION_DAYS
        ):
            return None

        return cls._finding(
            finding_type=(
                "rds_excessive_backup_retention"
            ),

            severity="LOW",

            confidence="MEDIUM",

            resource=resource,

            reason=(
                f"Backup retention is configured "
                f"for {retention} days. Review whether "
                "the recovery requirements justify "
                "the current retention period and "
                "associated backup storage."
            ),

            conditions=[
                {
                    "name":
                        "backup_retention_high",

                    "expected":
                        f"> {cls.HIGH_BACKUP_RETENTION_DAYS} days",

                    "actual":
                        retention,

                    "status":
                        "PASS",
                }
            ],

            metadata={
                "backup_retention_days":
                    retention,
            },
        )

    @classmethod
    def _check_performance_insights(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        enabled = configuration.get(
            "performance_insights_enabled"
        )

        if enabled is not True:
            return None

        return cls._finding(
            finding_type=(
                "rds_performance_insights_review"
            ),

            severity="LOW",

            confidence="LOW",

            resource=resource,

            reason=(
                "Performance Insights is enabled. "
                "Review whether its monitoring capability "
                "is still required for this workload."
            ),

            conditions=[
                {
                    "name":
                        "performance_insights_enabled",

                    "expected":
                        False,

                    "actual":
                        True,

                    "status":
                        "INFO",
                }
            ],

            metadata={
                "performance_insights_enabled":
                    True,
            },
        )

  
    @classmethod
    def _check_high_io(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        read_iops = cls._metric_value(
            resource,
            "ReadIOPS",
        )

        write_iops = cls._metric_value(
            resource,
            "WriteIOPS",
        )

        read_latency = cls._metric_value(
            resource,
            "ReadLatency",
        )

        write_latency = cls._metric_value(
            resource,
            "WriteLatency",
        )

        if (
            read_iops is None
            and write_iops is None
        ):
            return None

        read_iops = (
            read_iops or 0.0
        )

        write_iops = (
            write_iops or 0.0
        )

        total_iops = (
            read_iops
            + write_iops
        )

       
        if total_iops < 100:
            return None

        return cls._finding(
            finding_type=(
                "rds_io_intensive_workload"
            ),

            severity="INFO",

            confidence="HIGH",

            resource=resource,

            reason=(
                "The RDS workload shows significant "
                "I/O activity. Storage configuration "
                "and I/O requirements should be reviewed "
                "before considering instance downsizing."
            ),

            conditions=[
                {
                    "name":
                        "total_iops_high",

                    "expected":
                        ">= 100 IOPS",

                    "actual":
                        total_iops,

                    "status":
                        "PASS",
                }
            ],

            metadata={
                "read_iops":
                    read_iops,

                "write_iops":
                    write_iops,

                "total_iops":
                    total_iops,

                "read_latency":
                    read_latency,

                "write_latency":
                    write_latency,
            },
        )

 
    @classmethod
    def _check_old_generation(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        instance_class = configuration.get(
            "instance_class"
        )

        if not instance_class:
            return None

        if not any(
            instance_class.startswith(prefix)
            for prefix
            in cls.OLD_INSTANCE_FAMILIES
        ):
            return None

        return cls._finding(
            finding_type=(
                "rds_old_instance_generation"
            ),

            severity="LOW",

            confidence="HIGH",

            resource=resource,

            reason=(
                f"The RDS instance uses "
                f"{instance_class}, which belongs "
                "to an older instance generation. "
                "Evaluate newer generations for "
                "potentially better price/performance."
            ),

            conditions=[
                {
                    "name":
                        "old_instance_generation",

                    "expected":
                        "newer generation",

                    "actual":
                        instance_class,

                    "status":
                        "PASS",
                }
            ],

            metadata={
                "instance_class":
                    instance_class,
            },
        )

  
    @classmethod
    def _check_read_replica(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        replica_source = configuration.get(
            "read_replica_source"
        )

        if not replica_source:
            return None

        connections = cls._metric_value(
            resource,
            "DatabaseConnections",
        )

        network_rx = cls._metric_value(
            resource,
            "NetworkReceiveThroughput",
        )

        network_tx = cls._metric_value(
            resource,
            "NetworkTransmitThroughput",
        )

        low_connections = (
            connections is not None
            and
            connections <= cls.LOW_CONNECTIONS
        )

        low_network = (
            network_rx is not None
            and
            network_tx is not None
            and
            network_rx
            <= cls.LOW_NETWORK_BYTES_PER_SECOND
            and
            network_tx
            <= cls.LOW_NETWORK_BYTES_PER_SECOND
        )

        if not (
            low_connections
            and low_network
        ):
            return None

        return cls._finding(
            finding_type=(
                "rds_underused_read_replica"
            ),

            severity="MEDIUM",

            confidence="MEDIUM",

            resource=resource,

            reason=(
                "The RDS instance is a read replica "
                "with very low observed connections "
                "and network activity. Review whether "
                "the replica is still required."
            ),

            conditions=[
                {
                    "name":
                        "connections_low",

                    "expected":
                        f"<= {cls.LOW_CONNECTIONS}",

                    "actual":
                        connections,

                    "status":
                        "PASS",
                },

                {
                    "name":
                        "network_low",

                    "expected":
                        "low",

                    "actual":
                        {
                            "receive":
                                network_rx,

                            "transmit":
                                network_tx,
                        },

                    "status":
                        "PASS",
                },
            ],

            metadata={
                "read_replica_source":
                    replica_source,

                "database_connections":
                    connections,

                "network_receive":
                    network_rx,

                "network_transmit":
                    network_tx,
            },
        )

  
    @classmethod
    def _check_aurora_context(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        engine = str(
            configuration.get(
                "engine",
                "",
            )
        ).lower()

        if not engine.startswith(
            "aurora"
        ):
            return None

        cluster_identifier = (
            configuration.get(
                "db_cluster_identifier"
            )
        )

        if not cluster_identifier:
            cluster_identifier = (
                configuration.get(
                    "db_cluster_id"
                )
            )

        if not cluster_identifier:
            return None

       
        return cls._finding(
            finding_type=(
                "rds_aurora_cluster_context"
            ),

            severity="INFO",

            confidence="HIGH",

            resource=resource,

            reason=(
                "The RDS instance belongs to an "
                "Aurora cluster. Instance-level "
                "right-sizing should be evaluated "
                "together with the cluster writer/"
                "reader topology."
            ),

            conditions=[
                {
                    "name":
                        "aurora_cluster_detected",

                    "expected":
                        True,

                    "actual":
                        True,

                    "status":
                        "INFO",
                }
            ],

            metadata={
                "engine":
                    engine,

                "cluster_identifier":
                    cluster_identifier,
            },
        )

  
    @classmethod
    def _check_public_accessibility(
        cls,
        resource: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:

        configuration = cls._configuration(
            resource
        )

        publicly_accessible = (
            configuration.get(
                "publicly_accessible"
            )
        )

        if publicly_accessible is not True:
            return None

        return cls._finding(
            finding_type=(
                "rds_public_accessibility"
            ),

            severity="LOW",

            confidence="HIGH",

            resource=resource,

            reason=(
                "The RDS instance is publicly "
                "accessible. Review whether public "
                "access is required."
            ),

            conditions=[
                {
                    "name":
                        "publicly_accessible",

                    "expected":
                        False,

                    "actual":
                        True,

                    "status":
                        "FAIL",
                }
            ],
        )

    @classmethod
    def _finding(
        cls,
        *,
        finding_type: str,
        severity: str,
        confidence: str,
        resource: Dict[str, Any],
        reason: str,
        conditions: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
        limitations: Optional[List[str]] = None,
        recommendation_eligible: bool = True,
    ) -> Dict[str, Any]:
        return {
            "finding_type": finding_type,
            "severity": severity.lower(),
            "confidence": confidence.lower(),
            "resource_id": cls._resource_id(resource),
            "resource_type": cls.resource_type,
            "reason": reason,
            "conditions": conditions,
            "metadata": metadata or {},
            "limitations": limitations or [],
            "recommendation_eligible": recommendation_eligible,
        }

    def _to_finding(
        self,
        context: AnalysisContext,
        raw: Dict[str, Any],
    ) -> Finding:
        statements = [
            self._condition_to_statement(condition)
            for condition in raw.get("conditions", [])
            if isinstance(condition, dict)
        ]

        configuration = context.configuration()
        metrics = {
            name: metric_summary(context.metric(name))
            for name in context.metrics()
        }

        billing_match = context.rds_billing_match()

        return Finding(
            finding_type=raw["finding_type"],
            resource_type=context.resource_type or self.resource_type,
            resource_id=context.resource_id or raw.get("resource_id", "unknown"),
            analyzer=self.name,
            analyzer_version=self.version,
            severity=raw.get("severity", "medium"),
            confidence=raw.get("confidence", "medium"),
            reason=raw.get("reason", ""),
            conditions=statements,
            evidence=Evidence(
                metrics=metrics,
                configuration={
                    key: configuration.get(key)
                    for key in RDS_CONFIGURATION_FIELDS
                    if key in configuration
                },
                topology=context.topology(),
                resource={
                    "resource_id": context.resource_id,
                    "resource_type": context.resource_type,
                    "region": context.region,
                },
                derived={
                    "billing_instance_class": raw.get("metadata", {}).get(
                        "billing_instance_class"
                    ),
                    "actual_instance_class": raw.get("metadata", {}).get(
                        "actual_instance_class"
                    ),
                },
                data_quality={
                    "billing_resource_match": billing_match,
                    "category": raw.get("metadata", {}).get("category"),
                    "blocks_optimization": raw.get("metadata", {}).get(
                        "blocks_optimization"
                    ),
                },
            ),
            observation_period=self._observation_period(context),
            limitations=raw.get("limitations") or [],
            metadata=raw.get("metadata") or {},
            recommendation_eligible=bool(
                raw.get("recommendation_eligible", True)
            ),
        )

    @staticmethod
    def _condition_to_statement(
        condition: Dict[str, Any],
    ) -> EvidenceStatement:
        expected = condition.get("expected")
        actual = condition.get("actual")
        status = condition.get("status")
        if status is None:
            status = "PASS" if condition.get("passed") else "FAIL"

        description = condition.get("description")
        if not description:
            description = (
                f"expected={expected!r}, actual={actual!r}, status={status}"
            )

        return EvidenceStatement(
            name=condition.get("name") or "condition",
            value={
                "expected": expected,
                "actual": actual,
                "status": status,
            },
            description=description,
            source=condition.get("source") or [],
        )

    @staticmethod
    def _observation_period(
        context: AnalysisContext,
    ) -> ObservationPeriod | None:
        cloudwatch = context.cloudwatch()
        start = cloudwatch.get("start") or cloudwatch.get("metric_start")
        end = cloudwatch.get("end") or cloudwatch.get("metric_end")
        if not start and not end:
            value = context.observation_period
            if not value:
                return None
            return ObservationPeriod(
                start=value.get("start"),
                end=value.get("end"),
                duration_seconds=value.get("duration_seconds"),
            )
        return ObservationPeriod(start=start, end=end)