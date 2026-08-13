## Project Overview
The AWS Cost Optimizer is a **cost-driven optimization engine** that:
1. Starts from AWS billing data (Cost Explorer)
2. Identifies expensive services/usage types
3. Plans which resource collectors to run
4. Discovers AWS resources and collects metrics
5. Evaluates optimization rules
6. Generates findings and recommendations
---
## Directory Structure
```
fin/
├── .gitignore                          # Git ignore rules
├── aws_cost_optimizer/                 # Main application package
│   ├── main.py                         # Entry point / scan orchestrator
│   ├── aws/                            # AWS client utilities
│   │   └── client.py                   # Boto3 client factory (cached)
│   ├── collectors/                     # Resource & cost collectors
│   │   ├── base.py                     # Abstract base collector
│   │   ├── manager.py                  # Executes collectors & persists results
│   │   ├── registry.py                 # Collector registration & lookup
│   │   ├── persistence.py              # Saves resources/metrics to DB
│   │   ├── metric_collector.py         # CloudWatch metric collection
│   │   ├── cost/                       # Cost collection
│   │   │   ├── collector.py            # CostCollector - pulls Cost Explorer data
│   │   │   └── cost_explorer.py        # Cost Explorer API wrapper
│   │   └── services/                   # AWS service collectors
│   │       ├── nat_gateway.py          # NAT Gateway collector
│   │       ├── rds.py                  # RDS instance collector
│   │       ├── rds_cluster.py          # RDS cluster (Aurora) collector
│   │       ├── rds_snapshots.py        # RDS snapshot collector
│   │       ├── transit_gateway.py      # Transit Gateway collector
│   │       ├── eks.py                  # EKS cluster collector
│   │       ├── elastic_ip.py           # Elastic IP collector
│   │       ├── elb.py                  # Elastic Load Balancer collector
│   │       └── vpc_endpoint.py         # VPC Endpoint collector
│   ├── config/                         # Configuration
│   │   └── settings.py                 # App-wide constants (env vars)
│   ├── planner/                        # Collection planning
│   │   ├── planner.py                  # CollectionPlanner - decides what to collect
│   │   ├── resolver.py                 # Maps billing patterns to collectors
│   │   ├── resource_catalog.py         # Loads resource catalog YAML
│   │   └── resource_catalog.yaml       # Billing pattern → collector mapping
│   └── rules/                          # Rule engine
│       ├── __init__.py                 # Registers rules
│       ├── engine.py                   # RuleEngine - evaluates contexts
│       ├── registry.py                 # Rule registry
│       └── nat_gateway.py              # NAT Gateway optimization rule
├── backend/                            # Database layer
│   ├── aws_optimizer.db                # SQLite database (gitignored)
│   ├── database/                       # Database infrastructure
│   │   ├── __init__.py                 # Package marker
│   │   ├── base.py                     # SQLAlchemy DeclarativeBase
│   │   ├── connection.py               # SQLite engine & session factory
│   │   ├── session.py                  # get_db() dependency helper
│   │   ├── init_db.py                  # Creates tables & migrations
│   │   ├── models/                     # SQLAlchemy ORM models
│   │   │   ├── __init__.py             # Exports all models
│   │   │   ├── scan_run.py             # ScanRun - one analysis execution
│   │   │   ├── cost_record.py          # CostRecord - raw Cost Explorer data
│   │   │   ├── collection_plan.py      # CollectionPlan - planner output
│   │   │   ├── resource.py             # Resource - discovered AWS resources
│   │   │   ├── snapshot.py             # ResourceSnapshot - resource state over time
│   │   │   ├── metric.py               # Metric - CloudWatch metric values
│   │   │   ├── finding.py              # Finding - detected problem
│   │   │   └── recommendation.py       # Recommendation - suggested action
│   │   └── repository/                 # Data access layer
│   │       ├── scan_run_repository.py      # Create/finish scan runs
│   │       ├── resource_repository.py      # Save/query resources, snapshots, metrics
│   │       ├── collection_plan_repository.py # Save collection plans
│   │       ├── finding_repository.py       # Save/query findings
│   │       ├── recommendation_repository.py # Save/query recommendations
│   │       ├── service_cost_repository.py  # Service cost aggregations
│   │       └── usage_type_cost_repository.py # Usage type cost aggregations
│   └── services/                      # Business logic services
│       └── finding_builder.py         # Builds EvaluationContext for rules
├── docs/                              # Documentation
│   ├── architecture.md                # Architecture design document
│   ├── first_target.md                # Database design notes
│   ├── file_guide.md                  # This file - explains every file
│   └── improvements.md                # Improvement suggestions & roadmap
├── inspection/                        # Scan output & reporting
│   └── exporter.py                    # ScanExporter - writes CSV/TXT reports
└── scans/                             # Scan output folders (gitignored)
    └── scan_6/                        # Example scan output
```
---
## Detailed File Explanations
### `aws_cost_optimizer/` - Main Application
#### `aws_cost_optimizer/main.py`
**Purpose:** Entry point and scan orchestrator.
Runs the full pipeline:
1. **SCAN** - Creates a `ScanRun` record with account, dates, region, threshold
2. **COST COLLECTION** - `CostCollector` pulls raw Cost Explorer data into `CostRecord` table
3. **COST ANALYSIS** - Queries `CostRecord` for service/usage type aggregations with ranking
4. **COLLECTION PLAN** - `CollectionPlanner` decides which collectors to run based on cost
5. **RESOURCE COLLECTION** - `CollectorManager` executes collectors, saves resources + metrics
6. **FINDINGS** - `FindingBuilder` creates evaluation contexts, `RuleEngine` generates findings
Also provides CLI arguments: `--region`, `--threshold`, `--start-date`, `--end-date`.
#### `aws_cost_optimizer/aws/client.py`
**Purpose:** AWS client factory.
Provides a cached `get_client(service, region)` function using `functools.lru_cache` to avoid recreating boto3 clients. All AWS API access goes through this.
#### `aws_cost_optimizer/config/settings.py`
**Purpose:** Application-wide constants loaded from environment variables.
- `CE_REGION` - AWS Cost Explorer region (env: `AWS_CE_REGION`, default: `us-east-1`)
- `DEFAULT_START_DATE` - Default scan start date (env: `DEFAULT_START_DATE`, default: `2026-04-01`)
- `DEFAULT_END_DATE` - Default scan end date (env: `DEFAULT_END_DATE`, default: `2026-07-01`)
- `DEFAULT_COST_THRESHOLD` - Default cost threshold (env: `DEFAULT_COST_THRESHOLD`, default: `100.0`)
Scan-specific parameters live in the `ScanRun` model.
---
### `aws_cost_optimizer/collectors/` - Collectors
#### `base.py`
**Purpose:** Abstract base class for all resource collectors.
Defines the `BaseCollector` ABC with:
- `key` - unique identifier for the collector
- `__init__(scan, region)` - stores scan context and region
- `collect()` - abstract method that subclasses implement
#### `manager.py`
**Purpose:** Executes collectors and persists results.
`CollectorManager`:
- Loads all registered collectors via `load_collectors()`
- `execute(db, scan, collector_name, region)`:
  - Looks up collector class from registry
  - Instantiates and calls `collect()`
  - Saves each resource via `CollectorPersistence`
  - Handles errors per-resource with rollback isolation
  - Returns a result dict with status, resource count, metric count
#### `registry.py`
**Purpose:** Collector registration and dynamic loading.
- `register(cls)` - decorator that adds a collector class to the `COLLECTORS` dict by its `key`
- `load_collectors()` - reads `resource_catalog.yaml` and imports each enabled collector module
- `get_collector(name)` - returns the collector class for a given name
#### `persistence.py`
**Purpose:** Saves collected resources to the database.
`CollectorPersistence.save(db, scan, resource)`:
- Creates or updates a `Resource` record
- Saves a `ResourceSnapshot` with configuration and raw API response
- Saves metrics (supports both dict format `{name: value}` and list format)
- Infers the AWS service name from the resource type
#### `metric_collector.py`
**Purpose:** CloudWatch metric collection.
`CloudWatchMetricCollector`:
- `discover_metrics(namespace, dimensions)` - lists available metric names
- `collect(namespace, dimensions, start, end, period)` - dynamically discovers and collects all metrics, returns `{metric_name: average_value}`
- `collect_fixed(namespace, dimensions, metric_specs, start, end, period)` - collects specific metrics with defined statistics, returns list of metric dicts
#### `collectors/cost/collector.py`
**Purpose:** Cost collection from AWS Cost Explorer.
`CostCollector.collect(db, scan)`:
- Discovers regions with costs (or uses scan region)
- Calls `get_cost_usage()` for each region
- Saves each cost group as a `CostRecord` (service, usage_type, region, amount, dates)
- Validates collected total against monthly totals from Cost Explorer
- Returns validation dict with `collected_total`, `monthly_total`, `difference`, `matches`
#### `collectors/cost/cost_explorer.py`
**Purpose:** Cost Explorer API wrapper.
Functions:
- `get_cost_usage(start, end, region)` - gets cost grouped by SERVICE + USAGE_TYPE, with pagination
- `get_regions_with_costs(start, end)` - discovers regions with non-zero costs
- `get_monthly_totals(start, end)` - gets total monthly costs for validation
- `_paginate_cost_and_usage()` - handles NextPageToken pagination
- `_merge_groups_by_period()` - merges paginated results by time period
---
### `aws_cost_optimizer/collectors/services/` - AWS Service Collectors
Each collector extends `BaseCollector`, is decorated with `@register`, and returns a list of resource dicts with:
- `resource_id`, `resource_type`, `region`, `state`, `name`, `tags`
- `attributes` - service-specific configuration
- `metrics` - CloudWatch metric values
- `raw` - raw AWS API response
#### `nat_gateway.py`
**Purpose:** Collects NAT Gateway resources.
- Discovers NAT Gateways via `describe_nat_gateways()`
- Collects route tables, subnets, and instances for dependency analysis
- Collects CloudWatch metrics (BytesOut, BytesIn, ActiveConnections, etc.)
- Analyzes dependencies: which route tables, subnets, and instances use each NAT Gateway
- Skips non-available gateways
#### `rds.py`
**Purpose:** Collects RDS instances.
- Discovers RDS instances via `describe_db_instances()`
- Collects fixed CloudWatch metrics (CPU, connections, memory, IOPS, latency, storage)
- Collects cluster info via `RDSClusterCollector` if part of a cluster
- Collects snapshots via `RDSSnapshotCollector`
- Captures engine, instance class, storage, multi-AZ, backup, monitoring config
#### `rds_cluster.py`
**Purpose:** Collects RDS clusters (Aurora).
Contains two classes:
- `RDSClusterCollector` - helper class that collects details for a specific cluster ID (used by `rds.py`)
- `RDSClusterServiceCollector` - standalone collector that discovers all clusters
#### `rds_snapshots.py`
**Purpose:** Collects RDS snapshots.
`RDSSnapshotCollector`:
- `collect_instance_snapshots(db_identifier)` - gets snapshots for a specific DB instance
- `collect_cluster_snapshots(cluster_id)` - gets snapshots for a specific cluster
- Each snapshot includes identifier, status, storage, engine, creation time, age in days
#### `transit_gateway.py`
**Purpose:** Collects Transit Gateway resources.
- Discovers transit gateways with pagination
- For each gateway, collects attachments
- Captures ASN, route table settings, attachment details
#### `eks.py`
**Purpose:** Collects EKS clusters.
- Discovers cluster names via `list_clusters()`
- For each cluster: describes cluster, lists nodegroups and addons
- Captures version, endpoint, role, nodegroups, addons
#### `elastic_ip.py`
**Purpose:** Collects Elastic IP addresses.
- Discovers EIPs via `describe_addresses()`
- Determines state: `associated` or `idle`
- Captures public IP, allocation ID, association, network interface, instance attachment
#### `elb.py`
**Purpose:** Collects Elastic Load Balancers (ALB/NLB).
- Discovers load balancers via `describe_load_balancers()`
- Collects listeners and target groups
- Collects CloudWatch metrics (RequestCount, etc.)
- Captures type, scheme, DNS name, AZs
#### `vpc_endpoint.py`
**Purpose:** Collects VPC Endpoints.
- Discovers endpoints via `describe_vpc_endpoints()`
- Captures service name, endpoint type, VPC, route tables, subnets, network interfaces, policy
---
### `aws_cost_optimizer/planner/` - Collection Planning
#### `planner.py`
**Purpose:** Decides what to collect based on cost.
`CollectionPlanner.plan(db, scan)`:
- Queries `CostRecord` aggregated by service + usage_type + region
- Filters by cost threshold
- Uses `CatalogResolver` to map billing patterns to collectors
- Assigns priority: high (≥$500), medium (≥$200), low
- Saves `CollectionPlan` records to DB
- Returns sorted list of plan dicts
#### `resolver.py`
**Purpose:** Maps billing patterns to collectors.
`CatalogResolver.resolve(service, usage_type)`:
- Iterates through the resource catalog
- Matches service name and usage type patterns (using `fnmatch`)
- Returns `{resource_type, collector, key}` or `None`
#### `resource_catalog.py`
**Purpose:** Loads the resource catalog.
`ResourceCatalog`:
- Loads `resource_catalog.yaml` at initialization using `yaml.safe_load()`
- `by_key(key)` - get a catalog entry by key
- `all()` - get all catalog entries
#### `resource_catalog.yaml`
**Purpose:** Configuration mapping billing patterns to collectors.
Each entry defines:
- `services` - AWS service names that match
- `usage_patterns` - glob patterns for usage types
- `collector` - collector module name
- `resource_type` - resource type to store
- `metrics` - optional metric specifications
---
### `aws_cost_optimizer/rules/` - Rule Engine
#### `__init__.py`
**Purpose:** Rule registration.
Imports and registers all rules with the global registry. Currently registers `NATGatewayRule`.
#### `engine.py`
**Purpose:** Evaluates rules against contexts.
`RuleEngine.run(db, contexts)`:
- For each `EvaluationContext`, looks up the rule by `resource_type`
- Calls `rule.evaluate(context)` which returns finding dicts
- Saves each finding via `save_finding()`
- Saves associated recommendations via `save_recommendation()`
- Commits and returns created findings
#### `registry.py`
**Purpose:** Rule registry.
`RuleRegistry`:
- `register(rule)` - registers a rule by its `key`
- `get(resource_type)` - gets rule for a resource type
- `get_all()` - returns all rules
- Global `registry` instance
#### `nat_gateway.py`
**Purpose:** NAT Gateway optimization rule.
`NATGatewayRule.evaluate(context)`:
- Checks if cost exceeds threshold
- Aggregates metrics across all NAT Gateway resources
- Determines severity: high (no traffic), medium (>3 gateways), low
- Returns finding dict with evidence (cost, gateway count, bytes, connections)
---
### `backend/` - Database Layer
#### `backend/database/base.py`
**Purpose:** SQLAlchemy base class.
Defines `Base(DeclarativeBase)` that all ORM models inherit from.
#### `backend/database/connection.py`
**Purpose:** Database connection setup.
- Creates SQLite engine at `backend/aws_optimizer.db`
- Creates `SessionLocal` session factory
- Uses `check_same_thread=False` for multi-threaded access
#### `backend/database/session.py`
**Purpose:** Session dependency helper.
`get_db()` - yields a database session and closes it after use (for FastAPI-style dependency injection).
#### `backend/database/init_db.py`
**Purpose:** Database initialization and migrations.
- Imports all models to register them with `Base.metadata`
- Creates all tables via `Base.metadata.create_all()`
- Runs upgrade functions for schema migrations (adds `account_id` to resources, `resource_type` to findings)
#### `backend/database/models/` - ORM Models
##### `scan_run.py`
**Purpose:** Represents one analysis execution.
Stores: account_id, start_date, end_date, region, cost_threshold, tag_filter, status, collector_version, created_at, finished_at. Has relationships to collection_plans, resource_snapshots, metrics, findings.
##### `cost_record.py`
**Purpose:** Raw Cost Explorer data (fact table).
Stores: scan_run_id, start_date, end_date, service, usage_type, operation, region, availability_zone, linked_account, amount, usage_quantity, unit, created_at.
##### `collection_plan.py`
**Purpose:** Planner output - what to collect.
Stores: scan_run_id, service, region, usage_type, resource_type, collector_name, priority, cost_context, status. Has unique index on (scan_run_id, service, region, usage_type).
##### `resource.py`
**Purpose:** Discovered AWS resources.
Stores: scan_run_id, account_id, aws_resource_id, service, resource_type, region, availability_zone, name, state, tags (JSON), attributes (JSON), created_at. Has relationships to snapshots, metrics, findings.
##### `snapshot.py`
**Purpose:** Resource state over time.
Stores: resource_id, scan_run_id, source_api, configuration (JSON), raw_response (JSON), collected_at. Has indexes on (resource_id, scan_run_id) and scan_run_id.
##### `metric.py`
**Purpose:** CloudWatch metric values.
Stores: resource_id, scan_run_id, namespace, metric_name, statistic, period, value, unit, metric_start, metric_end, collected_at, dimensions (JSON), raw_datapoints (JSON).
##### `finding.py`
**Purpose:** Detected problem (not the recommendation).
Stores: scan_run_id, resource_id, resource_type, service, finding_type, title, description, severity, evidence (JSON), status, created_at. Has relationships to scan_run, resource, recommendations.
##### `recommendation.py`
**Purpose:** Suggested action for a finding.
Stores: finding_id, title, description, action, category, estimated_savings, confidence, priority, implementation (JSON), status, created_at.
#### `backend/database/repository/` - Data Access Layer
##### `scan_run_repository.py`
- `create_scan_run()` - creates a new ScanRun with status "running"
- `finish_scan_run()` - updates status and sets finished_at
##### `resource_repository.py`
- `get_or_create_resource()` - finds by aws_resource_id + account_id, updates or creates
- `save_resource_snapshot()` - saves a ResourceSnapshot with JSON serialization
- `save_metric()` - saves a Metric with deduplication (updates existing)
##### `collection_plan_repository.py`
- `save_collection_plan()` - upserts a CollectionPlan by (scan_run_id, service, region, usage_type)
##### `finding_repository.py`
- `save_finding()` - creates a Finding
- `get_findings_by_scan()` - gets findings for a scan
- `get_findings_by_resource()` - gets findings for a resource
##### `recommendation_repository.py`
- `save_recommendation()` - creates a Recommendation
- `get_recommendations_by_finding()` - gets recommendations for a finding
- `get_recommendations_by_scan()` - gets recommendations for a scan (via findings join)
##### `service_cost_repository.py`
- `get_service_costs_with_rank()` - returns ranked service costs with share percentage
##### `usage_type_cost_repository.py`
- `get_usage_types_by_service()` - returns top usage types for a service with percentages
---
### `backend/services/` - Business Logic
#### `finding_builder.py`
**Purpose:** Builds evaluation contexts for the rule engine.
`FindingBuilder.build(db, scan)`:
- Queries all `CollectionPlan` records for the scan
- For each plan, finds matching `Resource` records
- Loads snapshots and metrics for each resource
- Builds `EvaluationContext` objects with cost, resources, evidence
- Returns list of contexts for the `RuleEngine`
`EvaluationContext` class:
- Holds scan_run_id, service, region, usage_type, resource_type, cost, resources, evidence, cost_threshold
---
### `inspection/` - Reporting
#### `exporter.py`
**Purpose:** Exports scan results to CSV and TXT files.
`ScanExporter`:
- Creates `scans/scan_{id}/` directory
- `export_cost()` - writes `cost/service_costs.csv` and `cost/usage_type_costs.csv`
- `export_plan()` - writes `collectors/collection_plan.csv`
- `export_collectors()` - writes `collectors/resources.csv` and `collectors/metrics.csv`
- `export_summary()` - writes `summary.txt` with full human-readable report including scan metrics, findings, recommendations, and metric details
---
### `docs/` - Documentation
#### `architecture.md`
**Purpose:** Architecture design document.
Describes the cost-driven optimization flow: Billing → Cost Analysis → Planner → Registry → Resource Discovery → Resource Analysis → Rule Evaluation → Finding/Recommendation.
#### `first_target.md`
**Purpose:** Database design notes.
Historical document describing the database schema evolution and migration plan.
#### `file_guide.md`
**Purpose:** This file - explains every file in the project.
#### `improvements.md`
**Purpose:** Detailed improvement suggestions and roadmap.
Covers:
- Architecture improvements (package structure, relative imports, config)
- Code quality (type hints, docstrings, logging, exceptions, tests)
- Performance (batch inserts, indexes, connection pooling, parallel collectors)
- Reliability (AWS retry, scan recovery, data validation, backups)
- Extensibility (more rules, more collectors, FastAPI dashboard, frontend)
- Data model improvements (Account model, cost trends, recommendation workflow)
- Security (IAM roles, secret management)
- Monitoring (scan metrics, JSON export)
- Quick wins table with impact/effort ratings
- 4-phase long-term roadmap
---
## Data Flow
```
main.py
  │
  ├─ CostCollector ──→ CostRecord table
  │
  ├─ CollectionPlanner ──→ CollectionPlan table
  │     └─ CatalogResolver ──→ resource_catalog.yaml
  │
  ├─ CollectorManager ──→ Resource + ResourceSnapshot + Metric tables
  │     └─ [service collectors] ──→ AWS APIs + CloudWatch
  │
  ├─ FindingBuilder ──→ EvaluationContext objects
  │
  └─ RuleEngine ──→ Finding + Recommendation tables
        └─ [rules] ──→ evaluate contexts
```
## Pipeline Stages
| Stage | Component | Input | Output |
|-------|-----------|-------|--------|
| 1. SCAN | `create_scan_run()` | CLI args | `ScanRun` record |
| 2. COST COLLECTION | `CostCollector` | AWS Cost Explorer | `CostRecord` rows |
| 3. COST ANALYSIS | `service_cost_repository` | `CostRecord` | Ranked service costs |
| 4. COLLECTION PLAN | `CollectionPlanner` | Cost aggregates | `CollectionPlan` rows |
| 5. RESOURCE COLLECTION | `CollectorManager` | Collection plans | `Resource` + `Metric` rows |
| 6. FINDINGS | `FindingBuilder` + `RuleEngine` | Resources + metrics | `Finding` + `Recommendation` rows |
| 7. EXPORT | `ScanExporter` | All DB data | CSV + TXT reports in `scans/` |
