# First Target
This is the right moment to introduce the database.
Your current CSV output is temporary. Once you add FastAPI + SQLAlchemy + SQLite, the database becomes the **source of truth**.
First, answer your question:
> are the models replaced with tables?
No. They are not replaced exactly.
You currently have two types of models:
### 1. Runtime models (dataclasses)
Example:
```python
models/finding.py
```
Used while the program runs:
```
Analyzer
   |
   v
Finding object
   |
   v
Database insert
```
These can stay.
---
### 2. Database models (SQLAlchemy ORM)
New:
```
backend/
 └── database/
       ├── models.py
```
These represent tables:
```
Finding object
      |
      v
SQLAlchemy Finding table
      |
      v
SQLite
```
You can eventually remove some dataclasses because SQLAlchemy models can replace them, but do not mix the migration yet.
---
# New structure
Add:
```
aws_cost_optimizer/
├── backend/
│
│   ├── main.py                 # FastAPI entry point later
│   │
│   ├── database/
│   │   ├── connection.py       # SQLite connection
│   │   ├── base.py             # SQLAlchemy Base
│   │   ├── models.py           # Database tables
│   │   └── init_db.py          # Create tables
│   │
│   ├── schemas/
│   │   └── ...
│   │
│   └── api/
│       └── ...
│
├── analyzers/
├── billing/
├── engine/
├── aws/
└── main.py
```
---
# Tables you need
Do not create too many tables.
For your project, start with these:
---
## 1. accounts
Why:
Your project must work with multiple AWS accounts.
Table:
```
accounts
```
Columns:
| column     | type     |
| ---------- | -------- |
| id         | integer  |
| account_id | string   |
| name       | string   |
| created_at | datetime |
Example:
```
id:1
account_id:123456789012
name:test-account
```
---
# 2. billing_costs
Replace:
```
monthly_cost.csv
service_usage_cost.csv
billing_usage_type.csv
```
One normalized table.
```
billing_costs
```
Columns:
| column     | type    |
| ---------- | ------- |
| id         | integer |
| account_id | FK      |
| date_start | date    |
| date_end   | date    |
| service    | string  |
| usage_type | string  |
| region     | string  |
| cost       | float   |
Example:
```
Amazon VPC
NatGateway-Hours
eu-west-1
463.25
```
This becomes your planner input.
Instead of:
```python
usage_rows
```
you query:
```sql
SELECT *
FROM billing_costs
ORDER BY cost DESC
```
---
# 3. analysis_tasks
This represents your planner output.
Currently:
```python
AnalyzerTask
```
becomes a table.
```
analysis_tasks
```
Columns:
| column     | type     |
| ---------- | -------- |
| id         | integer  |
| account_id | FK       |
| domain     | string   |
| regions    | JSON     |
| status     | string   |
| created_at | datetime |
Example:
```
domain:
nat_gateway
regions:
[
"eu-west-1",
"us-east-1"
]
```
---
# 4. resources
Replace:
```
models/resource.py
```
This is discovered AWS inventory.
```
resources
```
Columns:
| column        | type    |
| ------------- | ------- |
| id            | integer |
| account_id    | FK      |
| resource_id   | string  |
| service       | string  |
| resource_type | string  |
| region        | string  |
| state         | string  |
| attributes    | JSON    |
Example:
```
resource_id:
nat-012345
service:
EC2
type:
nat_gateway
```
---
# 5. metrics
Replace:
```
models/metric.py
```
```
metrics
```
Columns:
| column      | type     |
| ----------- | -------- |
| id          | integer  |
| resource_id | FK       |
| metric_name | string   |
| statistic   | string   |
| value       | float    |
| timestamp   | datetime |
Example:
```
NatGatewayId
BytesOutToDestination
Sum
0
```
---
# 6. findings
Replace:
```
models/finding.py
```
This is your recommendation output.
```
findings
```
Columns:
| column      | type     |
| ----------- | -------- |
| id          | integer  |
| resource_id | FK       |
| rule        | string   |
| severity    | string   |
| title       | string   |
| description | text     |
| action      | text     |
| confidence  | string   |
| risk        | string   |
| evidence    | JSON     |
| created_at  | datetime |
Example:
```
rule:
IDLE_NAT_GATEWAY
severity:
MEDIUM
action:
Remove unused NAT Gateway
```
---
# Final database design
```
accounts
    |
    |
    +------ billing_costs
    |
    +------ analysis_tasks
    |
    +------ resources
                 |
                 |
                 +------ metrics
                 |
                 +------ findings
```
---
# Implementation steps
## Step 1 — Install packages
```bash
pip install fastapi uvicorn sqlalchemy
```
For SQLite:
Nothing needed.
Python already includes sqlite.
---
# Step 2 — Create database connection
Create:
```
backend/database/connection.py
```
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
DATABASE_URL = "sqlite:///./aws_optimizer.db"
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
```
---
# Step 3 — Base
Create:
```
backend/database/base.py
```
```python
from sqlalchemy.orm import DeclarativeBase
class Base(DeclarativeBase):
    pass
```
---
# Step 4 — SQLAlchemy models
Create:
```
backend/database/models.py
```
Start with:
```python
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.sqlite import JSON
from datetime import datetime
from .base import Base
class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    account_id = Column(String, unique=True)
    name = Column(String)
    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
class BillingCost(Base):
    __tablename__ = "billing_costs"
    id = Column(Integer, primary_key=True)
    account_id = Column(
        Integer,
        ForeignKey("accounts.id")
    )
    service = Column(String)
    usage_type = Column(String)
    region = Column(String)
    cost = Column(Float)
    date_start = Column(String)
    date_end = Column(String)
class Resource(Base):
    __tablename__ = "resources"
    id = Column(Integer, primary_key=True)
    account_id = Column(
        Integer,
        ForeignKey("accounts.id")
    )
    resource_id = Column(String)
    service = Column(String)
    resource_type = Column(String)
    region = Column(String)
    state = Column(String)
    attributes = Column(JSON)
class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    resource_id = Column(
        Integer,
        ForeignKey("resources.id")
    )
    rule = Column(String)
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    action = Column(Text)
    confidence = Column(String)
    risk = Column(String)
    evidence = Column(JSON)
    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
```
---
# Step 5 — Create tables
Create:
```
backend/database/init_db.py
```
```python
from .connection import engine
from .base import Base
from . import models
Base.metadata.create_all(bind=engine)
print("Database created")
```
Run:
```bash
python -m backend.database.init_db
```
You should get:
```
aws_optimizer.db
```
---
# Step 6 — First migration from your current pipeline
Do NOT change everything.
First migration:
```
billing/collector.py
        |
        v
billing_costs table
        |
        v
planner.py
        |
        v
analysis_tasks table
        |
        v
analyzers
        |
        v
findings table
```
Your new flow:
```
main.py
collect AWS
    |
    v
save billing_costs
    |
    v
planner reads database
    |
    v
create analysis_tasks
    |
    v
analyzers
    |
    v
save findings
```
---
I would **not add FastAPI routes yet**. First make the pipeline database-backed. FastAPI should come after you can query:
* `/costs`
* `/tasks`
* `/resources`
* `/findings`
from the database.
For your current architecture, do **not** create tables for every Python model. Some models are temporary runtime objects (`AnalyzerTask`, `MetricProfile`, etc.). The database should store **persistent data**:
* AWS account information
* collected billing data
* discovered resources
* metrics
* analysis execution
* findings/recommendations
Your `models/` folder is not directly replaced 1:1. Some become SQLAlchemy tables, some remain Python dataclasses.
## Database tables (SQLite + SQLAlchemy)
### 1. `aws_accounts`
Stores AWS accounts connected to the optimizer.
| Column     | Type       | Description    |
| ---------- | ---------- | -------------- |
| id         | INTEGER PK | Internal ID    |
| account_id | VARCHAR    | AWS account ID |
| name       | VARCHAR    | Friendly name  |
| region     | VARCHAR    | Default region |
| created_at | DATETIME   | Creation time  |
---
### 2. `billing_periods`
Stores monthly cost summaries.
Replacement for:
`MonthlyCost`
| Column     | Type       | Description   |
| ---------- | ---------- | ------------- |
| id         | INTEGER PK |               |
| account_id | FK         | AWS account   |
| start_date | DATE       | Billing start |
| end_date   | DATE       | Billing end   |
| total_cost | DECIMAL    | Total cost    |
| currency   | VARCHAR    | USD           |
Example:
```
2026-06-01 → 2026-07-01 → 1471.88
```
---
### 3. `service_costs`
Cost grouped by AWS service.
Replacement for:
`billing_service.csv`
| Column       | Type       | Description      |
| ------------ | ---------- | ---------------- |
| id           | INTEGER PK |                  |
| account_id   | FK         |                  |
| period_id    | FK         | Billing period   |
| service_name | VARCHAR    | EC2, RDS, VPC... |
| cost         | DECIMAL    | Service cost     |
Example:
```
Amazon RDS             559.04
Amazon VPC             539.49
EC2 - Other            669.67
```
---
### 4. `usage_costs`
Detailed Cost Explorer usage data.
Replacement for:
`ServiceUsageCost`
| Column       | Type       | Description      |
| ------------ | ---------- | ---------------- |
| id           | INTEGER PK |                  |
| account_id   | FK         |                  |
| period_id    | FK         |                  |
| service_name | VARCHAR    | AWS service      |
| usage_type   | VARCHAR    | NATGateway-Hours |
| region       | VARCHAR    | eu-west-1        |
| cost         | DECIMAL    | Cost             |
Example:
```
EC2 - Other
EU-NatGateway-Hours
eu-west-1
463.25
```
---
### 5. `resources`
Inventory discovered by analyzers.
Replacement for:
`Resource`
| Column        | Type       | Description       |
| ------------- | ---------- | ----------------- |
| id            | INTEGER PK |                   |
| account_id    | FK         |                   |
| resource_id   | VARCHAR    | AWS ID            |
| service       | VARCHAR    | EC2, RDS, NAT     |
| resource_type | VARCHAR    | nat_gateway       |
| region        | VARCHAR    |                   |
| state         | VARCHAR    | available/deleted |
| attributes    | JSON       | Extra AWS data    |
| discovered_at | DATETIME   |                   |
Example:
```
nat-01300ff326d760430
EC2 - Other
nat_gateway
eu-west-1
```
---
### 6. `metrics`
CloudWatch collected metrics.
Replacement for:
`MetricValue`, `MetricProfile`
| Column       | Type       | Description  |
| ------------ | ---------- | ------------ |
| id           | INTEGER PK |              |
| resource_id  | FK         | Resource     |
| metric_name  | VARCHAR    | BytesOut     |
| statistic    | VARCHAR    | Sum/Average  |
| value        | FLOAT      | Metric value |
| collected_at | DATETIME   |              |
Example:
```
nat-123
BytesOutToDestination
Sum
0
```
---
### 7. `analysis_runs`
Tracks executions.
New table.
| Column      | Type       | Description       |
| ----------- | ---------- | ----------------- |
| id          | INTEGER PK |                   |
| account_id  | FK         |                   |
| started_at  | DATETIME   |                   |
| finished_at | DATETIME   |                   |
| status      | VARCHAR    | running/completed |
Example:
```
Run #1
Account xxx
completed
```
---
### 8. `analysis_tasks`
Stores what the planner decided to analyze.
Replacement for:
`AnalyzerTask`
| Column          | Type       | Description        |
| --------------- | ---------- | ------------------ |
| id              | INTEGER PK |                    |
| analysis_run_id | FK         |                    |
| domain          | VARCHAR    | nat_gateway        |
| analyzer_name   | VARCHAR    | NatGatewayAnalyzer |
| regions         | JSON       | Regions list       |
| status          | VARCHAR    | pending/completed  |
Example:
```
domain:
nat_gateway
regions:
[
 eu-west-1,
 us-east-1
]
```
---
### 9. `findings`
Your recommendations output.
Replacement for:
`Finding`
| Column           | Type       | Description      |
| ---------------- | ---------- | ---------------- |
| id               | INTEGER PK |                  |
| analysis_run_id  | FK         |                  |
| resource_id      | FK         |                  |
| rule             | VARCHAR    | IDLE_NAT_GATEWAY |
| severity         | VARCHAR    | HIGH/MEDIUM      |
| title            | VARCHAR    |                  |
| description      | TEXT       |                  |
| action           | TEXT       |                  |
| estimated_saving | DECIMAL    |                  |
| confidence       | VARCHAR    |                  |
| risk             | VARCHAR    |                  |
| evidence         | JSON       |                  |
Example:
```
IDLE_NAT_GATEWAY
Remove unused NAT Gateway
confidence:
MEDIUM
```
---
### 10. `recommendation_rules`
Future table for your rule engine.
Instead of hardcoding everything.
| Column      | Type       | Description |
| ----------- | ---------- | ----------- |
| id          | INTEGER PK |             |
| domain      | VARCHAR    | nat_gateway |
| rule_name   | VARCHAR    | idle_nat    |
| description | TEXT       |             |
| severity    | VARCHAR    |             |
| enabled     | BOOLEAN    |             |
Example:
```
domain:
rds
rule:
idle_database
enabled:
true
```
---
# Final database relationship
```
aws_accounts
      |
      |
billing_periods
      |
      +---- service_costs
      |
      +---- usage_costs
aws_accounts
      |
      |
resources
      |
      |
metrics
aws_accounts
      |
      |
analysis_runs
      |
      |
analysis_tasks
      |
      |
findings
```
## Minimum MVP tables to create now
Do not create all 10 immediately.
Create these first:
1. `aws_accounts`
2. `billing_periods`
3. `service_costs`
4. `usage_costs`
5. `resources`
6. `analysis_runs`
7. `analysis_tasks`
8. `findings`
Then add:
9. `metrics`
10. `recommendation_rules`
This is enough to move from CSV pipeline → FastAPI + SQLite + SQLAlchemy without redesigning later.
# AWS Cost Optimizer - Complete Project Analysis
## 📁 Detailed Project Structure
```
c:\Users\meria\Desktop\ING\Stages\stage2\fin/
├── aws_cost_optimizer/                    # Main application package
│   ├── main.py                           # Entry point - orchestrates entire flow
│   ├── analyzers/                        # Analysis layer
│   │   ├── builder.py                    # InvestigationBuilder - builds investigation objects
│   │   └── reporter.py                   # InvestigationReporter - console output
│   ├── aws/                              # AWS client utilities
│   │   └── client.py                     # AWS client factory (get_client)
│   ├── collectors/                       # Resource collection layer
│   │   ├── base.py                       # BaseCollector abstract class
│   │   ├── registry.py                   # Collector registry & loader
│   │   ├── manager.py                    # CollectorManager - orchestrates collection
│   │   ├── persistence.py                # CollectorPersistence - saves to DB
│   │   ├── metric_collector.py           # CloudWatch metric collector
│   │   ├── cost/                         # Cost collection
│   │   │   ├── collector.py              # CostCollector - collects billing data
│   │   │   └── cost_explorer.py          # Cost Explorer API wrapper
│   │   ├── services/                     # Service-specific collectors
│   │   │   ├── nat_gateway.py            # NAT Gateway collector
│   │   │   ├── rds.py                    # RDS collector
│   │   │   └── ec2.py                    # EC2 collector
│   │   └── network/                      # Network context collectors
│   │       ├── vpc.py                    # VPC context
│   │       ├── subnet.py                 # Subnet context
│   │       ├── routes.py                 # Route tables
│   │       └── eni.py                    # Network interfaces
│   ├── config/
│   │   └── settings.py                   # Configuration (CE_REGION, time periods)
│   ├── planner/                          # Planning & routing layer
│   │   ├── planner.py                    # CollectionPlanner - creates collection plans
│   │   ├── resource_catalog.py           # ResourceCatalog - maps billing to collectors
│   │   └── resource_catalog.json         # Catalog configuration
│   └── output/                           # Output directory
│
├── backend/                              # Database layer
│   ├── database/
│   │   ├── base.py                       # SQLAlchemy Base
│   │   ├── session.py                    # Database session factory
│   │   ├── connection.py                 # Database connection
│   │   ├── init_db.py                    # Database initialization
│   │   ├── models/                       # SQLAlchemy ORM models
│   │   │   ├── __init__.py               # Exports all models
│   │   │   ├── scan_run.py               # ScanRun - tracks scan executions
│   │   │   ├── collection_execution.py   # CollectionExecution - tracks collector runs
│   │   │   ├── billing.py                # BillingDimension - service/usage_type pairs
│   │   │   ├── cost.py                   # CostFact - individual cost records
│   │   │   ├── resource.py               # Resource - AWS resources
│   │   │   ├── snapshot.py               # ResourceSnapshot - resource configurations
│   │   │   ├── metric.py                 # Metric - CloudWatch metrics
│   │   │   ├── investigation.py          # Investigation - analysis results
│   │   │   ├── finding.py                # Finding - optimization findings
│   │   │   └── recommendation.py         # Recommendation - actionable recommendations
│   │   └── repository/                   # Data access layer
│   │       ├── scan_run_repository.py
│   │       ├── task_repository.py
│   │       ├── cost_repository.py
│   │       ├── resource_repository.py
│   │       ├── collection_repository.py
│   │       ├── investigation_repository.py
│   │       └── finding_repository.py
│   └── aws_optimizer.db                  # SQLite database file
│
├── docs/                                 # Documentation
│   ├── architecture.md                   # Complete architecture documentation
│   └── first_target.md                   # First target: EC2-Other analysis
│
├── scripts/                              # Utility scripts
│   ├── 01_list_nat_gateways.py
│   ├── 02_find_nat_routes.py
│   ├── 03_collect_nat_metrics.py
│   ├── 04_analyze_nat_usage.py
│   ├── 05_generate_nat_recommendation.py
│   ├── view_db.py                        # Database viewer
│   ├── test_phase1.py                    # Phase 1 tests
│   └── migrate_*.py                      # Database migration scripts
│
└── archive/                              # Archived/legacy code
    ├── analyzers/
    ├── collectors_ec2/
    ├── collectors_inventory/
    └── engine/
```
---
## 🔄 Detailed Data Flow Analysis
### **Phase 1: Cost Collection** (Billing Layer)
**Entry Point:** `main.py` → `CostCollector.collect()`
**Flow:**
```
AWS Cost Explorer API
    ↓
get_cost_usage(start, end, region)
    ↓
For each region with costs:
    For each service/usage_type group:
        ↓
        get_or_create_billing_dimension(service, usage_type)
            ↓
            Creates/retrieves BillingDimension record
        ↓
        save_cost_fact(scan_run_id, billing_dimension_id, region, month, cost)
            ↓
            Creates CostFact record
    ↓
update_scan_run_summary(total_cost, region_count)
```
**Output:**
- `ScanRun` record (status: collecting)
- `BillingDimension` records (service + usage_type pairs)
- `CostFact` records (individual cost entries by region/month)
**Key Files:**
- `aws_cost_optimizer/collectors/cost/collector.py`
- `aws_cost_optimizer/collectors/cost/cost_explorer.py`
- `backend/database/repository/cost_repository.py`
---
### **Phase 2: Cost Analysis & Planning** (Decision Layer)
**Entry Point:** `main.py` → `CollectionPlanner.plan()`
**Flow:**
```
Query database for top N expensive billing dimensions:
    SELECT bd.id, bd.service, bd.usage_type, cf.region, SUM(cf.cost)
    FROM cost_facts cf
    JOIN billing_dimensions bd ON cf.billing_dimension_id = bd.id
    WHERE cf.scan_run_id = ?
    GROUP BY bd.id, cf.region
    ORDER BY SUM(cf.cost) DESC
    LIMIT top_n
    ↓
For each billing dimension:
    catalog.resolve(service, usage_type)
        ↓
        Matches against resource_catalog.json patterns
        ↓
        Returns: {key, resource, collector, required_context, metrics}
    ↓
    Group by (collector, region) to avoid duplicate runs
    ↓
    Create CollectionExecution records
```
**Output:**
- `CollectionExecution` records (one per collector/region combination)
- Each execution contains:
  - `collector_key`: Which collector to run (e.g., "nat_gateway")
  - `region`: AWS region
  - `billing_dimensions`: List of billing dimensions this collector will address
  - `total_cost`: Sum of costs
  - `investigation`: Catalog metadata
**Key Files:**
- `aws_cost_optimizer/planner/planner.py`
- `aws_cost_optimizer/planner/resource_catalog.py`
- `aws_cost_optimizer/planner/resource_catalog.json`
**Resource Catalog Example:**
```json
{
  "key": "nat_gateway",
  "domain": "networking",
  "service_patterns": ["EC2 - Other", "Amazon Virtual Private Cloud"],
  "usage_patterns": ["NatGateway", "NATGateway"],
  "resource_type": "nat_gateway",
  "collector": "nat_gateway",
  "required_context": ["vpc", "subnet", "route_table", "network_interface"],
  "metrics": [
    {"name": "BytesOutToDestination", "statistic": "Sum"},
    {"name": "BytesInFromSource", "statistic": "Sum"},
    {"name": "ActiveConnectionCount", "statistic": "Average"}
  ]
}
```
---
### **Phase 3: Resource Collection** (Discovery Layer)
**Entry Point:** `main.py` → `CollectorManager.execute()`
**Flow:**
```
For each pending CollectionExecution:
    Get collector class from registry:
        get_collector(collector_key)
            ↓
            Looks up COLLECTORS dict (populated by @register decorator)
    ↓
    Instantiate collector: collector_class(region)
    ↓
    collector.collect()
        ↓
        Example: NatGatewayCollector.collect()
            ↓
            1. ec2.describe_nat_gateways() - discover resources
            2. For each resource:
                - Collect CloudWatch metrics
                - Collect context (VPC, subnet, routes, ENI)
            ↓
            Returns: list of resource dicts
    ↓
    CollectorPersistence.save(db, scan_id, resource, account_id)
        ↓
        1. Create/update Resource record
        2. Create ResourceSnapshot record
        3. Create Metric records
        4. Create CollectionExecution record
    ↓
    Update CollectionExecution status to "completed"
```
**Output:**
- `Resource` records (AWS resources discovered)
- `ResourceSnapshot` records (resource configurations at scan time)
- `Metric` records (CloudWatch metrics)
- `CollectionExecution` records (updated with resource count)
**Key Files:**
- `aws_cost_optimizer/collectors/manager.py`
- `aws_cost_optimizer/collectors/persistence.py`
- `aws_cost_optimizer/collectors/services/nat_gateway.py`
- `backend/database/repository/resource_repository.py`
---
### **Phase 4: Investigation Building** (Analysis Layer)
**Entry Point:** `main.py` → `InvestigationBuilder.build_for_plan()`
**Flow:**
```
For each CollectionExecution plan:
    For each billing_dimension in plan:
        investigation_info = plan.get("investigation")
        ↓
        Query resources by type and region:
            SELECT * FROM resources
            WHERE resource_type = ? AND region = ?
        ↓
        For each resource:
            Get ResourceSnapshot (configuration)
            Get Metrics (CloudWatch data)
        ↓
        Build investigation data structure:
        {
            "scan_run_id": scan_run_id,
            "billing_dimension_id": billing_dimension_id,
            "resource_type": "nat_gateway",
            "service": "EC2 - Other",
            "usage_type": "EU-NatGateway-Hours",
            "region": "eu-west-1",
            "total_cost": 463.0,
            "resource_data": {
                "resources": [resource_ids],
                "snapshots": [snapshots]
            },
            "configuration": {
                "resource_count": 3
            },
            "metrics": {
                "nat-123": {"BytesOutToDestination": 500000, ...},
                "nat-456": {"BytesOutToDestination": 0, ...}
            },
            "relationships": {
                "resource_ids": [resource_ids]
            },
            "status": "pending_review"
        }
        ↓
        save_investigation(db, data)
```
**Output:**
- `Investigation` records (ready for manual review)
- Contains all evidence: resources, metrics, configurations, costs
**Key Files:**
- `aws_cost_optimizer/analyzers/builder.py`
- `backend/database/repository/investigation_repository.py`
---
### **Phase 5: Reporting** (Output Layer)
**Entry Point:** `main.py` → `InvestigationReporter.print_summary()`
**Flow:**
```
Query all investigations for scan_run_id
    ↓
Group by (resource_type, region)
    ↓
For each group:
    Calculate total cost
    Format key metrics
    Print summary table
```
**Output:**
- Console report with:
  - Resource type and region
  - Number of findings
  - Total cost
  - Key metrics (traffic, CPU, connections, etc.)
**Key Files:**
- `aws_cost_optimizer/analyzers/reporter.py`
---
## 🏗️ Architecture Analysis
### **Current Architecture Pattern: Cost-Driven Investigation Engine**
The project follows a **cost-driven optimization engine** pattern (not resource discovery):
```
┌─────────────────────────────────────────────────────────────┐
│  1. BILLING LAYER                                           │
│  "Where is the money going?"                                │
│  Input: AWS Cost Explorer API                               │
│  Output: CostFact, BillingDimension                         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  2. PLANNING LAYER                                          │
│  "What deserves investigation?"                             │
│  Input: Top N expensive billing dimensions                  │
│  Output: CollectionExecution plans                          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  3. RESOURCE COLLECTION LAYER                               │
│  "What resources exist?"                                    │
│  Input: Collector plans                                     │
│  Output: Resource, ResourceSnapshot, Metric                 │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  4. INVESTIGATION LAYER                                     │
│  "Here's the evidence for human review"                     │
│  Input: Resources + Metrics + Costs                         │
│  Output: Investigation (pending_review)                     │
└─────────────────────────────────────────────────────────────┘
```
### **Key Design Principles**
1. **Cost-First Approach**: Start from billing data, not resource discovery
2. **Domain-Driven Collectors**: Each collector owns its discovery logic
3. **Separation of Concerns**:
   - Collectors: Discover resources & collect metrics
   - Planner: Decide what to collect based on cost
   - Analyzers: Build investigations from collected data
   - Reporters: Present findings
4. **Registry Pattern**: Dynamic collector loading based on catalog configuration
5. **Investigation Model**: Raw data for manual review (not automated recommendations yet)
---
## 📊 Database Schema Relationships
```
ScanRun (1) ──→ (N) CostFact
                    ↓
                    (N) BillingDimension (1) ──→ (N) Investigation
ScanRun (1) ──→ (N) CollectionExecution
ScanRun (1) ──→ (N) Investigation
                    ↓
                    Contains:
                    - resource_data (JSON)
                    - metrics (JSON)
                    - configuration (JSON)
Resource (1) ──→ (N) ResourceSnapshot
Resource (1) ──→ (N) Metric
```
---
## 🎯 Current State & Capabilities
### **What Works:**
✅ Cost collection from AWS Cost Explorer
✅ Cost analysis and ranking
✅ Automated planning (which collectors to run)
✅ Resource discovery (NAT Gateway, RDS, EC2, EBS)
✅ CloudWatch metric collection
✅ Context collection (VPC, subnet, routes, ENI)
✅ Investigation building with full evidence
✅ Console reporting
### **What's Missing:**
⚠️ Automated rule evaluation (idle detection, rightsizing)
⚠️ Finding generation (structured optimization opportunities)
⚠️ Recommendation generation (actionable advice)
⚠️ Confidence scoring
⚠️ Estimated savings calculation
### **Current Output:**
- Investigations with raw data for **manual review**
- No automated recommendations yet
- Human must analyze metrics and make decisions
---
## 🔍 Example Flow: NAT Gateway Analysis
```
1. Cost Explorer shows: "EC2 - Other + EU-NatGateway-Hours = $463 in eu-west-1"
2. Planner resolves:
   service="EC2 - Other", usage_type="EU-NatGateway-Hours"
   → catalog matches "NatGateway" pattern
   → collector="nat_gateway", resource_type="nat_gateway"
3. CollectionPlanner creates:
   CollectionExecution(
       collector_key="nat_gateway",
       region="eu-west-1",
       billing_dimensions=[{service, usage_type, cost: 463}],
       total_cost=463
   )
4. CollectorManager executes:
   NatGatewayCollector("eu-west-1").collect()
   → ec2.describe_nat_gateways() → finds 3 NATs
   → For each NAT:
       - Collect CloudWatch metrics (BytesIn, BytesOut, ActiveConnectionCount)
       - Collect context (VPC, subnet, routes, ENI)
   → Returns 3 resource dicts
5. Persistence saves:
   - 3 Resource records
   - 3 ResourceSnapshot records
   - ~9 Metric records (3 metrics × 3 resources)
6. InvestigationBuilder creates:
   Investigation(
       resource_type="nat_gateway",
       region="eu-west-1",
       total_cost=463,
       resource_data={resources: [1,2,3], snapshots: [...]},
       metrics={
           "nat-123": {"BytesOutToDestination": 500000, ...},
           "nat-456": {"BytesOutToDestination": 0, ...},
           "nat-789": {"BytesOutToDestination": 250000, ...}
       },
       status="pending_review"
   )
7. Reporter prints:
   "nat_gateway (eu-west-1) - 1 investigation, total $463.00/mo
    usage=EU-NatGateway-Hours  $   463.00/mo  resources=3  BytesOutToDestination=750000.00  ..."
```
## 📝 Summary
This is a **sophisticated cost-driven AWS optimization platform** that:
1. **Starts from billing data** (not resource discovery)
2. **Intelligently plans** which resources to investigate based on cost
3. **Collects comprehensive data** (resources, metrics, context)
4. **Builds investigations** with full evidence for human review
5. **Reports findings** in a structured format
The architecture is **production-ready** for data collection and investigation building, but **not yet automated** for generating optimization recommendations. The current output requires human analysis to identify idle resources, rightsizing opportunities, etc.
