Cost Collection
        |
        v
Service Ranking
        |
        v
Usage Type Ranking  
        |
        v
Analyzer Selection
        |
        v
Resource Discovery
        |
        v
Rule Evaluation
        |
        v
Finding / Recommendation


The complete general flow should be designed as a **cost-driven optimization engine**, not a resource discovery engine.

The core idea:

> Start from AWS billing → identify expensive areas → map them to optimization domains → discover possible resources → analyze behavior → generate recommendations.

---

# Complete General Architecture Flow

```text
┌───────────────────────────────┐
│          AWS Account           │
│                               │
│ EC2 RDS S3 EKS Lambda VPC ... │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│        Billing Layer           │
│                               │
│ Cost Explorer API             │
│ CUR (optional later)          │
│                               │
│ Collect:                      │
│ - total cost                  │
│ - service cost                │
│ - usage type cost             │
│ - region cost                 │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│      Cost Normalization        │
│                               │
│ Convert AWS billing data into │
│ internal models               │
│                               │
│ Example:                      │
│                               │
│ Service: EC2 - Other          │
│ Usage: EU-NatGateway-Hours    │
│ Cost: $463                    │
│ Region: eu-west-1             │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│      Cost Analysis Engine      │
│                               │
│ Rank expensive:               │
│                               │
│ Level 1                       │
│ Service                       │
│                               │
│ Level 2                       │
│ Usage Type                    │
│                               │
│ Level 3                       │
│ Region                        │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│      Analysis Planner          │
│                               │
│ Creates analysis jobs         │
│                               │
│ Example:                      │
│                               │
│ Task:                         │
│ Service: EC2 - Other          │
│ Usage: NATGateway-Hours       │
│ Cost: $463                    │
│ Domain: nat_gateway           │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│      Optimization Registry     │
│                               │
│ Maps billing pattern to       │
│ optimization domain            │
│                               │
│ Example:                      │
│                               │
│ NatGateway-Hours              │
│          ↓                    │
│ nat_gateway domain             │
│          ↓                    │
│ NatGatewayAnalyzer             │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│        Resource Discovery      │
│                               │
│ Discover real AWS resources    │
│                               │
│ Example:                      │
│                               │
│ EC2 API                       │
│ describe_nat_gateways()       │
│                               │
│ Result:                       │
│                               │
│ nat-001                       │
│ nat-002                       │
│ nat-003                       │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│       Resource Collector       │
│                               │
│ Collect technical information │
│                               │
│ Example NAT:                  │
│                               │
│ - state                       │
│ - VPC                         │
│ - subnet                      │
│ - routes                      │
│ - CloudWatch metrics          │
│ - traffic                     │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│       Rule Analysis Engine     │
│                               │
│ Apply optimization rules      │
│                               │
│ Example:                      │
│                               │
│ NAT Gateway                   │
│                               │
│ IF traffic = 0                │
│ AND active                    │
│                               │
│ THEN                          │
│ possible idle NAT             │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│        Finding Generator       │
│                               │
│ Creates recommendation object │
│                               │
│ Example:                      │
│                               │
│ Finding: Idle NAT Gateway     │
│ Resource: nat-002             │
│ Confidence: Medium            │
│ Evidence: zero traffic        │
│ Action: Review/delete         │
└───────────────┬───────────────┘
                |
                |
                v

┌───────────────────────────────┐
│       Recommendation API/UI    │
│                               │
│ Dashboard                     │
│ Reports                       │
│ Export CSV                    │
└───────────────────────────────┘
```

---

# Detailed explanation of each layer

## 1. Billing Collection Layer

Purpose:

Answer:

> "Where is the money going?"

It does NOT answer:

> "Which exact resource created this cost?"

Example output:

`service_usage_cost.csv`

| service     | usage_type          | region    | cost |
| ----------- | ------------------- | --------- | ---- |
| EC2 - Other | EU-NatGateway-Hours | eu-west-1 | 463  |
| RDS         | Aurora Storage      | eu-west-1 | 103  |
| EKS         | Cluster Hours       | us-east-1 | 218  |

---

# 2. Cost Analysis Layer

Purpose:

Find what deserves investigation.

Example:

Input:

```
Total cost: $2874
```

Ranking:

```
1. EC2 - Other       $669
2. RDS               $559
3. VPC               $539
4. QuickSight        $331
5. EKS               $322
```

Then:

For EC2 Other:

```
EC2 - Other
 |
 +-- NAT Gateway Hours       $463
 +-- EBS Volume              $20
 +-- Elastic IP              $15
```

---

# 3. Analysis Planner

This is the brain deciding:

> "What analyzers should run?"

Example:

Input:

```
EC2 - Other
EU-NatGateway-Hours
$463
```

Creates:

```json
{
 "service":"EC2 - Other",
 "usage_type":"EU-NatGateway-Hours",
 "domain":"nat_gateway",
 "cost":463
}
```

---

# 4. Registry

The registry is your knowledge map.

Example:

```text
AWS Billing Pattern

        |
        v

Optimization Domain

        |
        v

Analyzer
```

Example:

```
NatGateway-Hours
        |
        v
nat_gateway
        |
        v
NatGatewayAnalyzer


Aurora:StorageIOUsage
        |
        v
rds_storage
        |
        v
RDSAnalyzer
```

---

# 5. Resource Discovery

Now you leave billing.

You ask AWS:

> "Show me resources related to this domain."

Example:

NAT domain:

```python
ec2.describe_nat_gateways()
```

Result:

```
nat-123
nat-456
```

Important:

You are NOT saying:

```
EU-NatGateway-Hours
       |
       nat-123
```

You are saying:

```
EU-NatGateway-Hours
       |
       NAT Gateway domain
       |
       discover NAT gateways
```

---

# 6. Resource Analysis

Now you analyze every discovered resource.

Example:

```
nat-123

State:
available

Traffic:
500 GB/month

Finding:
Used
```

---

```
nat-456

State:
available

Traffic:
0 GB/month

Finding:
Potentially idle
```

---

# 7. Recommendation Generation

The output should contain:

## What was expensive?

```json
{
"billing_context":{
"service":"EC2 - Other",
"usage":"EU-NatGateway-Hours",
"cost":463
}
}
```

## What resource was analyzed?

```json
{
"resource":{
"id":"nat-456",
"type":"nat_gateway"
}
}
```

## Why?

```json
{
"evidence":{
"traffic":0,
"connections":0
}
}
```

## Recommendation

```json
{
"title":"Possible idle NAT Gateway",

"action":
"Review NAT Gateway and delete if unused",

"confidence":"MEDIUM"
}
```

---

# The complete reusable pattern for every AWS service

## NAT Gateway

```
Cost Explorer
 |
NatGateway-Hours
 |
nat_gateway domain
 |
discover NAT gateways
 |
traffic analysis
 |
idle NAT recommendation
```

---

## RDS

```
Cost Explorer
 |
db.t3.large
 |
rds_compute domain
 |
discover DB instances
 |
CPU/connections/storage
 |
rightsizing recommendation
```

---

## EBS

```
Cost Explorer
 |
EBS:VolumeUsage.gp3
 |
ebs_volume domain
 |
discover volumes
 |
check attachment
 |
delete unused volume
```

---

## EKS

```
Cost Explorer
 |
AmazonEKS-Hours
 |
eks_cluster domain
 |
discover clusters
 |
node utilization
 |
optimize cluster
```

---

The final architecture principle:

```
                BILLING
                   |
                   |
          "What costs money?"
                   |
                   v
              DOMAIN
                   |
                   |
          "What type of optimization?"
                   |
                   v
             RESOURCES
                   |
                   |
          "What exists?"
                   |
                   v
              METRICS
                   |
                   |
          "How is it used?"
                   |
                   v
        RECOMMENDATION
```
Your current architecture has one conceptual mistake:

> You separated `inventory` from the analyzer, but then your analyzer has to import inventory anyway. This creates extra files without giving you real independence.

Your idea is correct:

* **Billing layer**: says "NAT Gateway cost exists in eu-west-1 = $463.25"
* **Planner**: decides "run NAT analyzer"
* **NAT Analyzer**:

  * discovers NAT Gateways
  * collects metrics
  * evaluates rules
  * creates findings

The analyzer should own its discovery because **discovery is domain-specific**.

Do not create:

```
inventory/
    nat_gateway.py
aws/
    metric_discovery.py
analyzers/
    nat_gateway.py
```

for every service. It becomes a framework before you even have recommendations.

Use this simpler structure:

```
project/

├── analyzers/
│   ├── base.py
│   └── nat_gateway.py        <-- everything NAT
│
├── planner/
│   ├── registry.py
│   └── planner.py
│
├── models/
│   ├── billing.py
│   ├── resource.py
│   └── finding.py
│
├── aws/
│   ├── client.py
│   ├── cloudwatch.py
│   └── regions.py
│
└── main.py
```

---

## 1. Fix the NAT analyzer

Replace your current `analyzers/nat_gateway.py` with:

```python
from typing import List, Dict

from aws.client import get_client
from aws.cloudwatch import get_metrics
from models.resource import Resource
from models.finding import Finding


class NatGatewayAnalyzer:

    def run(self, billing_context):

        region = billing_context.region

        print(f"    Discovering NAT gateways in {region}")

        resources = self.discover(region)


        if not resources:
            return [
                Finding(
                    resource_id="unknown",
                    rule="NAT_NOT_FOUND",
                    severity="LOW",
                    title="NAT Gateway cost detected but no NAT found",
                    description=(
                        f"{billing_context.usage_type} generated "
                        f"${billing_context.cost:.2f}"
                    ),
                    action="Check deleted resources or billing delay",
                    confidence="LOW",
                    service=billing_context.service,
                    region=region,
                    estimated_saving=0
                )
            ]


        findings=[]


        for nat in resources:

            metrics=self.collect_metrics(nat)


            finding=self.evaluate(
                nat,
                metrics,
                billing_context
            )


            if finding:
                findings.append(finding)


        return findings



    def discover(self, region):

        ec2=get_client(
            "ec2",
            region
        )


        response=ec2.describe_nat_gateways()


        resources=[]


        for nat in response["NatGateways"]:

            resources.append(
                Resource(
                    id=nat["NatGatewayId"],
                    service="EC2 - Other",
                    resource_type="nat_gateway",
                    region=region,
                    state=nat["State"],
                    attributes={
                        "vpc_id":nat["VpcId"],
                        "subnet_id":nat["SubnetId"]
                    }
                )
            )


        return resources



    def collect_metrics(self,nat):

        namespace="AWS/NATGateway"


        metrics=[
            "BytesInFromSource",
            "BytesOutToDestination",
            "ActiveConnectionCount"
        ]


        return get_metrics(
            nat.region,
            namespace,
            metrics,
            {
                "NatGatewayId":nat.id
            },
            days=30
        )



    def evaluate(
        self,
        nat,
        metrics,
        billing
    ):


        traffic=0


        for metric,data in metrics.items():

            traffic += sum(
                data.values()
            )


        if traffic == 0:

            return Finding(
                resource_id=nat.id,
                rule="IDLE_NAT_GATEWAY",
                severity="MEDIUM",
                title="Possible idle NAT Gateway",
                description=(
                    "NAT Gateway has cost but no traffic detected"
                ),
                action=(
                    "Review routes and remove unused NAT Gateway"
                ),
                estimated_saving=billing.cost,
                confidence="MEDIUM",
                service=billing.service,
                region=nat.region,
                evidence={
                    "metrics":metrics,
                    "billing_cost":float(billing.cost)
                }
            )


        return None
```

---

## 2. Fix planner

Your planner is almost correct.

Change only this part:

Before:

```python
AnalyzerTask(
    analyzer=mapping["analyzer"]
)
```

Keep it.

The planner should not know discovery.

Good:

```
Cost Explorer
      |
      v
Planner
      |
      v
NatGatewayAnalyzer
      |
      +--> discover NAT
      |
      +--> collect metrics
      |
      +--> evaluate
```

---

## 3. Fix registry

Keep:

```python
ANALYZER_CATALOG = [

{
"name":"nat_gateway",

"domain":"nat_gateway",

"analyzer":NatGatewayAnalyzer(),

"match":{
"services":[
"EC2 - Other",
"Amazon Virtual Private Cloud"
],

"usage_patterns":[
"NatGateway"
]
}

}

]
```

No changes.

---

## 4. Fix main.py

Currently you probably call:

```python
analyzer.run(
 billing_context,
 regions
)
```

Remove regions.

Change:

```python
findings = task.analyzer.run(
    BillingContext(
        service=task.service,
        usage_type=task.usage_type,
        region=task.region,
        cost=task.cost
    )
)
```

---

## 5. Delete these files

You do not need:

```
inventory/
    nat_gateway.py
```

because the analyzer owns it.

You also do not need:

```
metric_classifier.py
metric_discovery.py
```

yet.

They are premature abstraction.

You currently have **one analyzer**.

Dynamic metric frameworks make sense when you have:

* NAT Gateway
* RDS
* EBS
* Lambda
* ALB
* EKS

and you notice repeated patterns.

Right now:

```
NAT Analyzer
    |
    +-- discover NAT
    |
    +-- collect NAT metrics
    |
    +-- rules
```

is cleaner.

---

Your final flow becomes:

```
Cost Explorer
     |
     |
     v

     |
     |
     v

Planner (decison layer what  analyzer should  be  runing )

"EC2 Other + NatGateway usage"
        |
        |
        v

NatGatewayAnalyzer

        |
        +--> describe_nat_gateways()
        |
        +--> CloudWatch metrics
        |
        +--> rules

        |
        v

Finding

recommendation 
```

