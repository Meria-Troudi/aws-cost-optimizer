# Thesis Figures — PlantUML Source

Six figures for the thesis, corrected against the actual codebase
(`CLAUDE.md`, `docs/ARCHITECTURE.md`) and drawn with **one consistent
color convention** across all of them:

| Color | Hex | Meaning |
| --- | --- | --- |
| **Dark blue** | `#1F4E79` (border) | Main flow — a process or component, existing or proposed |
| **Light blue** | `#D9EAF7` fill / `#5B9BD5` border | Information / data — inputs, outputs, or things at rest |
| **Green** | `#E2F0D9` fill / `#70AD47` border | The proposed system's validated result — used **only** for this project's own findings/recommendations, never for an existing tool's output |
| **Orange** | `#FFF2CC` fill / `#BF9000` border | A decision point |
| **Red** | `#FADBD8` fill / `#C0392B` border | A limitation — the fail-closed / "insufficient evidence" path |

Two corrections from the original draft, applied throughout:

1. **Green was appearing on existing-tool outputs** (Figure 2's
   "Optimization Opportunities"). Green is reserved for *this project's*
   validated output, so existing-solution figures (1, 2, and the left
   half of 3) now stay dark-blue/light-blue only.
2. **Figure 6 didn't match the code.** File/module names, the evidence
   sections, the reconciliation statuses, and the endpoint/collector
   counts below are pulled directly from the current
   `aws_cost_optimizer/`, `backend/`, and `frontend/` trees, not the
   generic architecture from the earlier draft.

---

# Figure 1 — Existing Cost Optimization Solutions

**Placement:** Chapter I → Existing Solutions
**Caption:** *Figure X. Overview of Existing Cloud Cost Optimization Solutions*

```plantuml
@startuml
title Existing Cloud Cost Optimization Solutions

skinparam backgroundColor white
skinparam shadowing false
skinparam roundcorner 15
skinparam defaultFontName Arial
skinparam defaultTextAlignment center

skinparam package {
    BorderColor #1F4E79
    BackgroundColor #F4F8FC
    FontColor #1F4E79
    FontStyle bold
}

skinparam component {
    BorderColor #1F4E79
    BackgroundColor white
    FontColor #1F2937
}

rectangle "CLOUD COST OPTIMIZATION SOLUTIONS" as ROOT #D9EAF7

package "AWS Native Tools" as AWS {
    component "Cost Explorer\n\nCost visibility\n& expenditure analysis" as CE
    component "Cost Optimization Hub\n\nOptimization recommendations\n& prioritization" as COH
    component "Compute Optimizer\n\nResource utilization\n& rightsizing analysis" as COMP
    component "Trusted Advisor\n\nCost checks\n& recommendations" as TA
}

package "FinOps Platforms" as FINOPS {
    component "CloudZero\n\nCost visibility,\nattribution & optimization" as CZ
    component "IBM Cloudability\n\nFinancial management,\nforecasting & optimization" as CLOUD
}

ROOT --> AWS
ROOT --> FINOPS

legend right
  |Color| Meaning|
  |<#D9EAF7>| Information / data scope|
  |<back:white>| Existing-solution category or tool|
endlegend

@enduml
```

Establishes two categories — **AWS Native Tools** and **FinOps
Platforms** — without ranking either. No project claim is made here, so
no green appears.

---

# Figure 2 — AWS Native Solutions: Capability Flow

**Placement:** Chapter I → AWS Native Cost Optimization Solutions
**Caption:** *Figure X. Complementary Roles of AWS Native Cost Optimization Tools*

```plantuml
@startuml
title AWS Native Cost Optimization — Capability Flow

skinparam backgroundColor white
skinparam shadowing false
skinparam roundcorner 15
skinparam defaultFontName Arial
skinparam defaultTextAlignment center

skinparam rectangle {
    BorderColor #1F4E79
    BackgroundColor white
    FontColor #1F2937
}

skinparam component {
    BorderColor #1F4E79
    BackgroundColor white
    FontColor #1F2937
}

skinparam package {
    BorderColor #1F4E79
    BackgroundColor #F8FBFE
    FontColor #1F4E79
    FontStyle bold
}

rectangle "AWS Cost & Usage Information" as DATA #D9EAF7

component "AWS Cost Explorer" as CE

package "Complementary Optimization Capabilities" {
    component "Cost Optimization Hub\n\nRecommendations\n& prioritization" as HUB
    component "Compute Optimizer\n\nUtilization analysis\n& rightsizing" as OPT
    component "Trusted Advisor\n\nCost checks\n& optimization guidance" as TA
}

rectangle "Optimization Opportunities" as RESULT #D9EAF7

DATA --> CE : Cost visibility\n& analysis

CE --> HUB
CE --> OPT
CE --> TA

HUB --> RESULT
OPT --> RESULT
TA --> RESULT

legend right
  |Color| Meaning|
  |<#D9EAF7>| Information / data (input or output)|
  |<back:white>| Existing-tool process|
endlegend

@enduml
```

Makes the point that the AWS tools are **complementary**, not unrelated
products. `RESULT` stays light blue, not green — it's an existing
tool's output, not this project's.

---

# Figure 3 — Existing Approaches vs. Proposed Approach

The most important conceptual figure in Chapter I.

**Placement:** After the comparison / before the identified gap
**Caption:** *Figure X. From Conventional Cost Optimization to Evidence-Based Investigation*

```plantuml
@startuml
title Existing Approaches vs. Proposed Approach

skinparam backgroundColor white
skinparam shadowing false
skinparam roundcorner 15
skinparam defaultFontName Arial
skinparam defaultTextAlignment center

skinparam package {
    BorderColor #1F4E79
    BackgroundColor #F8FBFE
    FontColor #1F4E79
    FontStyle bold
}

skinparam rectangle {
    BorderColor #1F4E79
    BackgroundColor white
    FontColor #1F2937
}

package "Existing Cost Optimization Approaches" as EXISTING {
    rectangle "Cost / Usage\nInformation" as E1 #D9EAF7
    rectangle "Cost Analysis\n& Optimization Tools" as E2
    rectangle "Optimization\nRecommendations" as E3
    rectangle "Optimization Actions" as E4

    E1 --> E2
    E2 --> E3
    E3 --> E4
}

package "Proposed Evidence-Based Approach" as PROPOSED {
    rectangle "Cost / Usage\nInformation" as P1 #D9EAF7
    rectangle "Cost Analysis\n& Cost Drivers" as P2
    rectangle "Investigation\nPlanning" as P3
    rectangle "Targeted Evidence\nCollection" as P4
    rectangle "Billing / Resource\nReconciliation" as P5
    rectangle "Evidence-Based\nAnalysis" as P6
    rectangle "Validated\nFinding" as P7 #E2F0D9
    rectangle "Technically Justified\nRecommendation" as P8 #E2F0D9

    P1 --> P2
    P2 --> P3
    P3 --> P4
    P4 --> P5
    P5 --> P6
    P6 --> P7
    P7 --> P8
}

legend right
  |Color| Meaning|
  |<#D9EAF7>| Information / data|
  |<back:white>| Main flow step, either approach|
  |<#E2F0D9>| Proposed system: validated output|
endlegend

@enduml
```

**Framing to use in the text:** don't claim existing systems *can't*
reconcile billing or collect evidence. Say instead that this project
places explicit emphasis on an **integrated investigation workflow**,
where cost analysis determines what evidence is collected next — that's
the real, defensible distinction the diagram is making.

---

# Figure 4 — Proposed Solution: Main System Workflow

**Placement:** Chapter II → 3.1 General Description
**Caption:** *Figure X. Overall Workflow of the Proposed AWS Cloud Cost Intelligence and Optimization System*

```plantuml
@startuml
title Proposed AWS Cloud Cost Intelligence and Optimization System

skinparam backgroundColor white
skinparam shadowing false
skinparam roundcorner 18
skinparam defaultFontName Arial
skinparam defaultTextAlignment center

skinparam rectangle {
    BorderColor #1F4E79
    BackgroundColor white
    FontColor #1F2937
}

rectangle "AWS ENVIRONMENT\n\nBilling Data\nAWS Resources\nCloudWatch Metrics" as AWS #D9EAF7

rectangle "1. COST ANALYSIS\n\nServices\nUsage Types\nRegions\nCost Drivers" as CA

rectangle "2. INVESTIGATION PLANNING\n\nWhat to collect?\nWhere?\nWhy?" as IP

rectangle "3. TARGETED COLLECTION\n\nIdentity\nConfiguration\nRelationships\nObservations\nTopology" as TC

rectangle "4. BILLING / RESOURCE\nRECONCILIATION\n\ncurrent / current_mismatch\nhistorical / no_cost\nAttribution Scope" as REC

rectangle "5. EVIDENCE-BASED\nANALYSIS\n\nService-Specific\nAnalyzers" as ANA

rectangle "6. FINDINGS\n\nFinding Type\nSeverity\nConfidence\nEvidence" as FIND #E2F0D9

rectangle "7. RECOMMENDATIONS\n\nEvidence-Gated\nValidation Procedure" as RECO #E2F0D9

AWS --> CA
CA --> IP
IP --> TC
TC --> REC
REC --> ANA
ANA --> FIND
FIND --> RECO

legend right
  |Color| Meaning|
  |<#D9EAF7>| Information / data|
  |<back:white>| Main flow step|
  |<#E2F0D9>| Proposed system: validated output|
endlegend

@enduml
```

Step 3's evidence sections and step 4's reconciliation statuses now name
the actual five evidence categories and four reconciliation outcomes the
engine produces, instead of a generic paraphrase. Use this diagram to
**introduce the whole system**.

---

# Figure 5 — System Workflow: Decision Logic

For 3.3 System Workflow — deliberately different from Figure 4: this one
shows the **decision-making logic**, so it's the one figure where orange
(decision) and red (limitation) actually appear.

**Caption:** *Figure X. Detailed Workflow of the Cost-Driven Investigation Process*

```plantuml
@startuml
title Cost-Driven Investigation Process

skinparam backgroundColor white
skinparam shadowing false
skinparam roundcorner 15
skinparam defaultFontName Arial
skinparam defaultTextAlignment center

skinparam activity {
    BorderColor #1F4E79
    BackgroundColor #F4F8FC
    FontColor #1F2937
    DiamondBackgroundColor #FFF2CC
    DiamondBorderColor #BF9000
    DiamondFontColor #7F6000
}

skinparam arrow {
    Color #1F4E79
}

start

:Retrieve AWS Billing Data;
:Identify Significant\nCost Drivers;
:Determine Cost Condition;
:Plan Required Evidence;
:Collect Only Relevant Evidence;
:Reconcile Billing\nand Resources;
:Analyze Collected Evidence;

if (Is the evidence\nsufficient?) then (Yes)

    #E2F0D9:Create Validated Finding;
    #E2F0D9:Generate Technically\nJustified Recommendation;

else (No)

    #FADBD8:Mark Investigation\nas Inconclusive;
    #FADBD8:Do Not Generate\nUnsupported Finding;

endif

stop

legend right
  |Color| Meaning|
  |<#F4F8FC>| Main investigation flow|
  |<#FFF2CC>| Decision point|
  |<#E2F0D9>| Proposed system: validated output|
  |<#FADBD8>| Limitation: insufficient evidence|
endlegend

@enduml
```

This is the figure that visually establishes the project's **fail-closed
principle**:

```text
Insufficient Evidence
        v
   Inconclusive
        v
No Unsupported Finding
        v
No Unsupported Recommendation
```

---

# Figure 6 — Technical Architecture

**Placement:** Chapter II → 4.1 Overall Architecture
**Caption:** *Figure X. Technical Architecture of the AWS Cloud Cost Intelligence and Optimization System*

Rebuilt against the current codebase rather than a generic layered
sketch: real module names (`planner.py`, `reconciliation.py`,
`engine.py`), real counts (14 collectors, 14 analyzers, 6 API routers /
25 endpoints), and the real dependency direction — **Frontend → Backend
→ Cost Intelligence Engine → AWS**, with SQLite as the shared
persistence both the engine writes to and the backend reads from.

```plantuml
@startuml
title Technical Architecture of the AWS Cloud Cost Intelligence and Optimization System

skinparam backgroundColor white
skinparam shadowing false
skinparam roundcorner 15
skinparam defaultFontName Arial
skinparam defaultTextAlignment center

skinparam package {
    BorderColor #1F4E79
    BackgroundColor #F8FBFE
    FontColor #1F4E79
    FontStyle bold
}

skinparam component {
    BorderColor #1F4E79
    BackgroundColor white
    FontColor #1F2937
}

skinparam database {
    BorderColor #5B9BD5
    BackgroundColor #D9EAF7
    FontColor #1F2937
}

package "Frontend Application  ·  React + Vite" as FE {
    component "DashboardTab  /overview\nScanPage  /analysis\nResultsPage  /results\nAnalysisHistoryPage  /history" as UI_PAGES
    component "src/api/client.js\nsingle REST client" as UI_CLIENT
}

package "Backend Application  ·  FastAPI" as BE {
    component "api/routes/*\n6 routers, 25 endpoints" as BE_ROUTES
    component "ScanService\nruns the engine in a\nbackground thread" as BE_SCAN
    component "DashboardService\nbounded, locked\nCost Explorer cache" as BE_DASH
    component "RecommendationExplanationService\ncache-first, fails safe" as BE_EXPL
    component "database/repositories/*" as BE_REPO
}

database "SQLite\naws_optimizer.db\n\nScanRun . CollectionPlan . CostRecord\nResource/Snapshot . Metric\nFinding . Recommendation" as DB

package "AWS Cost Intelligence Engine  ·  aws_cost_optimizer/" as ENGINE {
    component "Collection Planner\nplanner.py +\nresource_catalog.yaml" as CP
    component "Per-Service Collectors\n(14, one per resource type)\nidentity . configuration .\nrelationships . observations . topology" as TC
    component "Billing / Resource Reconciliation\nreconciliation.py\nsole attribution authority" as REC
    component "Service-Specific Analyzers\n(14, one per resource type)" as ANA
    component "Finding Engine\nraw findings vs.\naggregated findings" as FIND
    component "Recommendation Engine\nresolver -> evidence gate ->\nscoring -> aggregation" as RECO
    component "Optional LLM Explanation\nollama.py + guard.py" as LLM
}

package "AWS Data Sources" as AWS {
    component "AWS Cost Explorer\nBilling & usage data" as CE
    component "AWS Resource APIs\nEC2 . RDS/Aurora . EKS . ELB\nDynamoDB . WAF . S3 . VPC . EBS" as RES
    component "Amazon CloudWatch\nUtilization metrics" as CW
}

' ---- dependency direction: Frontend -> Backend -> Engine -> AWS ----

UI_CLIENT --> BE_ROUTES : REST  /api

BE_ROUTES --> BE_SCAN
BE_ROUTES --> BE_DASH
BE_ROUTES --> BE_EXPL
BE_ROUTES --> BE_REPO

BE_SCAN --> CP : triggers scan pipeline

BE_REPO <--> DB
BE_DASH ..> CE : live Cost Explorer\nqueries (cached)
BE_EXPL --> LLM : on-demand /explain,\ncache-first

CP --> TC
TC --> REC
REC --> ANA
ANA --> FIND
FIND --> RECO

TC --> RES : collect resources
TC --> CW : collect metrics
CP --> CE : cost-driven\nplanning
REC --> CE : reconcile\nbilling

CP --> DB
TC --> DB
FIND --> DB
RECO --> DB

legend right
  |Color| Meaning|
  |<#D9EAF7>| Information / data, external or persisted|
  |<back:white>| Main flow: frontend, backend or engine component|
endlegend

@enduml
```

Green is deliberately absent here — it marks a *validated result*
(Figures 3–5), and an architecture diagram has no results, only
components. The dependency direction is explicit in the arrows
(`UI_CLIENT -> BE_ROUTES -> BE_SCAN -> CP -> ... -> AWS`), which is the
improvement worth keeping over a flatter, unordered box layout:

```text
        FRONTEND (React + Vite)
               |  REST
               v
        BACKEND (FastAPI)
          |            \
          v             v
   COST INTELLIGENCE   SQLite
       ENGINE      <----'  (read/write)
          |
          v
          AWS
```

---

## Recommended final set

| Figure | Report location | Purpose |
| --- | --- | --- |
| **1** | Existing Solutions | Existing ecosystem |
| **2** | AWS Native Solutions | Complementary AWS capabilities |
| **3** | Identified Gap | Existing vs. proposed investigation approach |
| **4** | 3.1 Proposed Solution | Overall system workflow |
| **5** | 3.3 System Workflow | Decision / fail-closed logic |
| **6** | 4.1 Overall Architecture | Actual technical architecture |

Figures 3, 4, 5, and 6 must not look like repetitions:

- **Figure 3** — why the approach is different
- **Figure 4** — what the system does
- **Figure 5** — how the system decides
- **Figure 6** — how the components are technically organized
