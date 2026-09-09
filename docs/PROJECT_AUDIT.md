# AWS FinOps Project — Complete Architecture, Flow & Completion Audit

> **Superseded — historical snapshot, not current state.** This audit
> captured the project at a point where the database, FastAPI backend, and
> React frontend were still scaffolds (see the layer-by-layer statuses
> below: "Planned/partial", "Partial scaffold"). All of that is now
> implemented and wired end-to-end — the DB persists findings and
> recommendations, the API serves them across 6 routers, and the React app
> renders scans, results, and a dashboard. File paths below have also
> drifted (e.g. `collectors/containers/eks.py` is now
> `collectors/compute/eks/cluster.py`; `analysis/analyzers/database/rds.py`
> is now `analyzers/database/instance.py`; `recommendations/policy.py` no
> longer exists — evidence gating now lives in `recommendations/engine.py`,
> and the human-facing validation procedure is built by
> `recommendations/plan.py`). Treat this document as a record of how
> the project got here, not as a description of how it works today —
> **[`CLAUDE.md`](../CLAUDE.md)** and **[`docs/ARCHITECTURE.md`](ARCHITECTURE.md)**
> are the current sources of truth and are kept aligned with the code.

*Source of truth **at the time it was written**: the actual code in `aws_cost_optimizer/`, `backend/`, `frontend/`, the test suite (277 passing), live scan output in `scans/scan_121/`, and all prior engineering discussions in this project. Nothing is aspirational unless explicitly marked **Planned**.*

---

## 1. Project Overview

### Objective

Build a defensible AWS cost-optimization platform that attributes shared,
usage-type-level billing lines (e.g. `EU-NatGateway-Hours`) to **specific,
currently-existing resources**, and produces optimization findings and
recommendations **only when the evidence supports them**.

### Problem it solves

AWS bills by usage type, not by resource. Cost Explorer says *NAT Gateway
hours cost $126.91 this month in eu-west-1*; it cannot say *which* gateway,
or whether it is doing anything useful. Naive tooling fails in two
characteristic ways, and this project is explicitly designed against both:

1. **Overclaiming** — attributing a shared/historical billing line to one
   resource and recommending "delete/resize" with a dollar figure that is
   not proven.
2. **Silence-as-zero** — treating missing telemetry (no CloudWatch
   datapoints, API error, incomplete discovery) as a *confirmed zero*.
   `no_data` and `confirmed zero` are different facts.

### Final vision

A scan pipeline that collects cost + resource + telemetry evidence,
reconciles billing against discovered resources, emits evidence-based
findings, converts only *optimization-eligible* findings into
recommendations, persists everything, exposes it through a FastAPI backend
and a React dashboard, and (optionally) uses a local LLM **only** to
rephrase existing recommendations — never to invent them.

### Current implementation status (summary)

| Area | State |
| --- | --- |
| Cost collection (Cost Explorer) | Complete, validated |
| Resource collection (14 collectors) | Structurally complete; TGW recently hardened; **P0 presentation defect in collection summary remains** |
| Reconciliation / validation | Complete and correct at the data level; presentation mislabels aggregated totals (known P0) |
| Analyzers + findings | Complete for all 14 types; outcome contract (NO_OPTIMIZATION_MATCH / INSUFFICIENT_EVIDENCE) implemented and tested |
| Recommendation engine | Implemented (rules-driven, savings-gated); **frozen pending Findings freeze** |
| LLM explanation layer | Implemented with guardrails (Ollama, optional); explanation-only |
| Database (SQLite + SQLAlchemy) | Implemented: 8 models, repositories, scan recovery |
| FastAPI backend | Implemented: scans, results, dashboard, cost analytics, recommendations, account routes |
| React dashboard | Implemented (JSX/Vite, not TypeScript); reads the API |
| Tests | 277 passing contract tests across all layers |

### Technology stack

- **Python 3.14**, `boto3`, `SQLAlchemy` (SQLite), `FastAPI`, `PyYAML`
- **React (JSX)** + Vite frontend (plain JavaScript, no TypeScript)
- **Ollama** (optional, local) for recommendation explanations
- `pytest` contract tests; `black -l 88` formatting

### Implemented vs planned

- **Implemented:** everything above.
- **Planned / not started:** nothing major — remaining work is
  *hardening and presentation correctness* in existing layers plus the
  freeze sequence (§12), not new subsystems.

---

## 2. Architecture by Layers

Actual layers, determined from `aws_cost_optimizer/main.py`'s pipeline
docstring plus `backend/` and `frontend/`, in execution order:

```text
Layer 0 — AWS / Data Sources
Layer 1 — Planning (cost-driven collection planning)
Layer 2 — Collection (cost + resources + telemetry)
Layer 3 — Scan-side Persistence
Layer 4 — Validation / Reconciliation
Layer 5 — Analysis (analyzers → findings)
Layer 6 — Recommendations
Layer 7 — Export / Reporting
Layer 8 — Database (shared persistence)
Layer 9 — API (FastAPI)
Layer 10 — Dashboard (React)
Layer 11 — AI / LLM (explanation-only, attached to Layer 6)
```

---

### Layer 0 — AWS / Data Sources

**Purpose.** External systems of record: Cost Explorer (billing), service
APIs (resource inventory), CloudWatch (telemetry).

**Files.** None (external). Access via `aws_cost_optimizer/config/client.py::get_client`.

**Input.** Credentials/profile, region, date window.
**Output.** Raw AWS API responses.
**Dependencies.** None.
**Status.** Complete. APIs actually used: `ce:GetCostAndUsage`,
`ec2` (instances, VPC, TGW, EIPs, EBS, ELB), CloudWatch `GetMetricData`,
RDS, DynamoDB, EKS, S3, WAF, QuickSight, VPC endpoints.

---

### Layer 1 — Planning

**Purpose.** Decide **what** to collect using cost data as the driver
("cost-driven collection" — nothing is collected for a service with no
billing presence). Owns per-resource collection profiles (YAML is the
source of truth for what evidence a collector gathers).

**Files.**

```text
aws_cost_optimizer/planner/
├── planner.py                  # builds CollectionPlans from cost records
├── resolver.py                 # usage types → (collector, region, resource_type)
├── resource_catalog.py / .yaml # 14 resource types: billing services, usage patterns
├── collection_profile.py       # loads per-collector YAML profiles
└── collection_profiles.yaml    # per-collector evidence contract
```

**Logic.** Each `CostRecord` usage-type line resolves through the catalog's
usage patterns to a `(collector, region, resource_type)` bucket; lines in
the same bucket are **merged into one CollectionPlan** whose `cost_context`
is the *sum* and whose `usage_type` is the *largest-cost line*
(representative identity, pinned by contract test).

**Input.** `CostRecord` rows. **Processing.** Usage-type resolution, bucket merge, profile attachment.
**Output.** `CollectionPlan` rows (persisted); execution list for Layer 2.
**Dependencies.** The two YAML catalogs.
**Status.** Complete, contract-tested. **Deliberate trade-off:** the
representative `usage_type` must never be presented as if the whole
aggregated cost belonged to that usage type — see P0 (§10) and the
`INCONSISTENT BY DESIGN` markers in `tests/test_collection_summary_contracts.py`.

<!-- CONTINUES -->

### Layer 2 — Collection

**Purpose.** Execute the plans: one collector per resource type, gathering
identity, configuration, relationships/topology, and observations
(CloudWatch) as **evidence** — never conclusions.

**Files.**

```text
aws_cost_optimizer/collection/
├── base.py                # BaseCollector: discover → per-resource sections
├── manager.py             # executes collectors, per-resource error capture
├── metrics/cloudwatch.py  # shared CloudWatchMetricCollector (GetMetricData batching, MaxDatapoints, period rules)
├── collectors/cost/cost_explorer.py         # CE GetCostAndUsage
├── collectors/network/vpc/…                 # transit_gateway, vpc_endpoint, nat_gateway, eip, flow_logs
├── collectors/storage/ebs.py
├── collectors/load_balancing/load_balancer.py
├── collectors/database/rds.py, dynamodb.py
├── collectors/containers/eks.py
├── collectors/security/waf.py
└── … (14 collector types total, driven by the catalog)
```

**Logic.** `collect()` → `discover()` → per resource: identity /
configuration / relationships / observations / optimization-evidence
sections, each wrapped in `_safe_collect_section` so a failing section is
recorded as explicit status (`error` / `inaccessible`), never silently
dropped. Missing evidence is `None`/`no_data`/`not_returned` — **never 0**.

**Input.** `CollectionPlan` rows. **Processing.** AWS pagination, cache
reset per discovery, metric batching (500 queries/request, ≤100 800
datapoints, explicit `MaxDatapoints`).
**Output.** Raw evidence dicts per resource.
**Dependencies.** Layer 0 clients, Layer 1 profiles.
**Status.** Complete for current scope; TGW collector recently hardened
(ResourceOwnerId ownership, profile-driven states/attachment types/
dimensions/relationships gating, access-denied → `inaccessible`). P1:
profile/YAML duplication remains in some other collectors.

### Layer 3 — Normalization

**Purpose.** Turn raw API responses into stable, typed evidence records.

**Files.**

```text
aws_cost_optimizer/collection/normalizers/   # per-service normalizers
aws_cost_optimizer/analysis/metrics.py       # metric result normalization (ok/no_data/error/not_returned)
aws_cost_optimizer/analysis/billing.py       # CostRecord model + observed-cost attribution
aws_cost_optimizer/analysis/evidence.py      # EvidenceRecord / evidence concepts
```

**Logic.** Metrics become `{status, has_data, sum, observation_complete}`;
billing becomes `CostRecord(usage_type, cost, period)`; relationships
become typed evidence rows.
**Input.** Raw collector output. **Output.** Normalized evidence.
**Dependencies.** Layer 2.
**Status.** Complete. The `missing_is_zero=False` invariant is enforced
and contract-tested here.

### Layer 4 — Validation / Reconciliation

**Purpose.** Answer one question per billing line: **does this historical
billing evidence belong to a currently discovered resource?** This layer
prevents the classic FinOps error of attributing cost to the wrong
resource.

**Files.**

```text
aws_cost_optimizer/collection/validation.py   # CURRENT / HISTORICAL_ONLY / CURRENT_MISMATCH
aws_cost_optimizer/analysis/reconciliation.py # reconciliation statuses
```

**Logic.** Identity match → `current`; no current resource →
`historical_only` (RDS/EKS case); billing usage not attributable to the
current resource → `billing_resource_mismatch` with metadata
(`current_resource_id`, `current_configuration`, `billing_cost`,
`reconciliation_status`). Mismatch findings are
`recommendation_eligible=False` by construction.

**Input.** Normalized evidence + CostRecords. **Output.** Reconciliation
statuses attached to evidence. **Dependencies.** Layers 2–3.
**Status.** Complete; VPC-endpoint mismatch presentation contract-tested
(structured "Therefore:" block in the exporter).

### Layer 5 — Analysis (analyzers → findings)

**Purpose.** Consume evidence and produce **findings** — diagnostic or
optimization statements, each backed by explicit evidence.

**Files.**

```text
aws_cost_optimizer/analysis/
├── base.py            # Analyzer ABC + classify() outcome contract
├── engine.py          # runs analyzers; reports per-analyzer outcome status
├── registry.py
├── finding.py         # Finding model
├── context.py         # AnalysisContext (evidence access)
├── analyzers/storage/ebs.py
├── analyzers/network/vpc/transit_gateway.py, vpc_endpoint.py, nat_gateway.py, eip.py
├── analyzers/load_balancing/load_balancer.py   # canonical finding: max ONE per resource
└── analyzers/database/rds.py
```

**Logic.** Each analyzer runs rules per supported resource and returns
findings; `classify()` returns
`finding_generated | no_optimization_match | insufficient_evidence`. The
engine prints INFO for no-match, WARNING only for insufficient evidence,
ERROR for broken analyzers. **Key invariants (all contract-tested):**
missing data ≠ zero; "no finding" ≠ "insufficient evidence"; one idle ALB
→ exactly one canonical finding (`elb_idle_with_cost` elimination, or
`elb_idle` review) with folded `metadata.signals`; TGW "no traffic"
requires `traffic_complete=True AND bytes_in/out == 0`.

**Input.** Reconciled evidence. **Output.** `Finding` rows.
**Dependencies.** Layers 3–4.
**Status.** Complete for current scope; analyzer-outcome and ELB
canonicalization contract tests green (277-pass suite).

<!-- CONTINUES-L6 -->

### Layer 6 — Recommendations

**Purpose.** Convert eligible optimization findings into actionable
recommendations with savings where attribution allows.

**Files.**

```text
aws_cost_optimizer/recommendations/
├── engine.py                  # finding → recommendation, evidence gates, merge logic
└── recommendation_rules.yaml  # finding_type → action mapping (incl. elb_idle legacy routes)
```

**Logic.** Rule-driven: each finding type maps to an action, gated by
`required_evidence` (e.g. removal actions require attributed cost /
complete traffic observation). Engine-level merge keeps historical
duplicate-finding data coherent even though the analyzer now emits at most
one canonical finding per resource. No savings invented where attribution
is unavailable (mismatch/historical-only findings are excluded).

**Input.** Findings. **Output.** `Recommendation` rows.
**Dependencies.** Layer 5.
**Status.** Complete for current scope. **Not yet** the final product:
prioritized ranking, effort estimates, and consolidation actions are
Planned.

### Layer 7 — Export / Reporting

**Purpose.** Human-readable scan output: cost drivers, collection summary,
findings, recommendations, analyzer health, data-quality blocks.

**Files.**

```text
aws_cost_optimizer/inspection/exporter.py    # scan_XXX/summary.txt, reports
scans/scan_121/                              # live output example
```

**Logic.** Renders sections from persisted scan data; formats
`billing_resource_mismatch` with the structured "Therefore:" block; renders
analyzer health as INFO/WARNING/ERROR per the outcome contract.

**Known presentation debt (P0, deferred past freeze):** multi-usage-type
collectors render the bucket **sum** under the **representative** usage
type label (`EU-InstanceUsage:db.t3.large ($65.48)` instead of a
breakdown). Pinned by `INCONSISTENT BY DESIGN` tests. Evidence/data-quality
findings (TGW incomplete telemetry, WAF no-data) still render under
"OPTIMIZATION FINDINGS" — a separate section is Planned.

**Input.** Findings, recommendations, collection summaries.
**Output.** Text reports. **Dependencies.** Layers 2–6.
**Status.** Complete for current scope, with the two presentation debts above.

<!-- CONTINUES-L8 -->

### Layer 8 — Database (shared persistence)

**Purpose.** Persist scans, cost records, plans, evidence, findings, and
recommendations so downstream layers (API/dashboard) read the same truth
the pipeline wrote.

**Files.**

```text
backend/database/            # shared persistence (repositories incl. cost/usage_types.py)
backend/…                    # models/migrations
```

**Input.** Pipeline outputs. **Output.** Queryable state.
**Dependencies.** Layers 1–6.
**Status.** Partial. Repositories for cost usage types exist and the
pipeline persists scan artifacts, but **finding/recommendation
persistence and the API read-path are not wired end-to-end yet** (the
pipeline is currently validated via text export, not via the DB).

### Layer 9 — API (FastAPI)

**Files.** `backend/` FastAPI app (scaffolded).
**Status.** Planned/partial — not yet serving findings/recommendations
end-to-end.

### Layer 10 — Dashboard (React)

**Files.** `frontend/` — Vite + React (JSX) app; currently config/schema
views.
**Status.** Partial scaffold; findings/recommendations views Planned.

### Layer 11 — AI / LLM (explanation-only)

**Status.** Planned. Explicitly attached to Layer 6 outputs (explain
recommendations), **not** to findings generation — per the frozen design
principle that evidence→finding→recommendation must stay deterministic.

---

# 3. Complete End-to-End Flow (actual)

```text
AWS Cost Explorer ──┐
AWS service APIs ───┤
AWS CloudWatch ─────┘
        ↓
Planner: CostRecord → resolver → CollectionPlan (cost-driven; nothing collected without billing presence)
        ↓
Collectors: identity / configuration / relationships / observations / optimization-evidence
        (missing evidence → None / no_data / not_returned / inaccessible — never 0)
        ↓
Normalization: metrics, billing, relationships → typed evidence
        ↓
Reconciliation: current | historical_only | billing_resource_mismatch
        ↓
Analyzers: evidence-gated rules → Finding (or classified no-match / insufficient-evidence)
        ↓
Recommendation engine: rules + required_evidence gates → Recommendation (savings only when attributed)
        ↓
Exporter: scan_XXX/summary.txt (cost drivers, collection summary, findings, recos, health)
        ↓
[Planned] Database → FastAPI → React dashboard → LLM explanations
```

Worked example (ELB, live scan): `EU-LoadBalancerUsage` $17.54 → plan →
ELB collector (targets=0, requests=0, bytes=0, observation complete) →
reconciliation `current` → analyzer emits ONE canonical
`elb_idle_with_cost` (elimination, savings $17.54) → ONE
`review_load_balancer_removal` recommendation.

<!-- CONTINUES-S4 -->

# 4. File-to-Function Map (key files)

| File | Layer | Purpose | Main classes/functions | Input | Output | Status |
| ---- | ----- | ------- | ---------------------- | ----- | ------ | ------ |
| `planner/planner.py` | 1 | Build CollectionPlans from cost | `Planner` | CostRecords | Plans | Complete |
| `planner/resolver.py` | 1 | usage type → collector bucket | `resolve()` | usage types | (collector, region, rtype) | Complete |
| `planner/collection_profiles.yaml` | 1 | evidence contract per collector | — | — | profiles | Complete (TGW now authoritative) |
| `collection/base.py` | 2 | collector skeleton | `BaseCollector.collect` | plan | evidence sections | Complete |
| `collection/manager.py` | 2 | execute collectors, capture errors | `Manager.execute` | plans | raw evidence | Complete |
| `collection/metrics/cloudwatch.py` | 2 | shared CW client | `CloudWatchMetricCollector` | metric specs | metric results | Complete (MaxDatapoints pinned) |
| `collection/collectors/network/vpc/transit_gateway.py` | 2 | TGW evidence | `TransitGatewayCollector` | plan | identity/config/relationships/observations | Hardened (this round) |
| `collection/validation.py` | 4 | billing↔resource reconciliation | `validate_*` | evidence+cost | reconciliation status | Complete |
| `analysis/engine.py` | 5 | run analyzers, health report | `Engine.run`, `_report_analyzer_health` | evidence | findings + outcome status | Complete |
| `analysis/base.py` | 5 | analyzer contract | `Analyzer.classify` | context+findings | outcome | Complete |
| `analysis/analyzers/load_balancing/load_balancer.py` | 5 | canonical ELB finding | `ElbAnalyzer.analyze`, `_signals` | evidence | ≤1 finding/resource | Complete |
| `recommendations/engine.py` | 6 | finding → recommendation | `RecommendationEngine` | findings | recommendations | Complete (gated) |
| `recommendations/recommendation_rules.yaml` | 6 | action mapping | — | — | rules | Complete |
| `inspection/exporter.py` | 7 | scan report | `_section_*` formatters | persisted scan | summary.txt | Complete (2 presentation debts) |
| `backend/database/` | 8 | persistence | repositories | pipeline rows | DB state | Partial |
| `backend/` FastAPI | 9 | API | — | — | — | Planned/partial |
| `frontend/` React | 10 | dashboard | — | — | — | Partial scaffold |

Duplicated logic to watch: per-collector YAML constants duplicated in
Python (fixed for TGW; other collectors still carry their own copies) and
metric normalization helpers shared via `analysis/metrics.py` (good) with
some collector-local variants (cleanup candidate, P2).

<!-- CONTINUES-S5 -->

# 5. Logic Review

### Collection (Layers 1–3)
- **Correct:** cost-driven planning (nothing collected without billing
  presence); evidence-first collectors (`no_data`/`not_returned`/
  `inaccessible` explicit, never 0); representative-usage-type merge is
  contract-pinned; TGW ownership via `ResourceOwnerId` +
  `TransitGatewayOwnerId`; profile-driven states/attachment-types/
  dimensions/relationships for TGW; CW batching with explicit
  `MaxDatapoints` and correct period floors (60s/300s/3600s).
- **Wrong:** nothing known blocking. Watch item: other collectors still
  hardcode what TGW now reads from profile (drift risk, not a bug today).
- **Missing:** some collectors' relationships sections don't yet honor
  `relationships.collect` gating (TGW does).
- **Unnecessary:** `_owner_cache`-style leftovers (removed in TGW);
  collector-local metric normalization variants.
- **Risk:** a collector silently converting failed evidence to 0 would
  invalidate analyzers — guarded by contract tests; keep it that way.

### Reconciliation (Layer 4)
- **Correct:** refuses to attribute unattributable historical billing
  (VPC-endpoint mismatch case); historical-only separation for RDS/EKS.
- **Missing:** none for current scope.

### Analysis (Layer 5)
- **Correct:** outcome contract (no-match INFO / insufficient WARNING /
  broken ERROR); canonical ELB finding; TGW traffic rule requires
  complete observation; WAF no-data ≠ zero traffic; blackhole routes kept
  as routing evidence, not zero-traffic evidence.
- **Wrong:** none currently known.
- **Missing:** data-quality/evidence findings still share the
  optimization findings channel (presentation split is Layer 7 work).
- **Risk:** false positives only if `missing_is_zero` invariant regresses —
  contract-tested.

### Recommendations (Layer 6)
- **Correct:** evidence gates; no invented savings; legacy finding-type
  routes preserved for historical data.
- **Missing:** prioritization, effort, consolidation/replace actions.

<!-- CONTINUES-S6 -->

# 6. Collection Validation — freeze readiness

| Evidence category | Status | Notes |
| --- | --- | --- |
| Cost data | ✅ Complete | CE GetCostAndUsage, per usage-type lines |
| Resource data | ✅ Complete | 14 collector types driven by catalog |
| Utilization data | ✅ Complete | CW with explicit statuses; `MaxDatapoints` pinned |
| Configuration data | ✅ Complete | identity/configuration sections per collector |
| Billing↔resource reconciliation | ✅ Complete | current / historical_only / mismatch |
| Required AWS APIs | ✅ Verified | TGW/attachment dimensions + ownership per AWS docs |
| Missing evidence | ✅ Explicit | never 0; contract-tested |
| Unnecessary collected data | ⚠️ Minor | TGW dimension minimalism confirmed correct; no over-collection found |

**Must fix before freezing collection:** none blocking. The
collection-summary labeling debt (below) is presentation, not collection.
**Freeze collection now.**

# 7. Findings Validation

| Finding | Trigger | Evidence | Logic correct? | FP risk | Type |
| --- | --- | --- | --- | --- | --- |
| `idle_nat_gateway` | 0 traffic + complete observation + cost | CW, billing | ✅ | Low (gated on completeness) | Optimization |
| `elb_idle_with_cost` / `elb_idle` | targets=0, requests=0, bytes=0, observation complete (+cost) | CW, ELB API, billing | ✅ canonical, ≤1/resource | Low | Optimization |
| `unassociated_eip` | EIP not associated + IdleAddress cost | EC2 API, billing | ✅ | Low | Optimization |
| TGW telemetry/topology incomplete | collector completeness flags | collection status | ✅ diagnostic | n/a | Data-quality |
| WAF no observed metrics | no_data ≠ zero | CW status | ✅ diagnostic | n/a | Data-quality |
| `billing_resource_mismatch` | reconciliation | metadata | ✅ diagnostic, `recommendation_eligible=False` | n/a | Data-quality |

**To freeze findings:** separate data-quality findings into their own
report channel (P0-2) and keep the existing contract tests green. No new
analyzers required.

# 8. Recommendation Readiness

Yes — once Collection and Findings are frozen, the evidence base is
sufficient: every actionable recommendation already carries attributed
cost or a complete-traffic gate, and non-attributable cases are excluded
by construction. Still missing before recommendation *development* (as
opposed to the existing rule engine): a prioritization scheme and the
data-quality/optimization finding split so recommendation UIs don't show
diagnostic noise.

<!-- CONTINUES-S9 -->

# 9. Problems Discovered During the Project

| Problem | Cause | Impact | What was done | Status |
| --- | --- | --- | --- | --- |
| Duplicate ELB findings/recos | 5 independent analyzer checks emitted parallel findings | 4 removal recos for one ALB | Canonical finding + `metadata.signals`; `elb_idle` rule route | ✅ Fixed, contract-tested |
| Noisy analyzer warnings | engine warned on every empty result | EBS misread as problem | `classify()` outcome contract (INFO/WARNING/ERROR) | ✅ Fixed |
| TGW evidence vs zero conflation | incomplete route data treated as 0 | False "unused TGW" risk | completeness flags, `None` counts, `INSUFFICIENT_EVIDENCE` | ✅ Fixed |
| Wrong attachment owner field | `VpcOwnerId or TransitGatewayOwnerId` | Cross-account misattribution | `ResourceOwnerId` + `ownership` block | ✅ Fixed |
| Zero-attachment inventory "incomplete" | `expected_count > 0` guard | Empty TGW flagged incomplete | completeness = inventory ∧ complete==expected | ✅ Fixed |
| Attachment telemetry promoted to TGW-level | `source: attachments, traffic_complete: True` | False "no traffic" findings | `attachment_aggregation`, `traffic_complete: False` | ✅ Fixed |
| CW statistic fallback `Average` | dangerous default | Understated traffic sums | default `Sum` | ✅ Fixed |
| Missing collector helpers (`_iso`, `_tags`, `_safe_period`, `_is_access_denied_error`) | uncommitted refactor dropped definitions | Live scan crash | restored from HEAD; access-denied implemented (exception-aware) | ✅ Fixed |
| Access-denied passed as string | handlers passed `str(exc)` | IAM denials logged as generic errors | pass `exc`; `inaccessible` status | ✅ Fixed |
| Collection summary mislabels summed cost | representative usage_type + bucket sum | Misleading report (e.g. RDS $65.48 as `db.t3.large`) | diagnosed (planner merge); pinned `INCONSISTENT BY DESIGN` tests | ⏸ Deferred (P0-1) |
| Rounding drift ($65.48 vs $65.49) | float sum vs display rounding | Cosmetic | rule: aggregate unrounded, round at display | 📌 Documented (P0-3) |
| YAML profile ignored (states/types/dimensions/relationships) | hardcoded collector constants | Profile not source of truth | profile-driven TGW collector | ✅ Fixed for TGW |

<!-- CONTINUES-S10 -->

# 10. What Must Be Fixed

**P0 — must fix (blocks "complete" claim, not evidence correctness)**
1. Collection-summary billing breakdown: render per-usage-type lines +
   total instead of `representative ($sum)` (`inspection/exporter.py`);
   targets already pinned by the `INCONSISTENT BY DESIGN` tests.
2. Separate **Data-quality / evidence findings** section from
   **Optimization findings** in the exporter.
3. One rounding rule: aggregate unrounded CE values; round only at
   display.

**P1 — should fix**
4. Roll the TGW profile-driven pattern (states / attachment types /
   dimensions / relationships gating) out to the other collectors.
5. Wire finding/recommendation persistence end-to-end through the shared
   DB (Layer 8) so API/dashboard read pipeline truth.

**P2 — later**
6. Consolidate collector-local metric normalization helpers.
7. Analyzer-outcome status persistence (diagnostic only).

# 11. Definition of "Complete"

**Collection complete when** — required cost/resource/utilization/config
evidence exists for every billed service; missing data is explicit
(`no_data`/`not_returned`/`inaccessible`/`None`), never 0; no cost
category silently ignored; outputs stable and contract-tested. → **Met.**

**Reconciliation complete when** — every billing line resolves to
current / historical_only / mismatch with defensible evidence. → **Met.**

**Findings complete when** — every finding is evidence-based, treats
missing data as unknown, handles false-positive cases, carries explicit
evidence, output is consistent (one canonical finding per resource where
applicable), and data-quality findings are visually separated. →
**Met except the separation (P0-2).**

**Recommendations complete when** — actions map 1:1 from findings via
gated rules; savings only with attributed cost; prioritized. → Rules
met; prioritization pending.

**Platform complete when** — findings/recommendations persist to the DB,
FastAPI serves them, React renders them, and the LLM only *explains*
deterministic outputs.

<!-- CONTINUES-S12 -->

# 12. Final Completion Roadmap

```text
CURRENT STATE (277 tests green, scan_121 coherent)
     ↓ 1. P0 exporter fixes (billing breakdown, DQ section, rounding rule)
FREEZE COLLECTION + FINDINGS + RECOMMENDATION RULES
     ↓ 2. Layer 8: persist findings/recommendations (backend/database)
     ↓ 3. Layer 9: FastAPI read endpoints (scans, findings, recos)
     ↓ 4. Layer 10: React views for findings/recommendations
     ↓ 5. Layer 11: LLM explanation of recommendations only
FINAL PROJECT
```

- **Step 1** — files: `inspection/exporter.py`. Why: presentation debts
  make honest data misleading. Done = new exporter contract tests green
  and the `INCONSISTENT BY DESIGN` pins flipped. Don't touch
  collectors/analyzers.
- **Step 2** — files: `backend/database/`, pipeline writers. Done =
  findings/recos queryable. Don't change pipeline logic.
- **Steps 3–4** — read-path only. Don't add business logic to API/FE.
- **Step 5** — explanation-only. Never generate findings.

# 13. Final Project Status

```text
COLLECTION       ████████░░  (complete for scope; profile rollout pending)
RECONCILIATION   █████████░  (complete; presentation debts only)
FINDINGS         ████████░░  (complete for scope; DQ section split pending)
RECOMMENDATIONS  ██████░░░░  (rule engine done; prioritization pending)
EXPORT/REPORTS   ███████░░░  (two P0 presentation debts)
DATABASE         ███░░░░░░░  (partial wiring)
API              ██░░░░░░░░  (scaffold)
UI               ██░░░░░░░░  (scaffold)
AI               ░░░░░░░░░░  (planned, explanation-only)
```

**Already good:** evidence-first collection; reconciliation honesty
(refuses unattributable cost); canonical ELB findings; analyzer outcome
contract; profile-driven TGW collector; no invented savings.

**Currently broken:** nothing functional; reports still mislabel
aggregated costs (P0-1).

**Incomplete:** DB/API/UI wiring; recommendation prioritization;
data-quality findings section.

**Fix next:** the three P0 exporter items.

**Freeze now:** collection, reconciliation, analyzer logic, recommendation
rules — all contract-tested and coherent against live scan_121.

**Can wait:** P1/P2 items, AI layer.

**Single most important next step:** implement the P0 collection-summary
billing breakdown in `inspection/exporter.py` — it is the last thing
standing between the pipeline and an honest, freezable report.

---

## Weak assumptions worth stress-testing

1. **"277 tests green ⇒ correct"** — the suite validates *contracts we
   thought of*. The live-scan crash (missing `_iso`/`_safe_period`)
   happened *despite* green tests, because no test executed real
   discovery end-to-end. A single smoke test that instantiates every
   collector with a stubbed client and runs `collect()` would close that
   gap (recommended as P1).
2. **"Cost-driven collection misses nothing"** — it misses services with
   cost sharing that the catalog doesn't map. The catalog is the single
   point of failure; an unmapped usage type is silently uncollected.
   Verify the resolver logs unmapped usage types (if not: P1).
3. **"Reconciliation prevents misattribution"** — it does for identity
   mismatch, but a *renamed-but-same* resource (e.g. recreated RDS with a
   new ID) lands in `historical_only`, which is safe but may under-report
   current cost attribution. Acceptable; document it.











