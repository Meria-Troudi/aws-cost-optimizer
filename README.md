# AWS Cost Optimizer

An AWS FinOps platform that scans an account, identifies cost waste, and produces
evidence-backed optimization recommendations. It collects cost and resource data
from AWS, analyses it for waste conditions, and turns each confirmed finding into
a recommendation that carries the evidence it was based on.

The emphasis throughout is on **not overstating what the data supports** — a
recommendation says what was observed and what to check, and reports savings as
unknown when they genuinely are.

## Components

- **`aws_cost_optimizer/`** — the scan engine: collectors, analyzers, and the
  recommendation pipeline. Config-driven and plugin-based — adding a resource
  type means adding a catalog entry plus a collector/analyzer pair, nothing
  else. Currently covers 14 resource types across compute, database, storage,
  networking, load balancing, security, and analytics. Runs standalone or
  behind the API.
- **`backend/`** — FastAPI app wrapping the engine, persisting results to SQLite
  and serving the REST API.
- **`frontend/`** — React + Vite SPA that starts scans and renders the
  dashboard and results. The dashboard also surfaces AWS's own Cost Explorer
  recommendations (Savings Plans, Reserved Instances, EC2 rightsizing)
  alongside this engine's evidence-backed findings, as a second,
  complementary source.
- **`docs/`** — architecture and design-rationale reference material; see
  [Further reading](#further-reading).

## Prerequisites

- **Python 3.12+** (developed against 3.14)
- **Node.js 20+** (developed against 24)
- **AWS credentials** with read access to Cost Explorer (`ce`) and the scanned
  services: `ec2`, `rds`, `eks`, `elbv2`, `dynamodb`, `wafv2`, `quicksight`,
  `s3`, `cloudwatch`, `cloudtrail`, `autoscaling`, `application-autoscaling`,
  `sts`. The platform only ever reads; it never modifies or deletes AWS
  resources.
- **Ollama is entirely optional** — it powers natural-language explanations of
  recommendations. Everything else works without it.

## Quick start

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Start the backend (from the repository root, so the SQLite file resolves):

```bash
python -m uvicorn backend.main:app --reload --port 8000
```

Start the frontend, in a second terminal:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to port 8000
```

Then start a scan from the UI, or run the engine directly:

```bash
python aws_cost_optimizer/main.py --region eu-west-1 --threshold 0
```

`--start-date` / `--end-date` accept `YYYY-MM-DD` and default to a trailing
60-day window.

### Optional: local AI explanations

```bash
docker compose up -d
docker compose exec ollama ollama pull qwen2.5:3b
```

Recommendations then gain a plain-language explanation, generated locally and
cached. If Ollama is not running, the API returns the recommendation with
`ai_status: "unavailable"` rather than failing.

## Tests

```bash
python -m pytest tests/ -q      # 277 tests (274 passing; 3 known-failing, see CLAUDE.md)
python -m black -l 88 --check aws_cost_optimizer backend tests   # formatting check
```

The suite is resource-independent: no AWS credentials, no live Cost Explorer
calls, and no running Ollama instance. It is mostly *contract* tests — each one
pins an invariant that has actually been violated in this codebase at some point.

## Design principles

- **Reconciliation is the sole cost-attribution authority.** Only
  `analysis/reconciliation.py` decides whether a billing amount belongs to a
  specific resource. Analyzers read that verdict and pass it through untouched;
  none of them re-derive it. A shared NAT gateway bill is never silently divided
  across the gateways that share it.

- **Savings are never inferred from confidence.** A finding being high-confidence
  says the *condition* is real, not that the cost is recoverable. Unless there is
  a genuine target cost or the resource can be eliminated outright,
  `estimated_monthly_savings` is `null` with a `savings_basis` explaining why —
  `cost_not_resource_attributed`, `target_cost_required`, and so on.

- **Findings are raw and per-resource; recommendations merge deliberately, not
  by accident.** Every `Finding` row is resource-scoped — three idle NAT
  gateways always persist as three rows, never pre-merged. The recommendation
  engine consumes those raw rows directly (never a report-level aggregated
  view) and merges only findings that share the same recommendation key,
  service, resource type, region, and finding type into one recommendation
  listing every affected resource — so a merge is explicit, traceable logic,
  not a side effect of how the dashboard happens to display things.

- **Recommendation eligibility is gated on declared evidence.** Every catalog
  route declares the evidence a recommendation of that kind must stand on, and
  `recommendations/engine.py` enforces it: a requirement is satisfied only by a
  non-empty value, and a declared concept the gate cannot evaluate is rejected
  rather than waved through. Withheld recommendations are logged with the reason.

## Further reading

- [`CLAUDE.md`](CLAUDE.md) — the deep architectural reference: pipeline
  stages, the `sys.path` bootstrap gotcha, how to add a resource type, and
  the reasoning behind the invariants above.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the narrative *why*
  behind the design: problem definition, cost-optimization principles,
  cost-driven collection, and the evidence model.
- [`docs/THESIS_FIGURES.md`](docs/THESIS_FIGURES.md) — PlantUML source for
  the project's reference diagrams, checked against the current codebase.
- `docs/PROJECT_AUDIT.md` is a superseded historical snapshot from an
  earlier project stage (kept for reference only — see the note at the top
  of the file for what has since changed).
