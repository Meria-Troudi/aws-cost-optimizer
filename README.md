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
  recommendation pipeline. Runs standalone or behind the API.
- **`backend/`** — FastAPI app wrapping the engine, persisting results to SQLite
  and serving the REST API.
- **`frontend/`** — React + Vite SPA that starts scans and renders the dashboard
  and results.

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
pip install -r requirements.txt -r requirements-dev.txt
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
make check                       # formatting + tests, as CI runs them
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

- **Findings are raw and per-resource; aggregation is presentation only.** Three
  idle NAT gateways persist as three findings and produce three recommendations.
  The dashboard may summarise them as one row, but the recommendation layer never
  consumes that summary — so a recommendation always points at exactly one
  resource.

- **Recommendation eligibility is gated on declared evidence.** Every catalog
  route declares the evidence a recommendation of that kind must stand on, and
  `recommendations/engine.py` enforces it: a requirement is satisfied only by a
  non-empty value, and a declared concept the gate cannot evaluate is rejected
  rather than waved through. Withheld recommendations are logged with the reason.

## Further reading

[`CLAUDE.md`](CLAUDE.md) is the deep architectural reference — pipeline stages,
the `sys.path` bootstrap gotcha, how to add a resource type, and the reasoning
behind the invariants above.
