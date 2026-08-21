# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

An AWS FinOps cost-optimization platform with three parts:

- **`aws_cost_optimizer/`** — Python scan/analysis engine. Collects AWS cost & resource data, finds waste, produces recommendations.
- **`backend/`** — FastAPI app that wraps the engine, persists results to SQLite, and serves the REST API.
- **`frontend/`** — React + Vite SPA that drives scans and renders dashboards/results.

No dependency manifest exists for Python (no `requirements.txt`/`pyproject.toml`) — packages (`fastapi`, `uvicorn`, `sqlalchemy`, `boto3`, `pydantic`, `httpx`) are expected to already be installed in whatever Python interpreter is used.

`tests/` contains a pytest suite of resource-independent contract tests (attribution/reconciliation invariants, metric-semantics round-tripping, collector/analyzer registry validation, recommendation-engine behavior, AI-explanation contracts) — see Commands below. It is not an integration suite: nothing in it makes real AWS calls or requires a running Ollama instance.

## Commands

### Frontend (`frontend/`)

```
npm install         # install deps
npm run dev          # vite dev server on :5173, proxies /api -> http://127.0.0.1:8000
npm run build         # production build (esbuild-minified CSS; lightningcss breaks on @keyframes)
npm run preview       # serve the production build
```

There is no `lint` or `test` npm script. `.oxlintrc.json` configures oxlint (react/typescript/oxc plugins) but the package isn't installed as a devDependency, so it must be run via `npx oxlint` if needed.

`VITE_API_PORT` (default `8000`) controls the dev/preview proxy target for `/api`.

### Backend (`backend/`)

```
python -m uvicorn backend.main:app --reload --port 8000
```

`backend/main.py` re-exports the FastAPI `app` from `backend/api/main.py`. There's no CLI entry-point script otherwise. `init_db()` runs automatically on import of `backend/api/main.py`, creating/migrating the SQLite file at `./aws_optimizer.db` (path is relative to the process's working directory — run uvicorn from the repo root).

### Standalone scan engine (`aws_cost_optimizer/`)

```
python aws_cost_optimizer/main.py --region us-east-1 --threshold 0 --start-date 2026-06-01 --end-date 2026-08-01
```

Runs the same pipeline the backend uses, outside the API (writes to the same SQLite DB and to `aws_cost_optimizer/output/*.csv`). In practice, scans triggered through the API run via `ScanService` (see below), not this script.

### Tests

```
py -3 -m pytest tests/ -q
```

`tests/conftest.py` puts both the repo root and `aws_cost_optimizer/` on `sys.path` (mirroring `ensure_project_paths()`) so the suite can be run standalone. One pre-existing failure (`test_no_route_points_at_a_finding_nobody_emits`, dead `aurora_*` routes with no Aurora analyzer implemented yet) is expected and unrelated to most work in this repo.

### Local AI (Ollama, for recommendation explanations)

```
docker compose up -d
docker compose exec ollama ollama pull qwen2.5:3b   # one-time, or any small instruct model
```

`docker-compose.yml` runs a single `ollama` service on `localhost:11434` with a named volume for model persistence. `OLLAMA_BASE_URL`/`OLLAMA_MODEL` env vars override the defaults. This is entirely optional — the backend and scan pipeline work fully without it; see "Recommendation explanations" below.

## Architecture

### `sys.path` bootstrap (important gotcha)

`aws_cost_optimizer` was written with **bare top-level imports** (`from collection.registry import ...`, `from config.settings import ...`), which only resolve if `aws_cost_optimizer/` itself is on `sys.path`. `backend/bootstrap.py::ensure_project_paths()` inserts both the repo root and `aws_cost_optimizer/` onto `sys.path`, and is called at the top of `backend/main.py`, `backend/api/main.py`, and `aws_cost_optimizer/main.py` before any other project imports. When adding new entry points, call it first — otherwise the mixed import styles (`aws_cost_optimizer.foo.bar` from backend code vs. bare `foo.bar` inside the engine itself) will fail depending on how the process was launched.

### Scan pipeline (`aws_cost_optimizer/`)

Pipeline stages (see `aws_cost_optimizer/main.py` docstring): scan create → cost collection (Cost Explorer) → cost analysis → collection planning → resource collection (per-service collectors) → billing/resource validation → findings (analyzers + reconciliation) → recommendations → summary export.

- **Collectors and analyzers are config-driven plugins**, keyed by resource type in `aws_cost_optimizer/planner/resource_catalog.yaml` (`domain`/`subdomain`/billing service names/usage patterns/collector key/enable flag; the catalog's own docstring notes `domain`/`subdomain` are organizational metadata for path resolution, not execution gating — that's determined by the planner/billing match). To add a resource type: add a catalog entry, add `collection/collectors/<domain>/<subdomain>/<name>.py` (registers itself via `@collection.registry.register` on import; `subdomain` is optional — its path segment is omitted when the catalog entry has none, e.g. `load_balancing/`), and `analysis/analyzers/<domain>/<subdomain>/<name>.py` (registers via `analysis.registry.register`, and must be added as an explicit import in `analysis/analyzers/__init__.py` — unlike collectors, analyzer registration is not dynamic). `collection/registry.py::load_collectors()` dynamically resolves each catalog entry's `domain`/`subdomain` into a `collection/collectors/...` path (the `"collectors"` segment is hardcoded, only domain/subdomain vary) and imports only the modules the catalog enables; a wrong domain/subdomain mapping fails **silently** (the collector just never registers) unless caught by `tests/test_collector_contracts.py`, which calls `validate_collector_registry()`'s underlying checks on every test run.
- **Findings vs. aggregation are deliberately separate concerns** (see docstrings in `analysis/engine.py` and `analysis/finding_engine.py`): `analysis/engine.py` produces one raw, resource-level `Finding` per affected resource with `aggregation_scope` unset; a `FindingAggregator` later decides whether findings are reported per-resource/region/account/service. A DB `Finding` row is always the raw, resource-level fact — 3 affected NAT gateways persist as 3 rows even if the UI shows 1 aggregated finding. `finding_engine.py::evaluate_and_persist()` returns **both** `raw_findings` and `aggregated_findings` — the recommendation engine must consume `raw_findings` (never the aggregated view), while report/summary output (e.g. `main.py`'s printed scan summary) uses `aggregated_findings`. Feeding aggregated findings into the recommendation engine was a real bug fixed this project's history — don't reintroduce it.
- **Recommendations** (`recommendations/engine.py`) flow one-to-one: eligible raw finding → `resolver.py` (finding → catalog route → definition) → `policy.py` (eligibility gate) → `scoring.py` (priority — financial value first, confidence as tiebreaker; only counts `impact.observed_monthly_cost` when `evidence.billing.attribution_scope == "resource"`, never shared/collection-plan cost) → one `Recommendation`. There is deliberately **no grouping/deduplication** — 3 idle NAT gateways produce 3 recommendations, not 1. `resolver.py::resolve_persistence_scope()` sets the DB `scope` column to the **resource ID** (not the region) for resource-scoped recommendations — this is what keeps the `(scan_run_id, recommendation_key, recommendation_variant, resource_type, scope)` unique constraint from colliding when multiple same-region resources of the same type each get their own recommendation. Each finding's recommendation-building is wrapped in its own try/except so one malformed finding can't abort the batch.
- **Savings are never inferred from confidence alone.** `analysis/financial.py::calculate_savings()` only reports a non-null `estimated_monthly_savings` when either a `target_cost` is supplied, or `full_elimination=True` is passed — the latter derived from `Finding.cost_optimization_type == "elimination"` (a field on `analysis/finding.py`'s `Finding` dataclass, defaulting to `"review"` and only overridden by the few analyzers where a finding genuinely means "this resource can be fully removed": `elb_idle_with_cost`, `elastic_ip_unassociated`, `unattached_ebs_volume`). Everything else (rightsizing/underutilization findings, `attribution_scope != "resource"`) reports `estimated_monthly_savings: null` with an explanatory `savings_basis` — this is intentional, not a bug, and the pattern to follow when adding new cost-optimization analyzers.
- `collection/manager.py::CollectorManager` orchestrates resource/metrics/topology collection across the enabled collectors for a scan. `collection/` also holds cross-cutting infrastructure shared by every collector — `base.py` (the `BaseCollector` lifecycle), `cost/` (Cost Explorer), `metrics/` (CloudWatch), `shared/` (reusable VPC/topology helpers used by RDS/EKS/ELB collectors too, despite the network-flavored naming) — and `validation.py`, the post-collection billing/resource reconciliation step run right after `CollectorManager` in the pipeline. **Reconciliation (`analysis/reconciliation.py`) is the single cost-attribution authority** — it decides `attribution_scope`/`claimable_resource_cost`; no analyzer may re-derive it, they only read `context.billing()` and pass it through untouched.

### Recommendation explanations (`aws_cost_optimizer/recommendations/llm/`, optional local AI)

A `Recommendation` can have an on-demand, locally-generated natural-language explanation layered on top of its deterministic fields — the LLM only explains an already-decided recommendation (title/action/priority/savings), it never decides eligibility, priority, or savings itself.

- `backend/api/routes/recommendations.py`: `GET /api/recommendations/{id}` and `POST /api/recommendations/{id}/explain?force=` (registered in `backend/api/main.py`).
- `backend/api/services/recommendation_explanation_service.py::RecommendationExplanationService.explain()` is **cache-first** — it returns the persisted `ai_explanation` without calling Ollama unless it's missing or `force=True` — and **fails safe** — any provider error (Ollama not running, timeout, bad response) returns `ai_status: "unavailable"` rather than raising; the API and scans work fully with Ollama absent.
- `aws_cost_optimizer/recommendations/explanation.py::build_explanation_payload()` builds a deliberately compact evidence package (recommendation fields + finding evidence/limitations/financial impact — never full topology/raw CloudWatch/full `Evidence`) before it reaches the LLM.
- `aws_cost_optimizer/recommendations/llm/ollama.py::OllamaProvider` calls Ollama's **native** `/api/chat` with a Pydantic-derived JSON `format` schema via `httpx` directly (not the OpenAI-compatible shim, no `openai` package dependency).
- `Recommendation` DB model has 5 nullable `ai_*` columns (`ai_explanation` as JSON-encoded `Text`, `ai_provider`, `ai_model`, `ai_prompt_version`, `ai_generated_at`) — added the normal way (just add to the SQLAlchemy model; see the migration note below).
- Frontend: `UnifiedFindingRecommendationModal.jsx` auto-fetches the explanation the first time a recommendation is opened (respects the cache, no repeat calls) and shows a graceful "unavailable, retry" state when Ollama isn't reachable, via `frontend/src/api/client.js::explainRecommendation()`.

### Backend (`backend/`)

Layered: `api/routes/*` (FastAPI routers) → `api/services/*` (business logic, e.g. `ScanService`) → `database/repositories/*` (SQLAlchemy queries) → `database/models/*` (ORM models). `api/presenters/*` shape ORM/engine objects into API response dicts; `api/schemas/*` are the Pydantic request/response models.

- **Scans run as background threads**, not request-blocking: `POST /api/scans` (`backend/api/routes/scans.py`) starts a `threading.Thread` running `ScanService(db).run(scan)` against its **own** `SessionLocal()` session — the request's DB session must never be reused inside the worker. `ScanService` re-implements the same pipeline as `aws_cost_optimizer/main.py` (cost collection → planning → resource collection → validation → optimization), calling into `aws_cost_optimizer.*` modules directly rather than shelling out to `main.py`.
- **No migration framework, but adding a column is a one-line change.** `backend/database/models_loader.py::init_db()` calls `Base.metadata.create_all()`, then diffs each ORM model's columns against `PRAGMA table_info(<table>)` and generates `ALTER TABLE ... ADD COLUMN` automatically for anything missing (idempotent, best-effort, wrapped in try/except) — the SQLite-safe default is derived from the column's `server_default`/Python default/type. Adding a column to an existing model requires **no further step**; you don't hand-write the `ALTER TABLE` yourself.
- DB is SQLite (`sqlite:///./aws_optimizer.db`), single `engine`/`SessionLocal` in `database/connection.py`, with `PRAGMA foreign_keys=ON` enabled per-connection.
- CORS is hardcoded in `api/main.py` to `localhost:3000`/`localhost:5173`.

### Frontend (`frontend/`)

- `src/api/client.js` is the single fetch wrapper (`API_BASE` from `VITE_API_BASE`, empty by default so requests go through the Vite dev proxy to `/api`). It throws a specific "Cannot reach the backend. Start the API server on port 8000." error on network failure — the backend must be running separately from `npm run dev`. `getRecommendation()`/`explainRecommendation()` call the per-recommendation detail/explain endpoints described above.
- Feature areas are split into hooks (`src/hooks/useDashboard.js`, `useScan.js`, `useScanResults.js`, `useDashboardScan.js`) that own fetch/loading/error state, consumed by top-level page components in `src/components/` (`DashboardTab`, `ScanPage`, `ResultsPage`) and routed by simple pathname matching in `App.jsx` (`/analysis`, `/results`, `/overview`).
- `vite.config.ts` strips the dev-mode inline `@react-refresh`/`@vite/client` script tags (`cspFriendlyDev` plugin) so the app still loads under a strict CSP; HMR is disabled (`hmr: false`) in both dev and preview.
