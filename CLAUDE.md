# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

An AWS FinOps cost-optimization platform with three parts:

- **`aws_cost_optimizer/`** — Python scan/analysis engine. Collects AWS cost & resource data, finds waste, produces recommendations.
- **`backend/`** — FastAPI app that wraps the engine, persists results to SQLite, and serves the REST API.
- **`frontend/`** — React + Vite SPA that drives scans and renders dashboards/results.

No dependency manifest exists for Python (no `requirements.txt`/`pyproject.toml`) — packages (`fastapi`, `uvicorn`, `sqlalchemy`, `boto3`, `pydantic`) are expected to already be installed in whatever Python interpreter is used. There is no automated test suite anywhere in the repo.

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

## Architecture

### `sys.path` bootstrap (important gotcha)

`aws_cost_optimizer` was written with **bare top-level imports** (`from collectors.registry import ...`, `from config.settings import ...`), which only resolve if `aws_cost_optimizer/` itself is on `sys.path`. `backend/bootstrap.py::ensure_project_paths()` inserts both the repo root and `aws_cost_optimizer/` onto `sys.path`, and is called at the top of `backend/main.py`, `backend/api/main.py`, and `aws_cost_optimizer/main.py` before any other project imports. When adding new entry points, call it first — otherwise the mixed import styles (`aws_cost_optimizer.foo.bar` from backend code vs. bare `foo.bar` inside the engine itself) will fail depending on how the process was launched.

### Scan pipeline (`aws_cost_optimizer/`)

Pipeline stages (see `aws_cost_optimizer/main.py` docstring): scan create → cost collection (Cost Explorer) → cost analysis → collection planning → resource collection (per-service collectors) → billing/resource validation → findings (analyzers + reconciliation) → recommendations → summary export.

- **Collectors and analyzers are config-driven plugins**, keyed by resource type in `aws_cost_optimizer/planner/resource_catalog.yaml` (billing service names/usage patterns, collector key, enable flag). To add a resource type: add a catalog entry, add `collectors/services/<name>.py` (registers itself via `@collectors.registry.register` on import), and `analysis/analyzers/<name>.py` (registers via `analysis.registry.register`). `collectors/registry.py::load_collectors()` dynamically imports only the modules the catalog enables.
- **Findings vs. aggregation are deliberately separate concerns** (see docstrings in `analysis/engine.py` and `analysis/finding_engine.py`): `analysis/engine.py` produces one raw, resource-level `Finding` per affected resource with `aggregation_scope` unset; a `FindingAggregator` later decides whether findings are reported per-resource/region/account/service. A DB `Finding` row is always the raw, resource-level fact — 3 affected NAT gateways persist as 3 rows even if the UI shows 1 aggregated finding.
- **Recommendations** (`recommendations/engine.py`) flow from a persisted/reportable finding → eligibility check → catalog route → family/variant → scope → grouping → `Recommendation`.
- `collectors/manager.py::CollectorManager` orchestrates resource/metrics/topology collection across the enabled collectors for a scan.

### Backend (`backend/`)

Layered: `api/routes/*` (FastAPI routers) → `api/services/*` (business logic, e.g. `ScanService`) → `database/repositories/*` (SQLAlchemy queries) → `database/models/*` (ORM models). `api/presenters/*` shape ORM/engine objects into API response dicts; `api/schemas/*` are the Pydantic request/response models.

- **Scans run as background threads**, not request-blocking: `POST /api/scans` (`backend/api/routes/scans.py`) starts a `threading.Thread` running `ScanService(db).run(scan)` against its **own** `SessionLocal()` session — the request's DB session must never be reused inside the worker. `ScanService` re-implements the same pipeline as `aws_cost_optimizer/main.py` (cost collection → planning → resource collection → validation → optimization), calling into `aws_cost_optimizer.*` modules directly rather than shelling out to `main.py`.
- **No migration framework.** `backend/database/models_loader.py::init_db()` calls `Base.metadata.create_all()` and then applies hand-written, idempotent `ALTER TABLE` statements (wrapped in try/except, best-effort) for columns added after a table already existed. When adding a column to an existing model, add a corresponding guarded `ALTER TABLE` here, or existing SQLite databases won't pick it up.
- DB is SQLite (`sqlite:///./aws_optimizer.db`), single `engine`/`SessionLocal` in `database/connection.py`, with `PRAGMA foreign_keys=ON` enabled per-connection.
- CORS is hardcoded in `api/main.py` to `localhost:3000`/`localhost:5173`.

### Frontend (`frontend/`)

- `src/api/client.js` is the single fetch wrapper (`API_BASE` from `VITE_API_BASE`, empty by default so requests go through the Vite dev proxy to `/api`). It throws a specific "Cannot reach the backend. Start the API server on port 8000." error on network failure — the backend must be running separately from `npm run dev`.
- Feature areas are split into hooks (`src/hooks/useDashboard.js`, `useScan.js`, `useScanResults.js`, `useDashboardScan.js`) that own fetch/loading/error state, consumed by top-level page components in `src/components/` (`DashboardTab`, `ScanPage`, `ResultsPage`) and routed by simple pathname matching in `App.jsx` (`/analysis`, `/results`, `/overview`).
- `vite.config.ts` strips the dev-mode inline `@react-refresh`/`@vite/client` script tags (`cspFriendlyDev` plugin) so the app still loads under a strict CSP; HMR is disabled (`hmr: false`) in both dev and preview.
