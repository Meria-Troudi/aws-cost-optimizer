---
name: verify
description: How to build/launch/drive this repo (FastAPI backend + Vite/React frontend) for runtime verification, and the environment gotchas that break naive attempts.
---

# Verifying this repo at runtime

Three parts: `aws_cost_optimizer/` (scan engine, not usually the surface),
`backend/` (FastAPI + SQLite), `frontend/` (Vite + React). No test suite.
No `.env`/venv marker — packages are on whatever interpreter is already
set up; AWS creds are already configured in this environment (Cost
Explorer calls hit the real account).

## Gotchas that will silently blow up a first attempt

- **`python` is not on PATH in the Bash tool's shell.** Use `py` (the
  Windows launcher) for every Python invocation — `py -m uvicorn ...`,
  `py -c "..."`. Plain `python ...` fails with an App Execution Alias
  stub error, not a normal "command not found".
- **Background jobs started via the `run_in_background` tool param run
  in a different network namespace than the interactive Bash shell.**
  `curl` from a later Bash call cannot reach a port opened that way,
  even though the process itself is fine (confirmed via `Get-CimInstance
  Win32_Process` / the job's own log showing "ready"). Workaround: start
  the server **inline in the same Bash call** as the `curl`, e.g.
  `(py -m uvicorn backend.main:app --port 8010 &) ; sleep 4; curl ...`.
- **Vite's default dev-server bind isn't reachable from a fresh shell
  either**, even started inline. Pass `--host 127.0.0.1` explicitly:
  `npm run dev -- --port <N> --host 127.0.0.1 --strictPort`. Confirmed
  via `netstat`/`Get-NetTCPConnection` that the process really is
  listening; it's a reachability quirk, not a crash.
- Always run from the repo root (`aws_optimizer.db` path and
  `backend.bootstrap.ensure_project_paths()` both assume it).
- Pick a **non-default port** for verification servers (e.g. 8010,
  520x) so you don't collide with any dev server the user already has
  running on 8000/5173.
- **Kill what you start.** `Get-CimInstance Win32_Process -Filter
  "Name='python.exe' OR Name='node.exe'" | Where CommandLine -like
  '*uvicorn*<port>*' -or '*vite*<port>*' | Stop-Process -Force` after
  you're done — these are real background OS processes, not sandboxed.

## Backend surface (real HTTP, not TestClient)

```bash
cd <repo root>
(py -m uvicorn backend.main:app --port 8010 > /tmp/uvicorn.log 2>&1 &)
sleep 4
curl -s http://127.0.0.1:8010/health
curl -s "http://127.0.0.1:8010/api/dashboard/overview?history_months=2"
```

Dashboard-specific things worth checking on any change to
`DashboardService`/`dashboard.py`:
- First `/overview` call is slow (real Cost Explorer round trip, ~7-8s
  for a couple months); an **identical second call should be ~0.2s**
  (in-memory cache in `dashboard_service.py`'s module-level
  `_QUERY_CACHE`) — `force_refresh=true` should be slow again.
- `region=<x>` should narrow `regions` in the response to just that
  region.
- Bad `period_type`, `period_type=month` without `month`, and
  `start_date > end_date` for `period_type=custom` should all 400 with
  a specific message, not 500.

## Frontend surface (real Vite dev server, not a raw file read)

```bash
cd <repo root>/frontend
(npm run dev -- --port 5201 --host 127.0.0.1 --strictPort > /tmp/vite.log 2>&1 &)
sleep 5
curl -s http://127.0.0.1:5201/                                    # index.html, 200
curl -s http://127.0.0.1:5201/src/components/DashboardTab.jsx     # actual transformed module served
```

No Playwright installed and installing it prompts non-interactively
(fails without `--yes`) — full pixel/DOM rendering isn't available
here. Fetching the real transformed module through the dev server and
grepping it is the practical ceiling for the frontend surface in this
environment; it confirms the dev server is actually serving the edited
source (catches stale-import/syntax issues a raw file Read can't), but
is not a substitute for seeing it render.

Curling a path for a file that was **deleted** returns Vite's SPA
fallback (`200` + `index.html`), not `404` — that's normal dev-server
behavior for any path outside the real `import` graph, not a sign the
file still exists. Check the *importer's* served module for the
reference instead.

## npm build/lint (fine as a setup check, not a verification step)

```bash
npm run build     # esbuild-minified CSS; lightningcss breaks on @keyframes
npx oxlint src    # no lint script in package.json; oxlint isn't a devDependency
```
