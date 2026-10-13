# Build context is the repo ROOT, not backend/ — see docker-compose.yml.
# backend.main:app needs `backend/` importable as a package, and
# ensure_project_paths() additionally puts aws_cost_optimizer/ on sys.path,
# so both directories (plus the root requirements.txt) must be in the image.

FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aws_cost_optimizer/ aws_cost_optimizer/
COPY backend/ backend/

EXPOSE 8000

# Run from /app (== repo root) so backend.main:app resolves and the SQLite
# file lands at ./aws_optimizer.db, same as the documented local dev command.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
