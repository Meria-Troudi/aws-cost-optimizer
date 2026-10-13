"""
Prometheus instrumentation for the API layer.

Wires two things into the FastAPI app (see ``backend/api/main.py``):

1. ``PrometheusMiddleware`` -- records a request counter and a
   latency histogram for every call. The route label uses the matched
   route *template* (e.g. ``/api/scans/{scan_id}``) rather than the
   raw URL, so the number of time series stays bounded no matter how
   many scans or recommendations exist.

2. ``metrics_endpoint`` -- renders every registered collector in the
   Prometheus text exposition format for ``GET /metrics``.

``/metrics`` is registered like ``/health``: unauthenticated and not
exposed through the Ingress. Scraping in Kubernetes is handled
in-cluster by the ServiceMonitor in ``k8s/servicemonitor.yaml``,
which targets the backend Service on port 8000.
"""

from __future__ import annotations

import time

from fastapi import Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.responses import Response as StarletteResponse

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "HTTP requests handled, by method, "
    "matched route and status code.",
    ["method", "route", "status"],
)

# Custom buckets instead of the prometheus_client defaults: the
# ``/api/recommendations/{id}/explain`` endpoint proxies Ollama and
# can legitimately take tens of seconds on a cold model.
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds, "
    "by method and matched route.",
    ["method", "route"],
    buckets=(
        0.01,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        60.0,
    ),
)

_METRICS_PATH = "/metrics"
_UNMATCHED_ROUTE = "unmatched"


def _route_label(request: Request) -> str:
    """
    Best-effort route template for labeling metrics.

    After routing, Starlette stores the matched route in the shared
    ASGI scope; its ``path`` attribute is the template containing
    ``{param}`` placeholders, not the concrete URL. Unmatched
    requests (404s) collapse into a single ``unmatched`` label so a
    scanner hitting random paths cannot explode cardinality.
    """

    route = request.scope.get("route")
    path = getattr(route, "path", None)

    if isinstance(path, str) and path:
        return path

    return _UNMATCHED_ROUTE


class PrometheusMiddleware(BaseHTTPMiddleware):
    """
    Record ``http_requests_total`` and
    ``http_request_duration_seconds`` for every request.

    ``/metrics`` itself is excluded so Prometheus scrapes do not
    pollute the very series they collect. Unhandled exceptions are
    counted as 500s (via ``finally``) and still propagate.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> StarletteResponse:

        if request.url.path == _METRICS_PATH:
            return await call_next(request)

        started = time.perf_counter()
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed = time.perf_counter() - started
            labels = {
                "method": request.method,
                "route": _route_label(request),
            }

            HTTP_REQUESTS_TOTAL.labels(
                status=str(status_code),
                **labels,
            ).inc()

            HTTP_REQUEST_DURATION_SECONDS.labels(
                **labels,
            ).observe(elapsed)


def metrics_endpoint() -> Response:
    """
    Serve every registered metric in the Prometheus text exposition
    format consumed by both Prometheus and Grafana.
    """

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )