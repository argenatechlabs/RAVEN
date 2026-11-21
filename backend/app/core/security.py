"""API hardening: per-client rate limiting, optional API key auth and
security response headers.

The scanner engines already throttle requests *towards the target*
(``RateLimitedClient``); this module protects the API itself so a single
client cannot hammer ``POST /api/scans`` or exhaust the queue.

Rate limiting is intentionally in-process: RAVEN ships as a single backend
container, and the budget is small. The store is thread-safe and prunes stale
entries so it cannot grow without bound.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import settings


# ---------------------------------------------------------------------------
# Sliding-window rate limiter
# ---------------------------------------------------------------------------
@dataclass
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: float
    limit: int


class RateLimiter:
    """Fixed-capacity sliding window, one deque of timestamps per key."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = max(1, int(limit))
        self.window = max(1.0, float(window))
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def _prune(self, now: float) -> None:
        if now - self._last_prune < 30.0:
            return
        self._last_prune = now
        cutoff = now - self.window
        for key in [k for k, q in self._hits.items() if not q]:
            self._hits.pop(key, None)
        for queue in self._hits.values():
            while queue and queue[0] < cutoff:
                queue.popleft()

    def allow(self, key: str) -> RateLimitDecision:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            self._prune(now)
            queue = self._hits[key]
            while queue and queue[0] < cutoff:
                queue.popleft()
            if len(queue) >= self.limit:
                retry = max(1.0, queue[0] + self.window - now)
                return RateLimitDecision(False, 0, retry, self.limit)
            queue.append(now)
            remaining = max(0, self.limit - len(queue))
            return RateLimitDecision(True, remaining, 0.0, self.limit)


# Shared instances — created once per process, keyed by scope.
_LIMITERS: Dict[str, RateLimiter] = {}
_LIMITER_LOCK = threading.Lock()


def get_limiter(scope: str, limit: int, window: float) -> RateLimiter:
    with _LIMITER_LOCK:
        limiter = _LIMITERS.get(scope)
        if limiter is None or limiter.limit != limit or limiter.window != window:
            limiter = RateLimiter(limit, window)
            _LIMITERS[scope] = limiter
        return limiter


def client_key(request: Request) -> str:
    """Best-effort client identity.

    ``X-Forwarded-For`` is only honoured when ``trust_proxy`` is enabled, so a
    client cannot spoof its identity behind the compose network.
    """
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if settings.trust_proxy and request.headers.get("x-real-ip"):
        return request.headers["x-real-ip"].strip()
    return request.client.host if request.client else "unknown"


def reset_limiters() -> None:
    """Test helper: clear every limiter state."""
    with _LIMITER_LOCK:
        _LIMITERS.clear()


def _check(
    request: Request, scope: str, limit: int, window: float
) -> Tuple[Optional[dict], Optional[Response]]:
    """Return ``(headers, error_response)`` — exactly one of them is set.

    Kept free of exceptions so it can be used from middleware (where raising
    ``HTTPException`` would escape Starlette's exception handling and surface as
    a 500) as well as from route dependencies.
    """
    if not settings.api_rate_limit:
        return None, None
    limiter = get_limiter(scope, limit, window)
    decision = limiter.allow(f"{scope}:{client_key(request)}")
    if decision.allowed:
        return {
            "X-RateLimit-Limit": str(decision.limit),
            "X-RateLimit-Remaining": str(decision.remaining),
        }, None
    retry = str(int(decision.retry_after))
    body = {
        "detail": f"Cok fazla istek: {scope} limiti asildi. "
                  f"{retry} sn sonra tekrar deneyin."
    }
    headers = {
        "Retry-After": retry,
        "X-RateLimit-Limit": str(decision.limit),
    }
    return None, Response(
        content=json.dumps(body),
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        media_type="application/json",
        headers=headers,
    )


def _raise_from_response(response: Optional[Response]) -> None:
    if response is None:
        return
    import json as _json

    try:
        detail = _json.loads(response.body.decode("utf-8")).get("detail", "Asim")
    except Exception:  # pragma: no cover - defensive
        detail = "Asim"
    headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() in ("retry-after", "x-ratelimit-limit")
    }
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail, headers=headers
    )


def scan_write_limit(request: Request) -> None:
    """Stricter budget for scan creation (the expensive operation)."""
    _, response = _check(request, "scan-write", settings.scan_rate_limit_rpm, 60.0)
    _raise_from_response(response)


def api_write_limit(request: Request) -> None:
    """Budget for other mutating calls (settings, report rendering)."""
    _, response = _check(request, "api-write", settings.api_rate_limit_rpm // 2, 60.0)
    _raise_from_response(response)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global per-client cap for ``/api/*`` (health and websockets excluded)."""

    def __init__(self, app, skip_paths: tuple = ("/api/health",)) -> None:
        super().__init__(app)
        self.skip_paths = set(skip_paths)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/ws/") or path in self.skip_paths or not path.startswith("/api/"):
            return await call_next(request)
        headers, rejection = _check(request, "api", settings.api_rate_limit_rpm, 60.0)
        if rejection is not None:
            return rejection
        response = await call_next(request)
        if headers:
            for name, value in headers.items():
                response.headers.setdefault(name, value)
        return response


def rate_limited(limit: int, window: float, scope: str):
    """FastAPI dependency factory.

    Usage::

        @router.post("/api/scans", dependencies=[Depends(rate_limited(10, 60, "scan"))])
    """
    limiter = get_limiter(scope, limit, window)

    def dependency(request: Request) -> None:
        if not settings.api_rate_limit:
            return
        decision = limiter.allow(f"{scope}:{client_key(request)}")
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Cok fazla istek: {scope} limiti asildi. "
                       f"{int(decision.retry_after)} sn sonra tekrar deneyin.",
                headers={"Retry-After": str(int(decision.retry_after))},
            )

    return dependency


# ---------------------------------------------------------------------------
# Optional API key authentication
# ---------------------------------------------------------------------------
def _extract_key(request: Request) -> str:
    header = request.headers.get("x-api-key", "")
    if header:
        return header.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def require_api_key(request: Request) -> None:
    """Reject unauthenticated calls when ``settings.api_key`` is configured."""
    if not settings.api_key:
        return
    provided = _extract_key(request)
    if not provided or not _constant_time_equal(provided, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gecersiz veya eksik API anahtari",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _constant_time_equal(left: str, right: str) -> bool:
    """Avoid leaking the key through timing side channels."""
    if len(left) != len(right):
        return False
    result = 0
    for a, b in zip(left, right):
        result |= ord(a) ^ ord(b)
    return result == 0


# ---------------------------------------------------------------------------
# Security response headers
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add baseline hardening headers to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # HSTS is only meaningful on HTTPS terminators; the compose stack is
        # plain HTTP behind the user's proxy, so it stays opt-in.
        if settings.hsts_header:
            headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


def install_security(app: FastAPI) -> None:
    """Attach the security middleware (idempotent)."""
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
