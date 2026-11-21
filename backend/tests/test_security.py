"""Rate limiting, API-key gate and security headers."""
from __future__ import annotations

from app.core.security import RateLimiter, reset_limiters


def test_rate_limiter_blocks_after_capacity():
    limiter = RateLimiter(limit=2, window=60)
    assert limiter.allow("ip").allowed is True
    assert limiter.allow("ip").allowed is True
    assert limiter.allow("ip").allowed is False


def test_rate_limiter_isolates_keys():
    limiter = RateLimiter(limit=1, window=60)
    assert limiter.allow("a").allowed is True
    assert limiter.allow("a").allowed is False
    assert limiter.allow("b").allowed is True


def test_security_headers_present(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "referrer-policy" in response.headers


def test_api_key_gate_rejects_missing_key(client, settings_override):
    reset_limiters()
    settings_override(api_key="s3cret", api_rate_limit=False)
    try:
        assert client.get("/api/scanners/status").status_code == 401
        assert (
            client.get(
                "/api/scanners/status", headers={"X-API-Key": "s3cret"}
            ).status_code
            == 200
        )
        assert (
            client.get(
                "/api/scanners/status", headers={"Authorization": "Bearer s3cret"}
            ).status_code
            == 200
        )
    finally:
        settings_override(api_key="")


def test_rate_limit_returns_429_not_500(client, settings_override):
    reset_limiters()
    settings_override(api_rate_limit=True, api_rate_limit_rpm=1)
    try:
        first = client.get("/api/scanners/status")
        second = client.get("/api/scanners/status")
        assert first.status_code == 200
        assert second.status_code == 429
        assert "Retry-After" in second.headers
        assert "limit" in second.json()["detail"].lower()
    finally:
        reset_limiters()
        settings_override(api_rate_limit=False)


def test_scan_write_limit_is_stricter(client, settings_override):
    reset_limiters()
    settings_override(
        api_rate_limit=True, scan_rate_limit_rpm=1, api_rate_limit_rpm=100
    )
    try:
        payload = {
            "domain": "example.com",
            "scan_type": "fast",
            "authorized": True,
        }
        assert client.post("/api/scans", json=payload).status_code == 201
        blocked = client.post("/api/scans", json=payload)
        assert blocked.status_code == 429
    finally:
        reset_limiters()
        settings_override(api_rate_limit=False)
