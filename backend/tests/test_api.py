"""API contract tests: scans, reports, providers, settings and diff."""
from __future__ import annotations

import time

from app.config import settings
from app.core.pipeline import ScanPipeline
from app.core.security import reset_limiters
from app.database import SessionLocal
from app.logger import bus
from app.models import Scan, ScanStatus


def _run_demo_pipeline(scan_id: int) -> None:
    ScanPipeline(scan_id, settings, bus).run()


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert "version" in body


def test_create_scan_requires_authorization(client):
    response = client.post(
        "/api/scans",
        json={"domain": "example.com", "scan_type": "fast", "authorized": False},
    )
    assert response.status_code == 403
    assert "onay" in response.json()["detail"].lower()


def test_create_scan_rejects_invalid_domain(client):
    response = client.post(
        "/api/scans",
        json={"domain": "not a domain", "scan_type": "fast", "authorized": True},
    )
    assert response.status_code == 422


def test_create_scan_accepts_host_port(client):
    response = client.post(
        "/api/scans",
        json={"domain": "localhost:8080", "scan_type": "fast", "authorized": True},
    )
    assert response.status_code == 201
    assert response.json()["target_domain"] == "localhost:8080"


def test_demo_pipeline_produces_findings(demo_scan):
    _run_demo_pipeline(demo_scan.id)
    session = SessionLocal()
    try:
        scan = session.get(Scan, demo_scan.id)
        assert scan.status == ScanStatus.completed
        assert scan.risk_score > 0
        assert len(scan.findings) > 0
        assert len(scan.subdomains) > 0
        assert (scan.meta or {}).get("engines")
        assert (scan.meta or {}).get("ai")
    finally:
        session.close()


def test_get_scan_includes_findings_and_subdomains(client, demo_scan):
    response = client.get(f"/api/scans/{demo_scan.id}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == demo_scan.id
    assert "findings" in body and "subdomains" in body


def test_findings_filter_by_severity(client, demo_scan):
    response = client.get(
        f"/api/scans/{demo_scan.id}/findings", params={"severity": "critical"}
    )
    assert response.status_code == 200
    assert all(
        item["severity"] == "critical" for item in response.json()["items"]
    )


def test_subdomains_endpoint(client, demo_scan):
    response = client.get(
        f"/api/scans/{demo_scan.id}/subdomains", params={"alive": True}
    )
    assert response.status_code == 200
    assert all(item["is_alive"] for item in response.json()["items"])


def test_stats_endpoint(client, demo_scan):
    body = client.get(f"/api/scans/{demo_scan.id}/stats").json()
    assert body["scan_id"] == demo_scan.id
    assert body["severity_counts"]["critical"] >= 0
    assert "engines" in body


def test_logs_endpoint(client, demo_scan):
    body = client.get(f"/api/scans/{demo_scan.id}/logs").json()
    assert body["last_id"] >= 0
    assert isinstance(body["items"], list)


def test_events_route_is_registered():
    from app.main import app

    paths = {route.path for route in app.routes}
    assert "/api/scans/{scan_id}/events" in paths
    assert "/ws/scans/{scan_id}" in paths


def test_pdf_report_is_valid(client, demo_scan):
    _run_demo_pipeline(demo_scan.id)
    response = client.post(
        f"/api/scans/{demo_scan.id}/report", json={"format": "pdf"}
    )
    assert response.status_code == 200
    assert response.content[:5] == b"%PDF-"
    assert response.content.rstrip().endswith(b"%%EOF")


def test_json_report_payload(client, demo_scan):
    _run_demo_pipeline(demo_scan.id)
    response = client.post(
        f"/api/scans/{demo_scan.id}/report", json={"format": "json"}
    )
    assert response.status_code == 200
    body = response.json()
    for key in ("scan", "findings", "subdomains", "executive_summary", "tool"):
        assert key in body


def test_providers_and_settings(client):
    providers = client.get("/api/providers").json()
    assert len(providers["items"]) >= 8
    ids = {item["id"] for item in providers["items"]}
    assert {"openai", "anthropic", "gemini", "xai", "ollama"} <= ids

    settings = client.get("/api/settings").json()
    assert settings["provider"] in ("auto", "local")


def test_settings_update_masks_secret(client):
    response = client.put(
        "/api/settings",
        json={"provider": "xai", "model": "grok-3", "api_key": "gsk_supersecret123"},
    )
    assert response.status_code == 200
    body = response.json()
    stored = body["providers"]["xai"]["api_key"]
    assert stored and "supersecret123" not in stored
    assert "•" in stored


def test_settings_update_per_provider_keeps_key(client):
    """The /settings page patches one provider without wiping its stored key."""
    first = client.put(
        "/api/settings",
        json={"providers": {"xai": {"api_key": "gsk_keepme123", "model": "grok-3"}}},
    ).json()
    assert first["providers"]["xai"]["api_key_set"] is True

    second = client.put(
        "/api/settings",
        json={"providers": {"xai": {"model": "grok-3-mini", "keep_api_key": True}}},
    ).json()
    assert second["providers"]["xai"]["model"] == "grok-3-mini"
    assert second["providers"]["xai"]["api_key_set"] is True
    assert second["providers"]["xai"]["api_key"] == first["providers"]["xai"]["api_key"]

    # A provider that does not exist is rejected.
    assert client.put(
        "/api/settings", json={"providers": {"nope": {"model": "x"}}}
    ).status_code == 400


def test_settings_provider_local_is_accepted(client):
    body = client.put("/api/settings", json={"provider": "local"}).json()
    assert body["provider"] == "local"
    client.put("/api/settings", json={"provider": "auto"})


def test_provider_test_local(client):
    body = client.post("/api/providers/local/test").json()
    assert body["ok"] is True
    assert body["provider"] == "local"


def test_provider_test_requires_key(client):
    # Clear any key another test may have stored for xAI.
    client.put("/api/settings", json={"provider": "xai", "api_key": ""})
    response = client.post("/api/providers/xai/test")
    assert response.status_code == 400
    assert "anahtari" in response.json()["detail"].lower()


def test_provider_test_unknown(client):
    assert client.post("/api/providers/nope/test").status_code == 404


def test_diff_endpoint(client, demo_scan):
    body = client.get(f"/api/scans/diff?from={demo_scan.id}&to={demo_scan.id}").json()
    assert body["risk_delta"] == 0
    assert body["added"] == [] and body["removed"] == []


def test_diff_endpoint_404(client):
    assert client.get("/api/scans/diff?from=1&to=99999").status_code == 404


def test_scanners_status(client):
    body = client.get("/api/scanners/status").json()
    assert {item["name"] for item in body["items"]} >= {
        "subfinder", "httpx", "katana", "nuclei"
    }


def test_scan_completion_is_observable(client, demo_scan):
    _run_demo_pipeline(demo_scan.id)
    deadline = time.time() + 5
    while time.time() < deadline:
        body = client.get(f"/api/scans/{demo_scan.id}").json()
        if body["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert body["status"] == "completed"
    assert body["progress"] == 100


def test_rate_limit_headers_exposed(client, settings_override):
    settings_override(api_rate_limit=True, api_rate_limit_rpm=50)
    try:
        reset_limiters()
        response = client.get("/api/scanners/status")
        assert response.headers["x-ratelimit-limit"] == "50"
        assert "x-ratelimit-remaining" in response.headers
    finally:
        reset_limiters()
        settings_override(api_rate_limit=False)
