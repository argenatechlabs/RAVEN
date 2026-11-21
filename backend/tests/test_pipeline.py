"""Risk scoring, triage helpers and report content."""
from __future__ import annotations

from app.ai.triage import (
    _coerce_confidence,
    _coerce_severity,
    _extract_json_array,
    _owasp_for,
    local_analysis,
)
from app.core.pipeline import compute_risk_score
from app.models import Finding, Severity


def _finding(severity: Severity, fp: bool = False) -> Finding:
    return Finding(
        id=1,
        scan_id=1,
        type="vulnerability",
        title="t",
        severity=severity,
        is_false_positive=fp,
    )


def test_risk_score_weights_and_clamps():
    findings = [
        _finding(Severity.critical),
        _finding(Severity.high),
        _finding(Severity.medium),
        _finding(Severity.low),
        _finding(Severity.info),
    ]
    score = compute_risk_score(findings)
    assert score == round(12 + 6 + 2.5 + 0.8 + 0.1)


def test_risk_score_ignores_false_positives():
    assert compute_risk_score([_finding(Severity.critical, fp=True)]) == 0


def test_risk_score_clamped_to_100():
    findings = [_finding(Severity.critical) for _ in range(20)]
    assert compute_risk_score(findings) == 100


def test_local_analysis_assigns_owasp_and_fix():
    result = local_analysis(
        {
            "id": 1,
            "title": "Exposed .env File",
            "severity": "high",
            "tags": ["env", "credentials"],
            "cvss": 7.5,
        }
    )
    assert result.is_false_positive is False
    assert result.owasp_category == "A05:2021-Security Misconfiguration"
    assert "deny" in result.fix_code or "Nginx" in result.fix_code
    assert 0.0 <= result.confidence <= 1.0


def test_coercion_helpers():
    assert _coerce_severity("HIGH", "low") == "high"
    assert _coerce_severity("bogus", "medium") == "medium"
    assert _coerce_confidence(0.9) == 0.9
    assert _coerce_confidence(None) == 0.5
    assert _coerce_confidence(7) == 1.0


def test_json_extraction_handles_fences():
    assert _extract_json_array('```json\n[{"index": 0}]\n```')
    assert _extract_json_array('{"index": 0}')
    assert _extract_json_array("not json") is None


def test_owasp_mapping():
    assert _owasp_for("SQL Injection", ["sqli"]) == "A03:2021-Injection"
    assert _owasp_for("TLS Certificate", ["tls"]) == "A05:2021-Security Misconfiguration"


def test_reporter_local_summary_mentions_engines():
    from app.ai.reporter import _local_summary

    summary = _local_summary(
        {
            "target_domain": "example.com",
            "scan_type": "fast",
            "risk_score": 10,
            "meta": {"engines": {"recon": "subfinder", "vulnerability": "nuclei"}},
        },
        [],
        [{"subdomain": "a.example.com", "is_alive": True}],
    )
    assert "subfinder" in summary
    assert "nuclei" in summary
