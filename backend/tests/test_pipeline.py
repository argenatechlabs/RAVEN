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


def test_scanner_data_with_nul_is_saved(db, demo_scan, settings_override):
    from app.core.pipeline import ScanPipeline
    from app.logger import ScanLogger
    from app.models import Subdomain, ScanLog
    from app.scanners.types import SecretResult, SubdomainResult, VulnResult

    pipeline = ScanPipeline(demo_scan.id, settings_override())
    host = "acme.example.com"
    pipeline._save_subdomains(db, demo_scan, [host], [SubdomainResult(
        subdomain=host, title="başlık\x00sonu", technologies=["teknoloji\x00x"]
    )])
    found = pipeline._save_findings(db, demo_scan, [VulnResult(
        template_id="template\x00x", name="Güvenlik\x00bulgusu", severity="high",
        url="https://example.com/\x00test", evidence="metin\x00son\nTürkçe",
        description="açıklama\x00x", tags=["etiket\x00x"]
    )], [SecretResult(url="https://example.com/\x00app.js", secret_type="token\x00x",
                      match="abc\x00def", context="içerik\x00son")])
    assert len(found) == 2
    assert found[0].title == "Güvenlik bulgusu"
    assert found[0].evidence == "metin son\nTürkçe"
    assert found[0].raw == {"template_id": "template x", "tags": ["etiket x"], "description": "açıklama x"}
    assert found[1].evidence == "abc def\niçerik son"
    saved_host = db.query(Subdomain).filter_by(scan_id=demo_scan.id).one()
    assert saved_host.title == "başlık sonu"
    assert saved_host.technologies == ["teknoloji x"]
    ScanLogger(db, demo_scan.id).info("log\x00satırı")
    assert db.query(ScanLog).filter_by(scan_id=demo_scan.id).one().message == "log satırı"


def test_pipeline_cleans_ai_output_and_completes(db, demo_scan, settings_override, monkeypatch):
    from app.ai.triage import TriageResult
    from app.core import pipeline as module
    from app.models import Scan, ScanStatus

    def triage(items, *_args):
        return {item["id"]: TriageResult(
            severity="high", is_false_positive=False, reason="neden\x00son",
            cvss=7.0, exploit_scenario="senaryo\x00son", fix_code="çözüm\x00son",
            owasp_category="OWASP\x00son", provider="test"
        ) for item in items}

    monkeypatch.setattr(module, "triage_findings", triage)
    monkeypatch.setattr(module, "generate_executive_summary", lambda *_args: "özet\x00son")
    module.ScanPipeline(demo_scan.id, settings_override(demo_mode=True, ai_provider="local")).run()
    db.expire_all()
    scan = db.get(Scan, demo_scan.id)
    assert scan.status == ScanStatus.completed
    assert scan.meta["executive_summary"] == "özet son"
    assert scan.findings
    for finding in scan.findings:
        assert (finding.ai_analysis, finding.exploit_scenario, finding.fix_code, finding.owasp_category) == (
            "neden son", "senaryo son", "çözüm son", "OWASP son"
        )
        assert finding.to_dict()["ai_provider"] == "test"
        assert finding.to_dict()["ai_confidence"] == 0.5


def test_json_cleaning_handles_nested_keys_and_preserves_text():
    from app.core.pipeline import _clean_obj

    assert _clean_obj({"key\x00x": ["metin\x00son\nTürkçe", {"nested": "\x00"}]}) == {
        "key x": ["metin son\nTürkçe", {"nested": " "}]
    }


def test_command_failure_includes_exit_code_when_stderr_empty():
    from app.scanners.common import CmdResult

    result = CmdResult(argv=["httpx"], returncode=2, stdout="", stderr="")
    assert result.error_detail() == "çıkış kodu 2; stderr boş"
