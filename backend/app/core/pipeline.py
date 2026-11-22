"""End-to-end scan orchestration: recon -> httpx -> katana -> nuclei ->
secret scan -> AI triage -> report data."""
from __future__ import annotations

import os
import time
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.ai.provider import LocalProvider, resolve_provider
from app.ai.reporter import generate_executive_summary
from app.ai.triage import triage_findings
from app.config import Settings
from app.core.scan_lock import acquire_scan_slot
from app.database import SessionLocal
from app.logger import LogBus, ScanLogger, clean_text as _clean_text
from app.models import Finding, Scan, ScanStatus, Severity, Subdomain
from app.scanners import crawler, recon, secrets, tech, tls, vuln
from app.scanners.context import ScanContext
from app.scanners.types import SecretResult, SubdomainResult, VulnResult

def _clean_obj(value: Any) -> Any:
    """Clean strings, including keys, in JSON-bound scanner output."""
    if isinstance(value, dict):
        return {_clean_text(k): _clean_obj(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_obj(v) for v in value]
    return _clean_text(value)


STAGE_PROGRESS = {
    "recon": 15,
    "httpx": 32,
    "crawl": 48,
    "nuclei": 68,
    "secrets": 78,
    "ai-triage": 92,
    "reporting": 100,
}

SECRET_SEVERITY = {
    "Private Key Block": "critical",
    "AWS Secret Access Key": "critical",
    "AWS Session Token": "critical",
    "Azure Storage Key": "critical",
    "AWS Access Key ID": "high",
    "Google API Key": "high",
    "Google OAuth Client ID": "medium",
    "Google Service Account": "high",
    "Stripe Key": "high",
    "GitHub Token": "high",
    "GitHub OAuth Token": "high",
    "GitHub App Token": "high",
    "GitHub Fine-Grained Token": "high",
    "GitLab Token": "high",
    "Slack Token": "high",
    "Slack Webhook": "high",
    "SendGrid Key": "high",
    "Mailgun Key": "high",
    "Twilio SID": "medium",
    "Twilio API Key": "high",
    "Shopify Token": "high",
    "Square Token": "high",
    "PayPal Braintree": "high",
    "Firebase Server Key": "high",
    "Heroku API Key": "high",
    "NPM Token": "high",
    "PyPI Token": "high",
    "Docker Hub Token": "medium",
    "Discord Bot Token": "high",
    "Discord Webhook": "high",
    "Telegram Bot Token": "high",
    "Bearer Token": "medium",
    "Basic Auth Credentials": "medium",
    "Connection String": "high",
    "SMTP Credentials": "medium",
    "SSH Public Key": "low",
    "JWT": "medium",
    "Generic Secret Assignment": "medium",
    "Generic High Entropy String": "low",
    "Basic Auth in URL": "medium",
    "Firebase URL": "info",
    "Internal IPv4 Address": "low",
    "Internal Hostname": "info",
    "AWS S3 URL": "info",
    "Facebook Token": "high",
    "Mailchimp Key": "medium",
}


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.info


def compute_risk_score(findings: List[Finding]) -> int:
    total = 0.0
    for f in findings:
        if f.is_false_positive:
            continue
        total += f.severity.weight
    return max(0, min(100, int(round(total))))


class ScanPipeline:
    def __init__(self, scan_id: int, settings: Settings, bus: Optional[LogBus] = None) -> None:
        self.scan_id = scan_id
        self.settings = settings
        self.bus = bus

    # -- helpers ------------------------------------------------------------
    def _progress(self, session: Session, scan: Scan, stage: str) -> None:
        scan.current_stage = stage
        scan.progress = STAGE_PROGRESS.get(stage, scan.progress)
        session.commit()

    def _save_subdomains(self, session: Session, scan: Scan,
                         discovered: List[str], alive: List[SubdomainResult]) -> None:
        alive_by_host = {a.subdomain: a for a in alive}
        rows: List[Subdomain] = []
        for host in discovered:
            info = alive_by_host.get(host)
            rows.append(
                Subdomain(
                    scan_id=scan.id,
                    subdomain=_clean_text(host),
                    ip=_clean_text(info.ip) if info else None,
                    is_alive=bool(info),
                    technologies=_clean_obj(info.technologies if info else []),
                    ports=info.ports if info else [],
                    status_code=info.status_code if info else None,
                    title=_clean_text(info.title) if info else None,
                )
            )
        session.bulk_save_objects(rows)
        session.commit()

    def _save_findings(self, session: Session, scan: Scan,
                       vulns: List[VulnResult], secrets: List[SecretResult],
                       engine: str = "nuclei") -> List[Finding]:
        rows: List[Finding] = []
        seen: set = set()
        for v in vulns:
            key = (v.template_id, v.url)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                Finding(
                    scan_id=scan.id,
                    type="vulnerability",
                    title=_clean_text(v.name),
                    severity=_severity(v.severity),
                    cvss=v.cvss,
                    url=_clean_text(v.url),
                    evidence=_clean_text(v.evidence),
                    source=_clean_text(engine),
                    raw={"template_id": _clean_text(v.template_id),
                         "tags": _clean_obj(v.tags),
                         "description": _clean_text(v.description)},
                )
            )
        for s in secrets:
            rows.append(
                Finding(
                    scan_id=scan.id,
                    type="secret",
                    title=_clean_text(f"Sir Fitili: {s.secret_type}"),
                    severity=_severity(SECRET_SEVERITY.get(s.secret_type, "medium")),
                    cvss=None,
                    url=_clean_text(s.url),
                    evidence=_clean_text(f"{s.match}\n{s.context}"),
                    source="secret-scan",
                    raw={"secret_type": _clean_text(s.secret_type), "line": s.line},
                )
            )
        session.bulk_save_objects(rows)
        session.commit()
        # reload with ids
        return (
            session.query(Finding)
            .filter(Finding.scan_id == scan.id)
            .order_by(Finding.id.asc())
            .all()
        )

    # -- main ---------------------------------------------------------------
    def run(self) -> None:
        session: Session = SessionLocal()
        try:
            scan = session.get(Scan, self.scan_id)
            if scan is None:
                return
            if scan.status == ScanStatus.completed:
                return

            scan.status = ScanStatus.scanning
            scan.current_stage = "queued"
            scan.progress = 0
            scan.error = None
            session.commit()

            logger = ScanLogger(session, scan.id, self.bus)
            logger.info(f"Tarama baslatildi: {scan.target_domain} ({scan.scan_type})")
            workdir = os.path.join(self.settings.data_dir, "scans", str(scan.id))
            os.makedirs(workdir, exist_ok=True)
            ctx = ScanContext(
                scan_id=scan.id,
                domain=scan.target_domain,
                scan_type=scan.scan_type,
                workdir=workdir,
                settings=self.settings,
                logger=logger,
            )
            budget = (
                self.settings.scan_timeout_deep
                if ctx.deep
                else self.settings.scan_timeout_fast
            )
            ctx.deadline = time.monotonic() + budget
            logger.info(
                f"Tarama bütçesi: {budget} sn ({'deep' if ctx.deep else 'fast'})"
            )

            try:
                # 1) recon
                self._progress(session, scan, "recon")
                subdomains, recon_report = recon.run(ctx)
                logger.info(f"Recon motoru: {recon_report.engine} — {recon_report.detail}")

                # 2) liveness + tech
                self._progress(session, scan, "httpx")
                alive, tech_report = tech.run(ctx, subdomains)
                logger.info(f"Liveness motoru: {tech_report.engine} — {tech_report.detail}")
                self._save_subdomains(session, scan, subdomains, alive)

                # 2b) TLS / certificate health (cheap, runs on HTTPS hosts)
                tls_findings, tls_report = tls.run(ctx, alive)
                logger.info(f"TLS motoru: {tls_report.engine} — {tls_report.detail}")

                # 3) crawl
                self._progress(session, scan, "crawl")
                endpoints, crawl_report = crawler.run(ctx, alive)
                logger.info(f"Crawler motoru: {crawl_report.engine} — {crawl_report.detail}")

                # 4) vuln scan
                self._progress(session, scan, "nuclei")
                vulns, vuln_report = vuln.run(
                    ctx, alive, endpoints, extra_findings=tls_findings
                )
                logger.info(f"Zafiyet motoru: {vuln_report.engine} — {vuln_report.detail}")

                # 5) secret scan
                self._progress(session, scan, "secrets")
                secret_findings, secret_report = secrets.run(ctx, endpoints)
                logger.info(f"Gizli anahtar motoru: {secret_report.engine} — {secret_report.detail}")

                findings = self._save_findings(
                    session, scan, vulns, secret_findings, vuln_report.engine
                )
                scan.meta = _clean_obj({
                    **(scan.meta or {}),
                    "engines": {
                        "recon": recon_report.engine,
                        "liveness": tech_report.engine,
                        "tls": tls_report.engine,
                        "crawler": crawl_report.engine,
                        "vulnerability": vuln_report.engine,
                        "secrets": secret_report.engine,
                    },
                    "counts": {
                        "subdomains": len(subdomains),
                        "alive": len(alive),
                        "endpoints": len(endpoints),
                        "vulnerabilities": len(vulns),
                        "secrets": len(secret_findings),
                    },
                })
                session.commit()

                if not findings:
                    logger.warning(
                        "Tarama 0 bulgu üretti (motorlar: "
                        f"{recon_report.engine}/{vuln_report.engine}). "
                        "Scanner binary'leri kuruluysa loglara bakın; "
                        "kurulu değilse yerleşik motor sınırlı olabilir."
                    )
                    scan.meta = {**(scan.meta or {}), "warning": "no_findings"}
                    session.commit()

                # 6) AI triage
                self._progress(session, scan, "ai-triage")
                if ctx.expired():
                    # The wall-clock budget is spent: keep the deterministic
                    # analysis instead of paying for an LLM round-trip.
                    logger.warning(
                        "Tarama süresi doldu; AI triage atlanıyor (yerel analiz)"
                    )
                    provider = LocalProvider()
                else:
                    provider = resolve_provider(
                        self.settings, logger, db=session,
                        provider_id=(scan.meta or {}).get("ai_provider"),
                    )
                scan.meta = _clean_obj({
                    **(scan.meta or {}),
                    "ai": {"provider": provider.name, "model": provider.model},
                })
                session.commit()
                payload = [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "url": f.url,
                        "evidence": f.evidence,
                        "tags": (f.raw or {}).get("tags", []),
                        "cvss": f.cvss,
                        "type": f.type,
                    }
                    for f in findings
                ]
                triage = triage_findings(
                    payload, provider, logger, self.settings.ai_max_findings_per_request
                )
                for f in findings:
                    result = triage.get(f.id)
                    if not result:
                        continue
                    f.severity = _severity(result.severity)
                    f.is_false_positive = result.is_false_positive
                    f.ai_analysis = _clean_text(result.reason)
                    f.exploit_scenario = _clean_text(result.exploit_scenario)
                    f.fix_code = _clean_text(result.fix_code)
                    f.owasp_category = _clean_text(result.owasp_category)
                    if result.cvss is not None:
                        f.cvss = result.cvss
                    raw = dict(f.raw or {})
                    raw["confidence"] = result.confidence
                    raw["ai_attempts"] = result.attempts
                    f.raw = raw
                session.commit()

                # 7) summary + risk
                self._progress(session, scan, "reporting")
                scan.risk_score = compute_risk_score(findings)
                sub_rows = [s.to_dict() for s in scan.subdomains]
                finding_rows = [f.to_dict() for f in findings]
                summary = generate_executive_summary(
                    scan.to_dict(), finding_rows, sub_rows, provider, logger
                )
                scan.meta = _clean_obj({
                    **(scan.meta or {}),
                    "executive_summary": summary,
                })
                scan.status = ScanStatus.completed
                scan.progress = 100
                scan.current_stage = "completed"
                scan.completed_at = datetime.utcnow()
                session.commit()
                logger.success(
                    f"Tarama tamamlandi: risk={scan.risk_score}, "
                    f"bulgu={len(findings)}"
                )
            except Exception as exc:
                session.rollback()
                scan = session.get(Scan, self.scan_id)
                scan.status = ScanStatus.failed
                scan.error = _clean_text(f"{type(exc).__name__}: {exc}")
                scan.completed_at = datetime.utcnow()
                session.commit()
                logger.error(f"Tarama basarisiz: {scan.error}")
                logger.debug(traceback.format_exc())
        finally:
            session.close()
