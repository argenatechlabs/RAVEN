"""End-to-end scan orchestration: recon -> httpx -> katana -> nuclei ->
secret scan -> AI triage -> report data."""
from __future__ import annotations

import os
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.ai.provider import resolve_provider
from app.ai.reporter import generate_executive_summary
from app.ai.triage import triage_findings
from app.config import Settings
from app.database import SessionLocal
from app.logger import LogBus, ScanLogger
from app.models import Finding, Scan, ScanStatus, Severity, Subdomain
from app.scanners import crawler, recon, secrets, tech, vuln
from app.scanners.context import ScanContext
from app.scanners.types import SecretResult, SubdomainResult, VulnResult

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
    "AWS Access Key ID": "high",
    "Google API Key": "high",
    "Stripe Key": "high",
    "GitHub Token": "high",
    "GitLab Token": "high",
    "Slack Token": "high",
    "JWT": "medium",
    "Generic Secret Assignment": "medium",
    "Basic Auth in URL": "medium",
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
                    subdomain=host,
                    ip=info.ip if info else None,
                    is_alive=bool(info),
                    technologies=info.technologies if info else [],
                    ports=info.ports if info else [],
                    status_code=info.status_code if info else None,
                    title=info.title if info else None,
                )
            )
        session.bulk_save_objects(rows)
        session.commit()

    def _save_findings(self, session: Session, scan: Scan,
                       vulns: List[VulnResult], secrets: List[SecretResult],
                       engine: str = "nuclei") -> List[Finding]:
        rows: List[Finding] = []
        for v in vulns:
            rows.append(
                Finding(
                    scan_id=scan.id,
                    type="vulnerability",
                    title=v.name,
                    severity=_severity(v.severity),
                    cvss=v.cvss,
                    url=v.url,
                    evidence=v.evidence,
                    source=engine,
                    raw={"template_id": v.template_id, "tags": v.tags,
                         "description": v.description},
                )
            )
        for s in secrets:
            rows.append(
                Finding(
                    scan_id=scan.id,
                    type="secret",
                    title=f"Sir Fitili: {s.secret_type}",
                    severity=_severity(SECRET_SEVERITY.get(s.secret_type, "medium")),
                    cvss=None,
                    url=s.url,
                    evidence=f"{s.match}\n{s.context}",
                    source="secret-scan",
                    raw={"secret_type": s.secret_type, "line": s.line},
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

                # 3) crawl
                self._progress(session, scan, "crawl")
                endpoints, crawl_report = crawler.run(ctx, alive)
                logger.info(f"Crawler motoru: {crawl_report.engine} — {crawl_report.detail}")

                # 4) vuln scan
                self._progress(session, scan, "nuclei")
                vulns, vuln_report = vuln.run(ctx, alive, endpoints)
                logger.info(f"Zafiyet motoru: {vuln_report.engine} — {vuln_report.detail}")

                # 5) secret scan
                self._progress(session, scan, "secrets")
                secret_findings, secret_report = secrets.run(ctx, endpoints)
                logger.info(f"Gizli anahtar motoru: {secret_report.engine} — {secret_report.detail}")

                findings = self._save_findings(
                    session, scan, vulns, secret_findings, vuln_report.engine
                )
                scan.meta = {
                    **(scan.meta or {}),
                    "engines": {
                        "recon": recon_report.engine,
                        "liveness": tech_report.engine,
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
                }
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
                provider = resolve_provider(
                    self.settings, logger, db=session,
                    provider_id=(scan.meta or {}).get("ai_provider"),
                )
                scan.meta = {
                    **(scan.meta or {}),
                    "ai": {"provider": provider.name, "model": provider.model},
                }
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
                    f.ai_analysis = result.reason
                    f.exploit_scenario = result.exploit_scenario
                    f.fix_code = result.fix_code
                    f.owasp_category = result.owasp_category
                    if result.cvss is not None:
                        f.cvss = result.cvss
                session.commit()

                # 7) summary + risk
                self._progress(session, scan, "reporting")
                scan.risk_score = compute_risk_score(findings)
                sub_rows = [s.to_dict() for s in scan.subdomains]
                finding_rows = [f.to_dict() for f in findings]
                summary = generate_executive_summary(
                    scan.to_dict(), finding_rows, sub_rows, provider, logger
                )
                scan.meta = {**(scan.meta or {}), "executive_summary": summary}
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
                scan.error = f"{type(exc).__name__}: {exc}"
                scan.completed_at = datetime.utcnow()
                session.commit()
                logger.error(f"Tarama basarisiz: {scan.error}")
                logger.debug(traceback.format_exc())
        finally:
            session.close()
