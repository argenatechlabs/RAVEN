"""Findings and subdomain query endpoints."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding, Scan, Severity, Subdomain

router = APIRouter()


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadi")
    return scan


@router.get("/api/scans/{scan_id}/findings")
def list_findings(
    scan_id: int,
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
    type_: Optional[str] = Query(None, alias="type"),
    q: Optional[str] = Query(None, max_length=200),
    include_fp: bool = Query(False),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    _get_scan_or_404(db, scan_id)
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == Severity(severity))
    if type_:
        stmt = stmt.where(Finding.type == type_)
    if not include_fp:
        stmt = stmt.where(Finding.is_false_positive.is_(False))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Finding.title.ilike(like) | Finding.url.ilike(like))
    rows = db.execute(stmt.order_by(Finding.id.asc())).scalars().all()

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda f: (order.get(f.severity.value, 9), -f.id))
    return {"items": [f.to_dict() for f in rows], "total": len(rows)}


@router.get("/api/scans/{scan_id}/subdomains")
def list_subdomains(
    scan_id: int,
    alive: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    _get_scan_or_404(db, scan_id)
    stmt = select(Subdomain).where(Subdomain.scan_id == scan_id)
    if alive is not None:
        stmt = stmt.where(Subdomain.is_alive.is_(alive))
    rows = db.execute(stmt.order_by(Subdomain.subdomain.asc())).scalars().all()
    return {"items": [s.to_dict() for s in rows], "total": len(rows)}


@router.get("/api/scans/{scan_id}/stats")
def scan_stats(scan_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scan = _get_scan_or_404(db, scan_id)
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    false_positives = 0
    for f in scan.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        if f.is_false_positive:
            false_positives += 1
    alive = sum(1 for s in scan.subdomains if s.is_alive)
    return {
        "scan_id": scan.id,
        "status": scan.status.value,
        "progress": scan.progress,
        "risk_score": scan.risk_score,
        "severity_counts": counts,
        "false_positives": false_positives,
        "subdomains_total": len(scan.subdomains),
        "subdomains_alive": alive,
        "findings_total": len(scan.findings),
        "engines": (scan.meta or {}).get("engines", {}),
    }
