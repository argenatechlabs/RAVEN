"""PDF / JSON report generation and download."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai.provider import resolve_provider
from app.ai.reporter import generate_executive_summary
from app.config import settings
from app.core.security import api_write_limit
from app.database import get_db
from app.models import Scan, ScanStatus
from app.reports.pdf import render_pdf

router = APIRouter()


class ReportRequest(BaseModel):
    format: str = Field("pdf", pattern="^(pdf|json)$")


def _load(scan: Scan) -> Dict[str, Any]:
    findings = sorted(
        scan.findings,
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 9),
            -f.id,
        ),
    )
    return {
        "scan": scan.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "subdomains": [s.to_dict() for s in scan.subdomains],
    }


def _summary(scan: Scan) -> str:
    data = scan.meta or {}
    if data.get("executive_summary"):
        return data["executive_summary"]
    provider = resolve_provider(settings)
    payload = _load(scan)
    return generate_executive_summary(
        payload["scan"], payload["findings"], payload["subdomains"], provider
    )


def _filename(scan: Scan, ext: str) -> str:
    domain = scan.target_domain.replace(".", "_")
    return f"raven-report-{domain}-{scan.id}.{ext}"


@router.post("/api/scans/{scan_id}/report", dependencies=[Depends(api_write_limit)])
def create_report(
    scan_id: int,
    payload: ReportRequest = ReportRequest(),
    db: Session = Depends(get_db),
):
    return _build(scan_id, payload.format, db)


@router.get("/api/scans/{scan_id}/report")
def download_report(
    scan_id: int,
    format: str = Query("pdf", pattern="^(pdf|json)$"),
    db: Session = Depends(get_db),
):
    return _build(scan_id, format, db)


def _build(scan_id: int, fmt: str, db: Session):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadi")
    if scan.status not in (ScanStatus.completed, ScanStatus.failed):
        raise HTTPException(status_code=409, detail="Tarama henuz tamamlanmadi")

    data = _load(scan)
    summary = _summary(scan)
    if fmt == "pdf":
        content = render_pdf(data["scan"], data["findings"], data["subdomains"], summary)
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{_filename(scan, "pdf")}"'},
        )

    payload = {
        **data,
        "executive_summary": summary,
        "generated_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "tool": settings.app_name,
    }
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="{_filename(scan, "json")}"'},
    )
