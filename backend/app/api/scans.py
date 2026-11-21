"""Scan lifecycle endpoints: create, list, status and live logs."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security import scan_write_limit
from app.core.worker import ScanWorker
from app.database import get_db
from app.logger import bus
from app.models import Finding, Scan, ScanLog, ScanStatus

router = APIRouter()

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
MAX_DOMAIN_LEN = 253

_worker: Optional[ScanWorker] = None


def set_worker(worker: ScanWorker) -> None:
    global _worker
    _worker = worker


def get_worker() -> Optional[ScanWorker]:
    return _worker


class ScanCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=MAX_DOMAIN_LEN)
    scan_type: str = Field("fast", pattern="^(fast|deep)$")
    authorized: bool = False
    ai_provider: Optional[str] = Field(
        None, description="openai | anthropic | gemini | xai | openrouter | "
                          "deepseek | mistral | groq | ollama | custom | local"
    )


class ScanCreated(BaseModel):
    id: int
    status: str
    target_domain: str


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    host = domain.split(":")[0]
    if len(host) > MAX_DOMAIN_LEN or not DOMAIN_RE.match(host):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Gecersiz domain formati (ornek: example.com veya localhost:8080)",
        )
    if "." not in host and ":" not in domain:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Domain en az bir nokta icermeli veya port belirtilmelidir",
        )
    return domain


@router.post("/api/scans", response_model=ScanCreated, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(scan_write_limit)])
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    worker: Optional[ScanWorker] = Depends(get_worker),
) -> ScanCreated:
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tarama icin yasal onay gereklidir; lutfen onay kutusunu isaretleyin",
        )
    domain = validate_domain(payload.domain)

    scan = Scan(
        target_domain=domain,
        scan_type=payload.scan_type,
        status=ScanStatus.queued,
        progress=0,
        current_stage="queued",
        authorized=True,
        meta={"ai_provider": payload.ai_provider} if payload.ai_provider else {},
    )
    db.add(scan)
    db.commit()
    try:
        db.refresh(scan)
    except Exception:
        # Concurrent writers can expire the row; the id is what matters here.
        db.rollback()
        scan = db.get(Scan, scan.id)

    mode = "none"
    if worker is not None:
        try:
            mode = worker.enqueue(scan.id)
        except Exception:
            mode = "none"
    if mode == "none" and settings.allow_inline_scans:
        from app.core.scan_lock import run_pipeline

        background_tasks.add_task(run_pipeline, scan.id, settings, bus)

    return ScanCreated(id=scan.id, status=scan.status.value,
                       target_domain=scan.target_domain)


@router.get("/api/scans")
def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    total = db.scalar(select(func.count()).select_from(Scan)) or 0
    scans = (
        db.execute(
            select(Scan).order_by(Scan.id.desc()).limit(limit).offset(offset)
        )
        .scalars()
        .all()
    )
    finding_counts = dict(
        db.execute(
            select(Finding.scan_id, func.count(Finding.id)).group_by(Finding.scan_id)
        ).all()
    )
    items = []
    for scan in scans:
        data = scan.to_dict()
        data["finding_count"] = finding_counts.get(scan.id, 0)
        items.append(data)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/api/scans/diff")
def diff_scans(
    from_id: int = Query(..., alias="from"),
    to_id: int = Query(..., alias="to"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Compare two scans: findings present only in the newer/older scan."""
    older = db.get(Scan, from_id)
    newer = db.get(Scan, to_id)
    if older is None or newer is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadi")

    def key_set(scan: Scan):
        return {
            (f.title, f.url or "", f.severity.value)
            for f in scan.findings
            if not f.is_false_positive
        }

    before = key_set(older)
    after = key_set(newer)
    added = sorted(after - before)
    removed = sorted(before - after)
    return {
        "from": {"id": older.id, "domain": older.target_domain,
                 "risk_score": older.risk_score, "created_at": older.created_at.isoformat()},
        "to": {"id": newer.id, "domain": newer.target_domain,
               "risk_score": newer.risk_score, "created_at": newer.created_at.isoformat()},
        "added": [{"title": t, "url": u, "severity": s} for t, u, s in added],
        "removed": [{"title": t, "url": u, "severity": s} for t, u, s in removed],
        "risk_delta": newer.risk_score - older.risk_score,
    }


@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadi")
    data = scan.to_dict()
    data["findings"] = [f.to_dict() for f in scan.findings]
    data["subdomains"] = [s.to_dict() for s in scan.subdomains]
    return data


@router.get("/api/scans/{scan_id}/logs")
def get_logs(
    scan_id: int,
    after_id: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Tarama bulunamadi")
    rows = (
        db.execute(
            select(ScanLog)
            .where(ScanLog.scan_id == scan_id, ScanLog.id > after_id)
            .order_by(ScanLog.id.asc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    logs = [row.to_dict() for row in rows]
    return {"items": logs, "last_id": logs[-1]["id"] if logs else after_id}


@router.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: int):
    """Server-Sent Events stream of live scan logs.

    Works through ordinary HTTP proxies (unlike WebSockets), so the browser can
    subscribe through the Next.js rewrite. The WebSocket endpoint remains
    available for direct connections.
    """
    from fastapi.responses import StreamingResponse

    db = next(get_db())
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Tarama bulunamadi")
    finally:
        db.close()

    async def generate():
        db = next(get_db())
        try:
            history = (
                db.execute(
                    select(ScanLog)
                    .where(ScanLog.scan_id == scan_id)
                    .order_by(ScanLog.id.asc())
                    .limit(500)
                )
                .scalars()
                .all()
            )
            for row in history:
                payload = json.dumps({"type": "log", "log": row.to_dict()}, default=str)
                yield f"data: {payload}\n\n"
            yield "event: ready\ndata: {}\n\n"

            queue = bus.subscribe(scan_id)
            try:
                while True:
                    try:
                        log = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except asyncio.TimeoutError:
                        yield ": ping\n\n"
                        continue
                    payload = json.dumps({"type": "log", "log": log}, default=str)
                    yield f"data: {payload}\n\n"
            finally:
                bus.unsubscribe(scan_id, queue)
        finally:
            db.close()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws/scans/{scan_id}")
async def scan_logs_ws(websocket: WebSocket, scan_id: int) -> None:
    """Stream live scan logs. Historical lines are replayed first."""
    await websocket.accept()
    db = next(get_db())
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            await websocket.send_json({"type": "error", "message": "scan not found"})
            await websocket.close()
            return
        history = (
            db.execute(
                select(ScanLog)
                .where(ScanLog.scan_id == scan_id)
                .order_by(ScanLog.id.asc())
            )
            .scalars()
            .all()
        )
        await websocket.send_json({"type": "snapshot", "status": scan.status.value,
                                   "progress": scan.progress})
        for row in history:
            await websocket.send_json({"type": "log", "log": row.to_dict()})

        queue = bus.subscribe(scan_id)
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=20.0)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping"})
                    continue
                await websocket.send_json({"type": "log", "log": payload})
        except asyncio.CancelledError:
            pass
        finally:
            bus.unsubscribe(scan_id, queue)
    except WebSocketDisconnect:
        pass
    finally:
        db.close()
