"""RAVEN backend entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import ai_settings, findings, reports, scans, scanners
from app.config import settings
from app.core.security import install_security, require_api_key
from app.core.worker import ScanWorker
from app.database import init_db
from app.logger import bus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s",
)
logger = logging.getLogger("raven")

VERSION = "1.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    worker = ScanWorker(settings, bus)
    worker.start()
    scans.set_worker(worker)
    logger.info(f"{settings.app_name} v{VERSION} baslatildi (kuyruk={worker.mode})")
    yield
    worker.stop()
    logger.info("RAVEN kapatiliyor")


app = FastAPI(
    title=settings.app_name,
    version=VERSION,
    description="Autonomous AI pentester: recon, crawling, vulnerability scan, AI triage, PDF report.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

install_security(app)

# Everything except /api/health is behind the optional API-key gate so the
# container healthcheck keeps working even when a key is configured.
_authenticated = [Depends(require_api_key)]
app.include_router(scans.router, dependencies=_authenticated)
app.include_router(findings.router, dependencies=_authenticated)
app.include_router(reports.router, dependencies=_authenticated)
app.include_router(ai_settings.router, dependencies=_authenticated)
app.include_router(scanners.router, dependencies=_authenticated)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    from app.ai.provider import PROVIDERS

    configured = [
        pid for pid in PROVIDERS if getattr(settings, f"{pid}_api_key", "")
    ]
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": VERSION,
        "demo_mode": settings.demo_mode,
        "ai_provider": settings.ai_provider,
        "ai_configured_from_env": configured,
    }
