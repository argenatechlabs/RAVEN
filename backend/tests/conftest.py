"""Shared pytest fixtures.

Environment is configured *before* any ``app`` module is imported because the
application uses a settings singleton created at import time.
"""
from __future__ import annotations

import os
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix="raven-test-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/raven.db")
os.environ.setdefault("DATA_DIR", f"{_TMP}/data")
os.environ.setdefault("DEMO_MODE", "true")
os.environ.setdefault("SCANNER_BIN_DIR", "/nonexistent")
os.environ.setdefault("ALLOW_INLINE_SCANS", "false")
os.environ.setdefault("API_RATE_LIMIT", "false")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6399/0")
os.environ.setdefault("AI_PROVIDER", "local")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Scan, ScanStatus  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    init_db()


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def demo_scan(db):
    """A queued demo scan row that tests can drive through the pipeline."""
    scan = Scan(
        target_domain="acme.example.com",
        scan_type="fast",
        status=ScanStatus.queued,
        authorized=True,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@pytest.fixture()
def settings_override():
    """Temporarily change settings attributes (restored afterwards)."""
    changed: list[tuple[str, object]] = []

    def apply(**values):
        for key, value in values.items():
            changed.append((key, getattr(settings, key)))
            setattr(settings, key, value)
        return settings

    yield apply
    for key, value in reversed(changed):
        setattr(settings, key, value)
