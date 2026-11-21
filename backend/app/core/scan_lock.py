"""Scan concurrency control.

Scans are long-running and share one SQLite file in local mode, so running
several pipelines in parallel corrupts session state (and doubles the request
rate against the same target). A bounded semaphore keeps at most
``scan_concurrency`` pipelines alive; further scans wait in the queue.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from app.config import settings

_limit = max(1, int(settings.scan_concurrency))
_semaphore = threading.BoundedSemaphore(_limit)
_active = 0
_lock = threading.Lock()


def active_scans() -> int:
    with _lock:
        return _active


@contextmanager
def acquire_scan_slot(timeout: float = 1800.0) -> Iterator[bool]:
    """Wait for a free scan slot. Yields ``False`` when the wait timed out."""
    global _active
    acquired = _semaphore.acquire(timeout=timeout)
    if acquired:
        with _lock:
            _active += 1
    try:
        yield acquired
    finally:
        if acquired:
            with _lock:
                _active -= 1
            _semaphore.release()


def run_pipeline(scan_id: int, settings, bus, timeout: float = 1800.0) -> None:
    """Run one pipeline while holding a concurrency slot."""
    from datetime import datetime

    from app.core.pipeline import ScanPipeline
    from app.database import SessionLocal
    from app.models import Scan, ScanStatus

    with acquire_scan_slot(timeout) as acquired:
        if not acquired:
            session = SessionLocal()
            try:
                scan = session.get(Scan, scan_id)
                if scan and scan.status in (ScanStatus.queued, ScanStatus.scanning):
                    scan.status = ScanStatus.failed
                    scan.error = "Tarama slotu beklenirken zaman asimi"
                    scan.completed_at = datetime.utcnow()
                    session.commit()
            finally:
                session.close()
            return
        ScanPipeline(scan_id, settings, bus).run()
