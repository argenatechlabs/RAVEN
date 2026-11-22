"""Live log distribution.

Logs are persisted to ``scan_logs`` (history / replay) and pushed to any
connected WebSocket client through an in-process pub/sub bus. The worker
thread publishes, the async WebSocket handler consumes.
"""
from __future__ import annotations

import asyncio
import threading
from datetime import datetime
from typing import Any, Dict, Optional, Set, Tuple

from sqlalchemy.orm import Session

from app.models import ScanLog

Subscriber = Tuple[asyncio.AbstractEventLoop, "asyncio.Queue[Dict[str, Any]]"]

def clean_text(value: Any) -> Any:
    """Replace NUL, which PostgreSQL rejects in text and JSON strings."""
    if isinstance(value, str):
        return value.replace("\x00", " ")
    return value


class LogBus:
    def __init__(self) -> None:
        self._subs: Dict[int, Set[Subscriber]] = {}
        self._lock = threading.Lock()

    def subscribe(self, scan_id: int) -> "asyncio.Queue[Dict[str, Any]]":
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:  # pragma: no cover - programming error
            raise RuntimeError("LogBus.subscribe must be called from an event loop") from exc
        queue: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=2000)
        with self._lock:
            self._subs.setdefault(scan_id, set()).add((loop, queue))
        return queue

    def unsubscribe(self, scan_id: int, queue: "asyncio.Queue[Dict[str, Any]]") -> None:
        with self._lock:
            subs = self._subs.get(scan_id)
            if not subs:
                return
            for entry in list(subs):
                if entry[1] is queue:
                    subs.discard(entry)
            if not subs:
                self._subs.pop(scan_id, None)

    def publish(self, scan_id: int, level: str, message: str) -> None:
        payload = {
            "level": level,
            "message": message,
            "ts": datetime.utcnow().isoformat(),
        }
        with self._lock:
            subs = list(self._subs.get(scan_id, ()))
        for loop, queue in subs:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, payload)
            except RuntimeError:  # loop already closed
                continue


bus = LogBus()


class ScanLogger:
    """Persist a log line and broadcast it to live subscribers."""

    def __init__(self, session: Session, scan_id: int, bus_: Optional[LogBus] = None) -> None:
        self.session = session
        self.scan_id = scan_id
        self.bus = bus_ or bus

    def log(self, level: str, message: str) -> None:
        message = clean_text(str(message))
        try:
            self.session.add(ScanLog(scan_id=self.scan_id, level=level, message=message))
            self.session.commit()
        except Exception:  # logging must never break a scan
            self.session.rollback()
        self.bus.publish(self.scan_id, level, message)

    def debug(self, message: str) -> None:
        self.log("debug", message)

    def info(self, message: str) -> None:
        self.log("info", message)

    def warning(self, message: str) -> None:
        self.log("warning", message)

    def error(self, message: str) -> None:
        self.log("error", message)

    def success(self, message: str) -> None:
        self.log("success", message)
