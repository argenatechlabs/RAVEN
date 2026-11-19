"""Redis-backed scan worker with an in-process fallback.

The API enqueues scan ids into Redis; a daemon thread blocks on the queue and
executes pipelines one at a time. If Redis is unavailable the same thread
consumes a local queue, so a single-container deployment always works.
"""
from __future__ import annotations

import queue
import threading
from typing import Optional

from app.config import Settings
from app.logger import LogBus


class ScanWorker:
    def __init__(self, settings: Settings, bus: Optional[LogBus] = None) -> None:
        self.settings = settings
        self.bus = bus
        self._redis = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._local: "queue.Queue[int]" = queue.Queue()
        self.mode = "inline"

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        try:
            import redis

            client = redis.Redis.from_url(self.settings.redis_url, socket_timeout=5)
            client.ping()
            self._redis = client
            self.mode = "redis"
        except Exception:
            self._redis = None
            self.mode = "inline"
        self._thread = threading.Thread(target=self._loop, name="raven-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    # -- enqueue ------------------------------------------------------------
    def enqueue(self, scan_id: int) -> str:
        if self._redis is not None:
            try:
                self._redis.rpush(self.settings.scan_queue_key, str(scan_id))
                return "redis"
            except Exception:
                self._redis = None
                self.mode = "inline"
        self._local.put(scan_id)
        return "inline"

    # -- loop ---------------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            scan_id = self._next_job()
            if scan_id is None:
                continue
            self._execute(scan_id)

    def _next_job(self) -> Optional[int]:
        if self._redis is not None:
            try:
                result = self._redis.blpop(
                    self.settings.scan_queue_key,
                    timeout=self.settings.worker_poll_interval,
                )
                if result:
                    return int(result[1])
                return None
            except Exception:
                self._redis = None
                self.mode = "inline"
        try:
            return self._local.get(timeout=self.settings.worker_poll_interval)
        except queue.Empty:
            return None

    def _execute(self, scan_id: int) -> None:
        try:
            from app.core.pipeline import ScanPipeline

            ScanPipeline(scan_id, self.settings, self.bus).run()
        except Exception:
            import logging

            logging.getLogger("raven.worker").exception("Scan %s crashed", scan_id)
