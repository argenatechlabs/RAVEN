"""Context handed to every scanner stage."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from app.config import Settings
from app.logger import ScanLogger


@dataclass
class ScanContext:
    scan_id: int
    domain: str
    scan_type: str
    workdir: str
    settings: Settings
    logger: ScanLogger
    # Wall-clock cutoff for the whole pipeline; ``None`` disables the budget.
    deadline: Optional[float] = None

    @property
    def deep(self) -> bool:
        return self.scan_type == "deep"

    def remaining(self, floor: float = 20.0) -> float:
        """Seconds left before the scan is cut off."""
        if self.deadline is None:
            return float(self.settings.scanner_timeout)
        return max(floor, self.deadline - time.monotonic())

    def command_timeout(self, cap: Optional[float] = None) -> float:
        """Timeout for a single external command, bounded by the scan budget."""
        value = min(self.remaining(), float(self.settings.scanner_timeout))
        if cap is not None:
            value = min(value, float(cap))
        return value

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline
