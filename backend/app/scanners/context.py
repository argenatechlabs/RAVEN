"""Context handed to every scanner stage."""
from __future__ import annotations

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

    @property
    def deep(self) -> bool:
        return self.scan_type == "deep"
