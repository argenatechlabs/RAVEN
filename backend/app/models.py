"""Database models — deliberately kept to the three core entities plus the
live-log stream table."""
from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ScanStatus(str, enum.Enum):
    queued = "queued"
    scanning = "scanning"
    completed = "completed"
    failed = "failed"


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def order(self) -> int:
        return {self.critical: 0, self.high: 1, self.medium: 2, self.low: 3, self.info: 4}[self]

    @property
    def weight(self) -> float:
        return {self.critical: 12.0, self.high: 6.0, self.medium: 2.5, self.low: 0.8, self.info: 0.1}[self]


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_domain: Mapped[str] = mapped_column(String(253), index=True)
    scan_type: Mapped[str] = mapped_column(String(16), default="fast")  # fast | deep
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.queued, index=True
    )
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    current_stage: Mapped[str] = mapped_column(String(64), default="queued")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    meta: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    subdomains: Mapped[List["Subdomain"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    logs: Mapped[List["ScanLog"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_domain": self.target_domain,
            "scan_type": self.scan_type,
            "status": self.status.value,
            "progress": self.progress,
            "current_stage": self.current_stage,
            "risk_score": self.risk_score,
            "authorized": self.authorized,
            "error": self.error,
            "meta": self.meta or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(64), default="vulnerability")
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.info, index=True)
    cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exploit_scenario: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fix_code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="nuclei")
    raw: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped["Scan"] = relationship(back_populates="findings")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "type": self.type,
            "title": self.title,
            "severity": self.severity.value,
            "cvss": self.cvss,
            "url": self.url,
            "evidence": self.evidence,
            "ai_analysis": self.ai_analysis,
            "exploit_scenario": self.exploit_scenario,
            "fix_code": self.fix_code,
            "is_false_positive": self.is_false_positive,
            "owasp_category": self.owasp_category,
            "source": self.source,
            "ai_provider": (self.raw or {}).get("ai_provider"),
            "ai_confidence": (self.raw or {}).get("confidence"),
        }


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    subdomain: Mapped[str] = mapped_column(String(253), index=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False)
    technologies: Mapped[List[str]] = mapped_column(JSON, default=list)
    ports: Mapped[List[int]] = mapped_column(JSON, default=list)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="subdomains")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subdomain": self.subdomain,
            "ip": self.ip,
            "is_alive": self.is_alive,
            "technologies": self.technologies or [],
            "ports": self.ports or [],
            "status_code": self.status_code,
            "title": self.title,
        }


class Setting(Base):
    """Key/value store for user-configurable AI provider settings.

    Secrets are stored as-is (MVP has no encryption-at-rest by design); they are
    never returned by the API, only masked.
    """

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self, mask: bool = False) -> Dict[str, Any]:
        value = self.value
        if mask and self.is_secret and value:
            value = f"{value[:4]}••••{value[-4:]}" if len(value) > 8 else "••••"
        return {"key": self.key, "value": value, "is_secret": self.is_secret}


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="logs")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "level": self.level,
            "message": self.message,
            "ts": self.ts.isoformat() if self.ts else None,
        }
