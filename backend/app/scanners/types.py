"""Typed results returned by the scanner modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SubdomainResult:
    subdomain: str
    ip: Optional[str] = None
    is_alive: bool = False
    technologies: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    status_code: Optional[int] = None
    title: Optional[str] = None


@dataclass
class EndpointResult:
    url: str
    is_js: bool = False


@dataclass
class VulnResult:
    template_id: str
    name: str
    severity: str
    url: str
    matched_at: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    cvss: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class SecretResult:
    url: str
    secret_type: str
    match: str
    line: int = 0
    context: str = ""
