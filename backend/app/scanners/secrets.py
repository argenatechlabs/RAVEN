"""Stage 5 — hardcoded secret detection in JavaScript / config endpoints."""
from __future__ import annotations

import re
from typing import List, Tuple

from app.scanners.common import (
    EngineReport,
    RateLimitedClient,
    is_js_url,
)
from app.scanners.context import ScanContext
from app.scanners.types import EndpointResult, SecretResult

# name -> (regex, is_search)
PATTERNS = [
    ("AWS Access Key ID",
     re.compile(r"\b(AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b")),
    ("AWS Secret Access Key",
     re.compile(r"""(?i)aws(.{0,20})?(secret|private)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]""")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe Key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("Generic Secret Assignment",
     re.compile(
         r"""(?i)(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key)"""
         r"""['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]"""
     )),
    ("Basic Auth in URL", re.compile(r"https?://[^/\s:]+:[^/\s@]{3,}@[^\s\"']+")),
]


def _mask(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:3] + "*" * (len(secret) - 3)
    return secret[:6] + "*" * 8 + secret[-4:]


def _demo_secrets(endpoints: List[EndpointResult]) -> List[SecretResult]:
    js = [e for e in endpoints if e.is_js] or endpoints[:1]
    base = js[0].url if js else "https://example.com/app.js"
    return [
        SecretResult(
            url=base, secret_type="AWS Access Key ID",
            match=_mask("AKIAIOSFODNN7EXAMPLE"), line=42,
            context="const awsKey = 'AKIAIOSFODNN7EXAMPLE';",
        ),
        SecretResult(
            url=base, secret_type="Generic Secret Assignment",
            match=_mask("sk_live_51H8xYzAbCdEfGhIjKlMnOp"), line=87,
            context="stripe.apiKey = 'sk_live_51H8xYzAbCdEfGhIjKlMnOp';",
        ),
        SecretResult(
            url=base, secret_type="JWT",
            match=_mask("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"),
            line=120, context="localStorage.setItem('token', jwt);",
        ),
    ]


def _scan_text(url: str, text: str, findings: List[SecretResult], seen: set) -> None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                raw = match.group(0)
                key = (name, raw)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    SecretResult(
                        url=url,
                        secret_type=name,
                        match=_mask(raw),
                        line=line_no,
                        context=line.strip()[:300],
                    )
                )


def run(
    ctx: ScanContext, endpoints: List[EndpointResult]
) -> Tuple[List[SecretResult], EngineReport]:
    if not endpoints:
        return [], EngineReport(engine="none", detail="taranacak endpoint yok")

    if ctx.settings.demo_mode:
        secrets = _demo_secrets(endpoints)
        ctx.logger.info(f"[DEMO] secret scan: {len(secrets)} sır fitil")
        return secrets, EngineReport(engine="demo", detail="sentetik veri")

    candidates = [e for e in endpoints if e.is_js]
    candidates += [e for e in endpoints if e.url.split("?")[0].endswith(
        (".env", ".config", "config", "settings.js"))]
    # de-duplicate while keeping order
    seen_urls = set()
    unique: List[EndpointResult] = []
    for ep in candidates:
        if ep.url in seen_urls:
            continue
        seen_urls.add(ep.url)
        unique.append(ep)
    unique = unique[: ctx.settings.max_js_files]

    ctx.logger.info(f"secret taraması: {len(unique)} dosya")
    client = RateLimitedClient(rate_limit=ctx.settings.request_rate_limit)
    findings: List[SecretResult] = []
    seen = set()
    try:
        for ep in unique:
            resp = client.get(ep.url)
            if resp is None or resp.status_code >= 400:
                continue
            ctype = resp.headers.get("content-type", "")
            if "javascript" not in ctype and "json" not in ctype and "text" not in ctype:
                # still scan short text bodies, skip binaries
                if len(resp.content) > 1_000_000:
                    continue
            _scan_text(ep.url, resp.text, findings, seen)
    finally:
        client.close()

    ctx.logger.success(f"secret scan: {len(findings)} sır fitili")
    return findings, EngineReport(engine="regex", detail=f"{len(findings)} secret")
