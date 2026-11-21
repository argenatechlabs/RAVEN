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
    ("AWS Session Token",
     re.compile(r"\b(FwoGZXIvYXdz|ATPA)[A-Za-z0-9/+=]{100,}\b")),
    ("GitHub OAuth Token", re.compile(r"\bgho_[A-Za-z0-9]{36,}\b")),
    ("GitHub App Token", re.compile(r"\b(?:ghs|ghu)_[A-Za-z0-9]{36,}\b")),
    ("GitHub Fine-Grained Token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Slack Webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth Client ID",
     re.compile(r"\b[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b")),
    ("Stripe Key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Twilio SID", re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("SendGrid Key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("Mailgun Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("Mailchimp Key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("Facebook Token", re.compile(r"\bEAACEdEose0cBA[0-9A-Za-z]{10,}\b")),
    ("Discord Bot Token",
     re.compile(r"\b[MNO][A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{27,}\b")),
    ("Discord Webhook",
     re.compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
               r"[0-9]{17,}/[A-Za-z0-9_\-]{60,}")),
    ("Telegram Bot Token", re.compile(r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{30,}\b")),
    ("Shopify Token", re.compile(r"\bshpat_[0-9a-fA-F]{32}\b")),
    ("Square Token", re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")),
    ("PayPal Braintree",
     re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b")),
    ("Firebase URL", re.compile(r"\b[A-Za-z0-9-]+\.firebaseio\.com\b")),
    ("Firebase Server Key", re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}\b")),
    ("Heroku API Key",
     re.compile(r"(?i)\bheroku.{0,10}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
               r"[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("NPM Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI Token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{40,}\b")),
    ("Docker Hub Token", re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b")),
    ("Azure Storage Key", re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{64,}==\b")),
    ("Bearer Token",
     re.compile(r"(?i)\b(?:authorization|bearer)[\"'\s:=]+[A-Za-z0-9._\-]{20,}\b")),
    ("Basic Auth Credentials",
     re.compile(r"(?i)\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]{12,}")),
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("SSH Public Key",
     re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/=]{100,}\b")),
    ("Connection String",
     re.compile(r"(?i)\b(?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql|sqlserver)"
                 r"(?:\+[a-z]+)?://[^\s'\"]{8,200}")),
    ("SMTP Credentials",
     re.compile(r"(?i)\b(?:smtp|smtps)://[^\s'\"]{3,200}")),
    ("Generic Secret Assignment",
     re.compile(
         r"""(?i)(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key)"""
         r"""['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]"""
     )),
    ("Basic Auth in URL", re.compile(r"https?://[^/\s:]+:[^/\s@]{3,}@[^\s\"']+")),
    ("Internal IPv4 Address",
     re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b")),
    ("Internal Hostname",
     re.compile(r"\b[a-z0-9-]+\.(?:internal|local|corp|lan|intra|private)\b")),
    ("Email Address",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("AWS S3 URL",
     re.compile(r"\bhttps?://[A-Za-z0-9._\-]*\.?s3[.-][A-Za-z0-9._\-]*\.amazonaws\.com[^\s\"']*")),
    ("Google Service Account",
     re.compile(r"\"(?:private_key_id|client_email|project_id)\"\s*:\s*\"[^\"]{10,}\"")),
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
        (".env", ".config", "config", "settings.js", ".json", ".xml", ".yaml", ".yml"))]
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
