"""Stage 4 — vulnerability scanning (nuclei, 9000+ signatures).

When the nuclei binary is unavailable a small built-in engine performs a
handful of high-signal checks so the pipeline remains demonstrable offline.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional, Tuple

from app.scanners.common import (
    EngineReport,
    RateLimitedClient,
    read_lines,
    resolve_binary,
    run_cmd,
    write_lines,
)
from app.scanners.context import ScanContext
from app.scanners.types import SubdomainResult, VulnResult


def _demo_findings(alive: List[SubdomainResult]) -> List[VulnResult]:
    findings = [
        VulnResult(
            template_id="cve-2021-41773",
            name="Apache HTTP Server 2.4.49 Path Traversal",
            severity="critical",
            url=f"https://{alive[0].subdomain}/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
            matched_at=alive[0].subdomain,
            description="Path traversal + RCE in Apache 2.4.49 (CVE-2021-41773).",
            evidence="root:x:0:0:root:/root:/bin/bash",
            cvss=9.8,
            tags=["cve", "rce", "apache", "path-traversal"],
        ),
        VulnResult(
            template_id="exposed-git-directory",
            name="Exposed .git Directory",
            severity="high",
            url=f"https://{alive[1 % len(alive)].subdomain}/.git/config",
            matched_at=alive[1 % len(alive)].subdomain,
            description="The .git directory is publicly reachable, leaking source code.",
            evidence="[core]\n\trepositoryformatversion = 0\n\tfilemode = true",
            cvss=7.5,
            tags=["exposure", "git", "source-code"],
        ),
        VulnResult(
            template_id="wordpress-xss-jquery",
            name="WordPress jQuery 1.12.4 XSS",
            severity="medium",
            url=f"https://{alive[0].subdomain}/wp-includes/js/jquery/jquery.js",
            matched_at=alive[0].subdomain,
            description="Outdated jQuery version known to be vulnerable to XSS.",
            evidence="jQuery v1.12.4",
            cvss=6.1,
            tags=["xss", "wordpress", "jquery", "outdated"],
        ),
        VulnResult(
            template_id="missing-security-headers",
            name="Missing Content-Security-Policy Header",
            severity="low",
            url=f"https://{alive[0].subdomain}/",
            matched_at=alive[0].subdomain,
            description="CSP header is absent, increasing the impact of XSS.",
            evidence="HTTP/2 200 OK (no content-security-policy header)",
            cvss=3.7,
            tags=["headers", "csp", "misconfiguration"],
        ),
        VulnResult(
            template_id="exposed-env-file",
            name="Exposed .env File",
            severity="high",
            url=f"https://{alive[2 % len(alive)].subdomain}/.env",
            matched_at=alive[2 % len(alive)].subdomain,
            description="Environment file exposed; may contain credentials.",
            evidence="DB_PASSWORD=supersecret\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            cvss=7.5,
            tags=["exposure", "env", "credentials"],
        ),
    ]
    return findings


def _parse_nuclei_jsonl(path: str, logger) -> List[VulnResult]:
    results: List[VulnResult] = []
    for line in read_lines(path):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info") or {}
        severity = str(info.get("severity") or "info").lower()
        classification = info.get("classification") or {}
        cvss = classification.get("cvss-score")
        if isinstance(cvss, list):
            cvss = cvss[0] if cvss else None
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None
        results.append(
            VulnResult(
                template_id=str(row.get("template-id") or row.get("templateID") or "unknown"),
                name=str(info.get("name") or row.get("template-id") or "Unknown"),
                severity=severity,
                url=str(row.get("matched-at") or row.get("host") or ""),
                matched_at=row.get("host"),
                description=info.get("description"),
                evidence="\n".join(row.get("extracted-results") or [])
                or (row.get("matcher-name") or ""),
                cvss=cvss,
                tags=list(info.get("tags") or []),
                raw=row if isinstance(row, dict) else {},
            )
        )
    return results


# --- Built-in fallback engine -------------------------------------------------

_BUILTIN_CHECKS = [
    ("/.git/HEAD", "high", "Exposed .git Directory",
     "Git metadata is publicly reachable and may leak source code.", 7.5,
     ["exposure", "git"]),
    ("/.env", "high", "Exposed .env File",
     "Environment file exposed; may contain credentials.", 7.5,
     ["exposure", "env", "credentials"]),
    ("/phpinfo.php", "medium", "Exposed phpinfo() Page",
     "phpinfo() discloses configuration, versions and paths.", 5.3,
     ["exposure", "php", "info-disclosure"]),
    ("/server-status", "medium", "Apache server-status Exposed",
     "Apache status page reveals internal paths and metrics.", 5.3,
     ["exposure", "apache", "info-disclosure"]),
    ("/wp-config.php.bak", "medium", "WordPress Config Backup",
     "A wp-config backup file may expose database credentials.", 6.5,
     ["exposure", "wordpress", "backup"]),
    ("/backup.zip", "medium", "Public Backup Archive",
     "A backup archive is downloadable from the web root.", 5.3,
     ["exposure", "backup"]),
    ("/actuator/health", "low", "Spring Boot Actuator Exposed",
     "Actuator endpoints may reveal internals and enable further attacks.", 3.7,
     ["exposure", "spring", "actuator"]),
]


def _builtin_scan(alive: List[SubdomainResult], ctx: ScanContext) -> List[VulnResult]:
    client = RateLimitedClient(rate_limit=ctx.settings.request_rate_limit)
    findings: List[VulnResult] = []
    try:
        for host in alive[:30]:
            base = f"https://{host.subdomain}"
            landing = client.get(base + "/")
            if landing is None:
                base = f"http://{host.subdomain}"
                landing = client.get(base + "/")
            for path, severity, name, desc, cvss, tags in _BUILTIN_CHECKS:
                resp = client.get(base + path)
                if resp is None or resp.status_code not in (200, 401, 403):
                    continue
                body = resp.text
                if path == "/.git/HEAD" and not body.startswith("ref:"):
                    continue
                if path == "/.env" and "=" not in body[:2000]:
                    continue
                if path == "/phpinfo.php" and "phpinfo()" not in body[:4000]:
                    continue
                if path == "/server-status" and "Apache Status" not in body[:4000]:
                    continue
                if path == "/wp-config.php.bak" and "DB_PASSWORD" not in body[:4000]:
                    continue
                if path == "/backup.zip" and resp.headers.get("content-type", "") not in (
                    "application/zip", "application/octet-stream",
                ):
                    continue
                findings.append(
                    VulnResult(
                        template_id=path.strip("/").replace("/", "-") or "root",
                        name=name,
                        severity=severity,
                        url=base + path,
                        matched_at=host.subdomain,
                        description=desc,
                        evidence=body[:500].replace("\n", " "),
                        cvss=cvss,
                        tags=tags,
                    )
                )
            # Missing security headers on the landing page.
            resp = landing
            if resp is not None and resp.status_code < 500:
                missing = [
                    h for h in ("content-security-policy", "x-frame-options",
                                "strict-transport-security")
                    if h not in resp.headers
                ]
                if missing:
                    findings.append(
                        VulnResult(
                            template_id="missing-security-headers",
                            name="Missing Security Headers",
                            severity="low",
                            url=base + "/",
                            matched_at=host.subdomain,
                            description="Security headers absent: " + ", ".join(missing),
                            evidence=f"HTTP {resp.status_code}; missing: {', '.join(missing)}",
                            cvss=3.7,
                            tags=["headers", "misconfiguration"],
                        )
                    )
    finally:
        client.close()
    return findings


def run(
    ctx: ScanContext, alive: List[SubdomainResult]
) -> Tuple[List[VulnResult], EngineReport]:
    if not alive:
        return [], EngineReport(engine="none", detail="canlı host yok")

    if ctx.settings.demo_mode:
        findings = _demo_findings(alive)
        ctx.logger.info(f"[DEMO] nuclei: {len(findings)} bulgu")
        return findings, EngineReport(engine="demo", detail="sentetik veri")

    hosts_file = os.path.join(ctx.workdir, "alive_hosts.txt")
    out_file = os.path.join(ctx.workdir, "nuclei.jsonl")
    write_lines(hosts_file, [h.subdomain for h in alive])
    binary = resolve_binary("nuclei", ctx.settings)

    if binary:
        severities = list(ctx.settings.severity_list)
        if ctx.deep and "low" not in severities:
            severities.append("low")
        cmd = [
            binary, "-l", hosts_file,
            "-json", "-o", out_file,
            "-severity", ",".join(severities),
            "-rate-limit", str(ctx.settings.request_rate_limit),
            "-timeout", "8", "-retries", "1",
            "-duc", "-nc", "-silent",
        ]
        if ctx.settings.nuclei_templates_dir:
            cmd += ["-t", ctx.settings.nuclei_templates_dir]
        ctx.logger.info(f"nuclei taraması: {len(alive)} host, "
                        f"seviyeler={','.join(severities)}")
        result = run_cmd(cmd, timeout=ctx.settings.scanner_timeout, cwd=ctx.workdir)
        if result.returncode == 127:
            ctx.logger.warning("nuclei bulunamadı, yerel taramaya geçiliyor")
        elif not result.ok:
            ctx.logger.warning(f"nuclei hatası: {result.stderr.strip()[:300]}")
        findings = _parse_nuclei_jsonl(out_file, ctx.logger)
        if findings:
            ctx.logger.success(f"nuclei: {len(findings)} bulgu")
            return findings, EngineReport(
                engine="nuclei", command=" ".join(cmd), detail=f"{len(findings)} bulgu"
            )
        ctx.logger.warning("nuclei bulgu döndürmedi, yerel taramaya geçiliyor")

    findings = _builtin_scan(alive, ctx)
    ctx.logger.success(f"Yerel tarama: {len(findings)} bulgu")
    return findings, EngineReport(engine="builtin", detail=f"{len(findings)} bulgu")
