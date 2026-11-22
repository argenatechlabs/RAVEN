"""Stage 2 — liveness probing, HTTP fingerprinting and technology detection.

Uses httpx (projectdiscovery) with ``-tech-detect``; falls back to a small
httpx-based Python prober when the binary is unavailable.
"""
from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from app.scanners.common import (
    EngineReport,
    RateLimitedClient,
    read_lines,
    resolve_binary,
    run_cmd,
    write_lines,
)
from app.scanners.context import ScanContext
from app.scanners.types import SubdomainResult


def _demo_alive(subdomains: List[str]) -> List[SubdomainResult]:
    tech_pool = {
        "www": (["Nginx", "jQuery"], 200, "Ana Sayfa"),
        "api": (["FastAPI", "Cloudflare"], 200, "API Gateway"),
        "dev": (["Apache", "PHP"], 200, "Development"),
        "staging": (["Nginx", "React"], 200, "Staging"),
        "admin": (["Nginx", "Vue.js"], 403, "Admin Panel"),
        "mail": (["Microsoft-IIS", "Outlook"], 200, "Webmail"),
        "app": (["Express", "Node.js"], 200, "App"),
        "blog": (["WordPress", "PHP"], 200, "Blog"),
        "shop": (["Magento", "PHP"], 200, "Store"),
        "vpn": (["OpenVPN"], 200, "VPN Portal"),
        "jenkins": (["Jenkins", "Java"], 200, "Dashboard"),
        "git": (["Gitea", "Go"], 200, "Git"),
        "dashboard": (["Grafana", "Go"], 200, "Metrics"),
        "auth": (["Keycloak", "Java"], 200, "Login"),
        "status": (["Uptime Kuma", "Node.js"], 200, "Status"),
    }
    results: List[SubdomainResult] = []
    for sub in subdomains:
        key = sub.split(".", 1)[0]
        techs, code, title = tech_pool.get(key, (["Nginx"], 200, ""))
        results.append(
            SubdomainResult(
                subdomain=sub,
                ip="10.0.0.%d" % (7 + len(results)),
                is_alive=True,
                technologies=list(techs),
                ports=[443],
                status_code=code,
                title=title,
            )
        )
    return results


def _parse_httpx_jsonl(path: str, logger) -> List[SubdomainResult]:
    results: List[SubdomainResult] = []
    for line in read_lines(path):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            logger.debug(f"httpx satırı atlanıyor: {line[:120]}")
            continue
        url = row.get("url") or row.get("input")
        if not url:
            continue
        scheme = "https" if url.startswith("https://") else "http"
        results.append(
            SubdomainResult(
                subdomain=row.get("input") or url.split("://", 1)[-1].split("/", 1)[0],
                ip=row.get("ip"),
                is_alive=True,
                technologies=list(row.get("tech") or []),
                ports=[443 if scheme == "https" else 80],
                status_code=row.get("status_code"),
                title=row.get("title"),
            )
        )
    return results


def _probe_python(subdomains: List[str], ctx: ScanContext) -> List[SubdomainResult]:
    client = RateLimitedClient(rate_limit=ctx.settings.request_rate_limit,
                           extra_headers=ctx.settings.header_map)
    results: List[SubdomainResult] = []
    try:
        for sub in subdomains:
            if ctx.expired():
                break
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                resp = client.get(url)
                if resp is None:
                    continue
                techs: List[str] = []
                server = resp.headers.get("server")
                if server:
                    techs.append(server.split("/")[0])
                powered = resp.headers.get("x-powered-by")
                if powered:
                    techs.append(powered.split("/")[0])
                ctype = resp.headers.get("content-type", "")
                body = resp.text
                lower = body.lower()[:6000]
                if "wordpress" in lower or "wp-content" in lower or "wp-includes" in lower:
                    techs.append("WordPress")
                if "/wp-json" in lower:
                    techs.append("WordPress REST API")
                if "generator\" content=\"wordpress" in lower:
                    techs.append("WordPress")
                if "drupal" in lower or "drupal-settings-json" in lower:
                    techs.append("Drupal")
                if "joomla" in lower or "joomla!" in lower:
                    techs.append("Joomla")
                if "react" in lower and ("root" in lower or "data-react" in lower):
                    techs.append("React")
                if "__next" in lower or "next/static" in lower:
                    techs.append("Next.js")
                if "data-v-" in lower or "vue" in lower[:2000]:
                    techs.append("Vue")
                if "ng-version" in lower or "ng-app" in lower:
                    techs.append("Angular")
                if "shopify" in lower:
                    techs.append("Shopify")
                if "magento" in lower or "mage-" in lower:
                    techs.append("Magento")
                if "jquery" in lower:
                    techs.append("jQuery")
                if "bootstrap" in lower:
                    techs.append("Bootstrap")
                if "tailwind" in lower:
                    techs.append("Tailwind CSS")
                if "php" in lower[:2000] and "php" in (ctype or "").lower():
                    techs.append("PHP")
                title_match = re.search(
                    r"<title[^>]*>([^<]{0,200})</title>", body, re.IGNORECASE | re.DOTALL
                )
                title = title_match.group(1).strip() if title_match else None
                results.append(
                    SubdomainResult(
                        subdomain=sub,
                        ip=None,
                        is_alive=True,
                        technologies=sorted(set(techs)),
                        ports=[443 if scheme == "https" else 80],
                        status_code=resp.status_code,
                        title=title,
                    )
                )
                break
    finally:
        client.close()
    return results


def run(ctx: ScanContext, subdomains: List[str]) -> Tuple[List[SubdomainResult], EngineReport]:
    if not subdomains:
        return [], EngineReport(engine="none", detail="tarama edilecek host yok")

    if ctx.settings.demo_mode:
        alive = _demo_alive(subdomains)
        ctx.logger.info(f"[DEMO] {len(alive)} canlı host")
        return alive, EngineReport(engine="demo", detail="sentetik veri")
    if ctx.expired():
        return [], EngineReport(engine="timeout", detail="tarama süresi doldu")

    out_file = os.path.join(ctx.workdir, "alive.jsonl")
    list_file = os.path.join(ctx.workdir, "subdomains.txt")
    write_lines(list_file, subdomains)
    binary = resolve_binary("httpx", ctx.settings)

    if binary:
        cmd = [
            binary, "-l", list_file,
            "-silent", "-json", "-tech-detect", "-status-code", "-title",
            "-ip", "-web-server", "-threads", "50",
            "-rate-limit", str(ctx.settings.request_rate_limit),
            "-timeout", "8", "-retries", "1",
            "-o", out_file,
        ]
        ctx.logger.info(f"httpx canlı kontrolü: {len(subdomains)} host")
        result = run_cmd(cmd, timeout=ctx.command_timeout(), cwd=ctx.workdir)
        if result.returncode == 127:
            ctx.logger.warning("httpx bulunamadı, yerel proba geçiliyor")
        elif not result.ok:
            ctx.logger.warning(f"httpx hatası: {result.stderr.strip()[:300]}")
        alive = _parse_httpx_jsonl(out_file, ctx.logger)
        if alive:
            ctx.logger.success(f"httpx: {len(alive)} canlı host, teknoloji algılandı")
            return alive, EngineReport(
                engine="httpx", command=" ".join(cmd), detail=f"{len(alive)} canlı host"
            )
        ctx.logger.warning("httpx sonuç döndürmedi, yerel proba geçiliyor")

    alive = _probe_python(subdomains, ctx)
    ctx.logger.success(f"Yerel prob: {len(alive)} canlı host")
    return alive, EngineReport(engine="builtin-http", detail=f"{len(alive)} canlı host")
