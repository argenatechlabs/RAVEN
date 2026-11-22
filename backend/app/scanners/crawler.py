"""Stage 3 — endpoint & JavaScript discovery (katana)."""
from __future__ import annotations

import os
import re
from typing import List, Tuple
from urllib.parse import urldefrag, urljoin, urlsplit

from app.scanners.common import (
    EngineReport,
    RateLimitedClient,
    is_js_url,
    read_lines,
    resolve_binary,
    run_cmd,
    write_lines,
)
from app.scanners.context import ScanContext
from app.scanners.types import EndpointResult, SubdomainResult

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
# Quoted absolute paths inside JS/HTML (API routes, assets).
_JS_PATH_RE = re.compile(r"""["'](/[A-Za-z0-9_\-./?=&{}:$]{4,})["']""")


_PAGE_RE = re.compile(r"([?&])(page|p|offset|start|skip|from|pg)=\d+", re.IGNORECASE)


def _pagination_variants(url: str) -> List[str]:
    """Extend ``?page=N`` style URLs with the next couple of pages."""
    match = _PAGE_RE.search(url)
    if not match:
        return []
    param = match.group(2)
    variants: List[str] = []
    for page in (2, 3):
        variants.append(_PAGE_RE.sub(lambda m: f"{m.group(1)}{param}={page}", url, count=1))
    return variants


def _extract_inline_paths(text: str) -> List[str]:
    paths: List[str] = []
    for match in _JS_PATH_RE.findall(text or ""):
        path = match.split("?", 1)[0]
        if path.endswith((".js", ".mjs", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2")):
            continue
        paths.append(match)
    return paths


def _demo_endpoints(alive: List[SubdomainResult]) -> List[EndpointResult]:
    paths = [
        "/", "/login", "/admin", "/static/app.js", "/assets/index.js",
        "/js/main.js", "/api/config.js", "/dashboard", "/api/v1/users",
        "/api/v1/login", "/config", "/logout", "/register", "/search",
        "/robots.txt", "/sitemap.xml", "/.env", "/server-status",
    ]
    results: List[EndpointResult] = []
    for host in alive:
        base = f"https://{host.subdomain}"
        for path in paths[: 8 if host.subdomain.count(".") == 1 else 5]:
            url = base + path
            results.append(EndpointResult(url=url, is_js=is_js_url(url)))
    return results


def _crawl_python(alive: List[SubdomainResult], ctx: ScanContext) -> List[EndpointResult]:
    client = RateLimitedClient(rate_limit=ctx.settings.request_rate_limit,
                           extra_headers=ctx.settings.header_map)
    seen = set()
    results: List[EndpointResult] = []
    try:
        queue = [(f"{scheme}://{h.subdomain}", 0)
                 for h in alive for scheme in ("https", "http")]
        max_depth = 3 if ctx.deep else 2
        visited: set = set()
        # Bound the crawl so a busy target cannot run for the full timeout.
        budget = min(ctx.settings.max_endpoints, 800 if ctx.deep else 400)
        while queue and len(visited) < budget and not ctx.expired():
            url, depth = queue.pop(0)
            if url in seen or url in visited:
                continue
            seen.add(url)
            visited.add(url)
            resp = client.get(url, follow_redirects=False)
            if resp is None or resp.status_code >= 400:
                continue
            if depth >= max_depth:
                continue
            base = urlsplit(url).netloc.lower()
            inline = _extract_inline_paths(resp.text)
            links = _LINK_RE.findall(resp.text) + _SCRIPT_SRC_RE.findall(resp.text) + inline
            # robots.txt / sitemap.xml are goldmines for a crawler.
            if url.rstrip("/").endswith(("/robots.txt", "/sitemap.xml")):
                links += [
                    line.split(":", 1)[1].strip()
                    for line in (resp.text or "").splitlines()
                    if line.lower().startswith(("disallow:", "allow:", "sitemap:", "location:"))
                    and ":" in line
                ]
            for match in links:
                link, _ = urldefrag(match.strip())
                if not link or link.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                absolute = urljoin(url, link)
                parsed = urlsplit(absolute)
                if parsed.scheme not in ("http", "https") or parsed.netloc.lower() != base:
                    continue
                if absolute not in seen:
                    results.append(EndpointResult(url=absolute, is_js=is_js_url(absolute)))
                    queue.append((absolute, depth + 1))
                    for variant in _pagination_variants(absolute):
                        if variant not in seen:
                            results.append(
                                EndpointResult(url=variant, is_js=is_js_url(variant))
                            )
                            queue.append((variant, depth + 1))
    finally:
        client.close()
    return results[: ctx.settings.max_endpoints]


def run(
    ctx: ScanContext, alive: List[SubdomainResult]
) -> Tuple[List[EndpointResult], EngineReport]:
    if not alive:
        return [], EngineReport(engine="none", detail="canlı host yok")

    if ctx.settings.demo_mode:
        endpoints = _demo_endpoints(alive)
        ctx.logger.info(f"[DEMO] {len(endpoints)} endpoint, "
                        f"{sum(1 for e in endpoints if e.is_js)} JS dosyası")
        return endpoints, EngineReport(engine="demo", detail="sentetik veri")
    if ctx.expired():
        return [], EngineReport(engine="timeout", detail="tarama süresi doldu")

    hosts_file = os.path.join(ctx.workdir, "alive_hosts.txt")
    out_file = os.path.join(ctx.workdir, "endpoints.txt")
    write_lines(hosts_file, [h.subdomain for h in alive])
    binary = resolve_binary("katana", ctx.settings)

    if binary:
        cmd = [
            binary, "-list", hosts_file,
            "-jc", "-d", "3" if ctx.deep else "2", "-c", "10",
            "-rate-limit", str(ctx.settings.request_rate_limit),
            "-silent", "-o", out_file,
        ]
        ctx.logger.info(f"katana taraması: {len(alive)} host")
        result = run_cmd(cmd, timeout=ctx.command_timeout(), cwd=ctx.workdir)
        if result.returncode == 127:
            ctx.logger.warning("katana bulunamadı, yerel crawler'a geçiliyor")
        elif not result.ok:
            ctx.logger.warning(f"katana hatası: {result.error_detail()}")
        urls = sorted(set(read_lines(out_file)))
        if urls:
            endpoints = [EndpointResult(url=u, is_js=is_js_url(u)) for u in urls]
            js = sum(1 for e in endpoints if e.is_js)
            ctx.logger.success(f"katana: {len(endpoints)} endpoint, {js} JS dosyası")
            return endpoints[: ctx.settings.max_endpoints], EngineReport(
                engine="katana", command=" ".join(cmd), detail=f"{len(endpoints)} endpoint"
            )
        ctx.logger.warning("katana sonuç döndürmedi, yerel crawler'a geçiliyor")

    endpoints = _crawl_python(alive, ctx)
    # de-duplicate identical URLs (a page may link the same asset repeatedly)
    unique: List[EndpointResult] = []
    seen_urls = set()
    for ep in endpoints:
        if ep.url in seen_urls:
            continue
        seen_urls.add(ep.url)
        unique.append(ep)
    endpoints = unique
    js = sum(1 for e in endpoints if e.is_js)
    ctx.logger.success(f"Yerel crawler: {len(endpoints)} endpoint, {js} JS dosyası")
    return endpoints, EngineReport(engine="builtin-crawler", detail=f"{len(endpoints)} endpoint")
