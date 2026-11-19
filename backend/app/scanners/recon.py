"""Stage 1 — passive/active subdomain discovery (subfinder)."""
from __future__ import annotations

import os
import random
from typing import List, Tuple

from app.scanners.common import (
    COMMON_SUBDOMAINS,
    EngineReport,
    read_lines,
    resolve_binary,
    resolve_host,
    run_cmd,
    write_lines,
)
from app.scanners.context import ScanContext
from app.scanners.types import SubdomainResult  # noqa: F401  (re-exported)

DEMO_SUFFIXES = [
    "www", "api", "dev", "staging", "admin", "mail", "app", "blog",
    "shop", "vpn", "jenkins", "git", "dashboard", "auth", "status",
]


def _demo_subdomains(domain: str) -> List[str]:
    names = random.sample(DEMO_SUFFIXES, 8)
    return sorted({domain, *(f"{name}.{domain}" for name in names)})


def run(ctx: ScanContext) -> Tuple[List[str], EngineReport]:
    """Return a deduplicated list of discovered subdomains."""
    out_file = os.path.join(ctx.workdir, "subdomains.txt")
    binary = resolve_binary("subfinder", ctx.settings)

    if ctx.settings.demo_mode:
        subs = _demo_subdomains(ctx.domain)
        write_lines(out_file, subs)
        ctx.logger.info(f"[DEMO] {len(subs)} subdomain bulundu")
        return subs, EngineReport(engine="demo", detail="sentetik veri")

    if binary:
        cmd = [binary, "-d", ctx.domain, "-silent", "-all", "-o", out_file]
        if not ctx.deep:
            cmd.remove("-all")
        ctx.logger.info(f"subfinder çalıştırılıyor: {ctx.domain}")
        result = run_cmd(cmd, timeout=ctx.settings.scanner_timeout, cwd=ctx.workdir)
        if result.returncode == 127:
            ctx.logger.warning("subfinder bulunamadı, yerel keşfe geçiliyor")
        elif not result.ok:
            ctx.logger.warning(f"subfinder hata döndürdü: {result.stderr.strip()[:300]}")
        subs = sorted(set(read_lines(out_file)))
        if subs:
            ctx.logger.success(f"subfinder: {len(subs)} subdomain bulundu")
            return subs[: ctx.settings.max_subdomains], EngineReport(
                engine="subfinder", command=" ".join(cmd), detail=f"{len(subs)} host"
            )
        ctx.logger.warning("subfinder sonuç döndürmedi, yerel keşfe geçiliyor")

    # --- Pure-Python fallback: DNS brute force over a common-name list ------
    ctx.logger.info("Yerel DNS keşfi çalışıyor (ortak alt alan adları)")
    found: List[str] = []
    for name in COMMON_SUBDOMAINS:
        host = f"{name}.{ctx.domain}"
        if resolve_host(host):
            found.append(host)
    found = sorted({ctx.domain, *found})
    write_lines(out_file, found)
    ctx.logger.success(f"DNS keşfi: {len(found)} host çözümlendi")
    return found[: ctx.settings.max_subdomains], EngineReport(
        engine="builtin-dns", detail=f"{len(found)} host"
    )
