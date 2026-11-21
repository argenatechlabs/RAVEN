"""Shared helpers for invoking the embedded scanner binaries.

Every scanner first tries its native binary (subfinder / httpx / katana /
nuclei). When the binary is not available the module falls back to a small
pure-Python engine so the pipeline still produces useful, honest results —
the UI clearly labels which engine was used.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

from app.config import Settings


@dataclass
class CmdResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@dataclass
class EngineReport:
    engine: str
    command: Optional[str] = None
    detail: str = ""
    extra: Dict[str, object] = field(default_factory=dict)


def resolve_binary(name: str, settings: Settings) -> Optional[str]:
    """Return an executable path for ``name`` or ``None``."""
    candidate = os.path.join(settings.scanner_bin_dir, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return shutil.which(name)


def run_cmd(
    argv: List[str],
    timeout: int,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> CmdResult:
    """Run a command, capturing output. Never raises for non-zero exit codes."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=merged_env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return CmdResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except subprocess.TimeoutExpired as exc:
        return CmdResult(
            argv=argv,
            returncode=124,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=f"command timed out after {timeout}s",
        )
    except FileNotFoundError:
        return CmdResult(argv=argv, returncode=127, stdout="", stderr="binary not found")
    except Exception as exc:  # pragma: no cover - defensive
        return CmdResult(argv=argv, returncode=1, stdout="", stderr=str(exc))


def write_lines(path: str, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8", errors="replace") as handle:
        handle.write("\n".join(lines))
        if lines:
            handle.write("\n")


def read_lines(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return [line.strip() for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------------------
# Pure-Python fallback helpers
# ---------------------------------------------------------------------------

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "test", "staging", "stage", "prod",
    "admin", "portal", "app", "blog", "shop", "cdn", "static", "assets",
    "vpn", "remote", "ns1", "ns2", "smtp", "webmail", "git", "jenkins",
    "jira", "gitlab", "demo", "beta", "m", "mobile", "dashboard", "auth",
    "sso", "login", "secure", "support", "docs", "status", "grafana",
    "kibana", "elastic", "db", "mysql", "postgres", "redis", "ftp",
    "cpanel", "whm", "panel", "cloud", "internal", "intranet", "extranet",
    "old", "new", "v1", "v2", "v3", "uat", "qa", "sandbox", "preprod",
    "api-dev", "api-staging", "gw", "gateway", "proxy", "lb", "edge",
]

JS_FILE_HINTS = (".js", ".jsx", ".mjs", ".ts", ".tsx")


def is_js_url(url: str) -> bool:
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith(JS_FILE_HINTS) and not path.endswith(".json")


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


class RateLimitedClient:
    """Tiny httpx wrapper enforcing the per-target requests-per-second cap."""

    def __init__(self, rate_limit: int = 10, timeout: float = 8.0) -> None:
        self.rate_limit = max(1, int(rate_limit))
        self.min_interval = 1.0 / self.rate_limit
        self._last = 0.0
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            verify=False,
            headers={
                "User-Agent": "RAVEN-Pentest/1.0 (+https://github.com/argenatechlabs/RAVEN)",
                "Accept": "*/*",
            },
        )

    def get(self, url: str, follow_redirects: bool = True) -> Optional[httpx.Response]:
        return self.request("GET", url, follow_redirects=follow_redirects)

    def request(
        self, method: str, url: str, follow_redirects: bool = True
    ) -> Optional[httpx.Response]:
        delay = self.min_interval - (time.monotonic() - self._last)
        if delay > 0:
            time.sleep(delay)
        self._last = time.monotonic()
        try:
            return self.client.request(method, url, follow_redirects=follow_redirects)
        except httpx.HTTPError:
            return None

    def close(self) -> None:
        self.client.close()
