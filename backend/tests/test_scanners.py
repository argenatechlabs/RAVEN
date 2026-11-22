"""Pure-Python engine unit tests (no external binaries required)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.scanners import secrets, tls
from app.scanners.crawler import _pagination_variants
from app.scanners.secrets import PATTERNS, _mask, _scan_text
from app.scanners.vuln import _SENSITIVE_PATHS, _with_param


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/.git/HEAD"):
            body = b"ref: refs/heads/main\n"
        elif self.path.startswith("/.env"):
            body = b"DB_PASSWORD=hunter2\n"
        elif self.path.startswith("/backup.sql"):
            body = b"CREATE TABLE users (id int);\n"
        elif self.path.startswith("/search"):
            body = b"<html>ok</html>"
        else:
            body = b"<html><title>Test</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # pragma: no cover - silence test noise
        pass


def _serve() -> tuple[str, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"127.0.0.1:{server.server_address[1]}", thread


def test_secret_patterns_detect_common_tokens():
    sample = (
        "AKIAIOSFODNN7EXAMPLE\n"
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        "xoxb-1234567890-abcdef\n"
        "AIzaSyA1234567890abcdefghijklmnopqrstuv\n"
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "mongodb://admin:pass1234@db.internal:27017/app\n"
        "admin@corp.example.com\n"
    )
    found: set[str] = set()
    results = []
    _scan_text("http://x/app.js", sample, results, set())
    for result in results:
        found.add(result.secret_type)
    for expected in (
        "AWS Access Key ID", "GitHub Token", "Slack Token", "Google API Key",
        "JWT", "Private Key Block", "Connection String",
    ):
        assert expected in found, f"missing {expected}: {found}"


def test_mask_keeps_edges():
    assert _mask("AKIAIOSFODNN7EXAMPLE").startswith("AKI")
    assert "*" in _mask("AKIAIOSFODNN7EXAMPLE")
    assert _mask("short") == "sho**"
    assert "*" in _mask("tiny")


def test_patterns_cover_expected_families():
    names = {name for name, _ in PATTERNS}
    for family in (
        "AWS Access Key ID", "GitHub Token", "GitLab Token", "Slack Token",
        "Stripe Key", "Twilio SID", "SendGrid Key", "Telegram Bot Token",
        "NPM Token", "PyPI Token", "Connection String", "JWT",
        "Internal IPv4 Address", "AWS S3 URL",
    ):
        assert family in names


def test_pagination_variants_extend_page_numbers():
    variants = _pagination_variants("http://h/list?page=1&x=2")
    assert "page=2" in variants[0]
    assert "page=3" in variants[1]
    assert "x=2" in variants[0]
    assert _pagination_variants("http://h/list") == []


def test_with_param_replaces_existing_value():
    assert "id=%27" in _with_param("http://h/item?id=1&x=2", "id", "'")
    assert "x=2" in _with_param("http://h/item?id=1&x=2", "id", "'")
    assert _with_param("http://h/item", "q", "abc").endswith("q=abc")


def test_sensitive_paths_include_admin_panels_and_backups():
    paths = {path for path, *_ in _SENSITIVE_PATHS}
    for expected in (
        "/.git/HEAD", "/.env", "/backup.sql", "/phpinfo.php", "/server-status",
        "/actuator/env", "/phpmyadmin", "/wp-admin/", "/manager/html",
        "/swagger-ui.html", "/.well-known/security.txt",
    ):
        assert expected in paths


def test_tls_run_skips_http_only_hosts():
    class _Info:
        subdomain = "127.0.0.1:8080"
        ports = [80]

    class _Ctx:
        class settings:
            demo_mode = False
            builtin_max_hosts = 5

        class logger:
            @staticmethod
            def info(message):
                pass

        @staticmethod
        def expired():
            return False

    findings, report = tls.run(_Ctx(), [_Info()])
    assert findings == []
    assert report.engine in ("builtin-tls", "none")


def test_builtin_vuln_engine_finds_exposed_files():
    from app.scanners.vuln import _builtin_scan

    host, thread = _serve()
    try:
        alive = [type("H", (), {"subdomain": host, "ports": [80]})()]
        ctx = type(
            "Ctx",
            (),
            {
                "settings": type(
                    "S",
                    (),
                    {
                        "request_rate_limit": 50,
                        "builtin_max_hosts": 5,
                        "builtin_param_budget": 0,
                        "header_map": {},
                    },
                )(),
                "deep": False,
                "expired": staticmethod(lambda: False),
            },
        )()
        findings = _builtin_scan(alive, ctx, [])
        names = {f.name for f in findings}
        assert "Exposed .git Directory" in names
        assert "Exposed .env File" in names
    finally:
        thread.join(timeout=1)


def test_secret_evidence_does_not_leak_unmasked_line():
    from app.scanners.secrets import _scan_text

    raw = 'AKIAIOSFODNN7EXAMPLE'
    results = []
    _scan_text('https://example.com/app.js', f'const key = "{raw}";', results, set())
    assert results
    assert all(raw not in result.match and raw not in result.context for result in results)
