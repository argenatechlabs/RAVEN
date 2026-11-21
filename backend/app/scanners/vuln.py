"""Stage 4 — vulnerability scanning (nuclei, 9000+ signatures).

When the nuclei binary is unavailable a small built-in engine performs a
handful of high-signal checks so the pipeline remains demonstrable offline.
"""
from __future__ import annotations

import json
import os
import re
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
# A dependency-free mini-scanner. Probes sensitive files, admin panels, dev
# tools, backup artifacts, security headers/methods and a few behavioural
# checks (open redirect, reflected XSS, SQL error disclosure, outdated
# software). It exists so a deployment without the external binaries still
# produces actionable results instead of an empty report.

_SQL_ERROR_RE = re.compile(
    r"(You have an error in your SQL syntax|SQL syntax.*?MySQL|"
    r"Warning[^\n]*mysql_[a-z_]+|unclosed quotation mark after the character string|"
    r"ODBC SQL Server Driver|ORA-[0-9]{5}|PostgreSQL.*?ERROR|"
    r"pg_query\(\)|SQLite3::|unrecognized token)",
    re.IGNORECASE,
)

_OUTDATED_SOFTWARE = [
    (re.compile(r"Apache/2\.4\.(?:49|50)"), "critical",
     "Apache HTTP Server 2.4.49/2.4.50 Path Traversal",
     "CVE-2021-41773 / CVE-2021-42013 — path traversal + RCE.", 9.8,
     ["cve", "apache", "rce", "path-traversal"]),
    (re.compile(r"Apache/2\.2\."), "high", "Legacy Apache 2.2",
     "End-of-life Apache version with known exploits.", 7.5,
     ["outdated", "apache"]),
    (re.compile(r"PHP/(?:5\.[0-9]|7\.[0-3])\."), "high", "Outdated PHP",
     "End-of-life / unmaintained PHP version.", 7.5, ["outdated", "php"]),
    (re.compile(r"nginx/1\.(?:[0-9]|1[0-9])\."), "low", "Outdated nginx",
     "nginx version disclosed and likely outdated.", 4.3, ["outdated", "nginx"]),
    (re.compile(r"WordPress [0-4]\.[0-9]"), "medium", "Outdated WordPress",
     "Older WordPress core with known vulnerabilities.", 6.5,
     ["outdated", "wordpress"]),
    (re.compile(r"jQuery v?1\.[0-9]+\."), "medium", "Outdated jQuery 1.x",
     "jQuery 1.x has known XSS issues (CVE-2015-9251, CVE-2019-11358, …).", 6.1,
     ["outdated", "jquery", "xss"]),
    (re.compile(r"jQuery v?2\.[0-9]+\."), "low", "Unmaintained jQuery 2.x",
     "jQuery 2.x is no longer maintained.", 4.3, ["outdated", "jquery"]),
]

# (path, severity, name, description, cvss, tags, matcher, require_200)
_SENSITIVE_PATHS = [
    ("/.git/HEAD", "high", "Exposed .git Directory",
     "Git metadata is publicly reachable and may leak source code.", 7.5,
     ["exposure", "git"], re.compile(r"^ref:|\[core\]"), True),
    ("/.git/config", "high", "Exposed .git Config",
     "Git configuration exposed; may contain remote URLs and credentials.", 7.5,
     ["exposure", "git"], re.compile(r"\[core\]|\[remote"), True),
    ("/.env", "high", "Exposed .env File",
     "Environment file exposed; may contain credentials.", 7.5,
     ["exposure", "env", "credentials"], re.compile(r"[A-Z0-9_]+\s*="), True),
    ("/.env.bak", "high", "Exposed .env Backup",
     "Backup of the environment file is downloadable.", 7.5,
     ["exposure", "env", "backup"], re.compile(r"[A-Z0-9_]+\s*="), True),
    ("/id_rsa", "critical", "Exposed SSH Private Key",
     "An SSH private key is publicly downloadable.", 9.8,
     ["exposure", "ssh", "credentials"], re.compile(r"BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY"), True),
    ("/.ssh/id_rsa", "critical", "Exposed SSH Private Key",
     "An SSH private key is publicly downloadable.", 9.8,
     ["exposure", "ssh", "credentials"], re.compile(r"BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY"), True),
    ("/.htpasswd", "high", "Exposed .htpasswd",
     "Apache password file exposed; may leak password hashes.", 7.5,
     ["exposure", "credentials"], re.compile(r":\$|:\$apr1\$|:\$2y\$"), True),
    ("/.htaccess", "low", "Exposed .htaccess",
     "Server rewrite/authentication configuration is readable.", 4.3,
     ["exposure", "config"], re.compile(r"(RewriteRule|AuthType|deny from|Allow from)"), True),
    ("/.svn/entries", "medium", "Exposed .svn Metadata",
     "SVN metadata exposed; source tree may be reconstructable.", 6.5,
     ["exposure", "svn"], None, True),
    ("/.DS_Store", "low", "Exposed macOS .DS_Store",
     "Directory metadata discloses file names.", 3.7,
     ["exposure", "info-disclosure"], None, True),
    ("/web.config", "medium", "Exposed IIS web.config",
     "IIS configuration file is readable.", 6.5,
     ["exposure", "iis", "config"], re.compile(r"<configuration|<connectionStrings|<appSettings"), True),
    ("/phpinfo.php", "medium", "Exposed phpinfo() Page",
     "phpinfo() discloses configuration, versions and paths.", 5.3,
     ["exposure", "php", "info-disclosure"], re.compile(r"phpinfo\(\)|PHP Version"), True),
    ("/info.php", "medium", "Exposed PHP Info Page",
     "A phpinfo()-like page is publicly reachable.", 5.3,
     ["exposure", "php", "info-disclosure"], re.compile(r"phpinfo\(\)|PHP Version"), True),
    ("/server-status", "medium", "Apache server-status Exposed",
     "Apache status page reveals internal paths and metrics.", 5.3,
     ["exposure", "apache", "info-disclosure"], re.compile(r"Apache Status|Server Status"), True),
    ("/server-info", "medium", "Apache server-info Exposed",
     "Apache server-info reveals loaded modules and configuration.", 5.3,
     ["exposure", "apache", "info-disclosure"], re.compile(r"Server Information|Server Settings"), True),
    ("/wp-config.php", "high", "WordPress wp-config.php Exposed",
     "WordPress configuration may be downloadable.", 7.5,
     ["exposure", "wordpress", "credentials"], re.compile(r"DB_PASSWORD|DB_NAME|AUTH_KEY"), True),
    ("/wp-config.php.bak", "high", "WordPress Config Backup",
     "A wp-config backup file may expose database credentials.", 7.5,
     ["exposure", "wordpress", "backup"], re.compile(r"DB_PASSWORD|DB_NAME|AUTH_KEY"), True),
    ("/config.php.bak", "high", "PHP Config Backup",
     "A configuration backup may expose credentials.", 7.5,
     ["exposure", "backup", "credentials"], re.compile(r"(password|passwd|secret)\s*[=']", re.I), True),
    ("/backup.zip", "medium", "Public Backup Archive",
     "A backup archive is downloadable from the web root.", 5.3,
     ["exposure", "backup"], None, True),
    ("/backup.tar.gz", "medium", "Public Backup Archive",
     "A backup archive is downloadable from the web root.", 5.3,
     ["exposure", "backup"], None, True),
    ("/backup.sql", "high", "Public Database Dump",
     "A SQL dump is downloadable from the web root.", 8.1,
     ["exposure", "database", "backup"], re.compile(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), True),
    ("/database.sql", "high", "Public Database Dump",
     "A SQL dump is downloadable from the web root.", 8.1,
     ["exposure", "database", "backup"], re.compile(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), True),
    ("/dump.sql", "high", "Public Database Dump",
     "A SQL dump is downloadable from the web root.", 8.1,
     ["exposure", "database", "backup"], re.compile(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), True),
    ("/db.sql", "high", "Public Database Dump",
     "A SQL dump is downloadable from the web root.", 8.1,
     ["exposure", "database", "backup"], re.compile(r"(CREATE TABLE|INSERT INTO|DROP TABLE)"), True),
    ("/error.log", "low", "Exposed Error Log",
     "Application error log is readable and may leak paths/secrets.", 4.3,
     ["exposure", "log"], None, True),
    ("/debug.log", "low", "Exposed Debug Log",
     "Debug log is readable and may leak sensitive internals.", 4.3,
     ["exposure", "log"], None, True),
    ("/docker-compose.yml", "medium", "Exposed docker-compose.yml",
     "Container configuration may disclose services and credentials.", 6.5,
     ["exposure", "config", "docker"], re.compile(r"(image:|services:|environment:)"), True),
    ("/Dockerfile", "low", "Exposed Dockerfile",
     "Build configuration may disclose internals.", 4.3,
     ["exposure", "docker"], re.compile(r"^(FROM|RUN|COPY)\s", re.M), True),
    ("/.vscode/sftp.json", "medium", "Exposed VS Code SFTP Config",
     "May contain deployment credentials.", 6.5,
     ["exposure", "credentials", "vscode"], re.compile(r"(host|username|password|privateKeyPath)"), True),
    ("/.idea/workspace.xml", "low", "Exposed JetBrains Project Config",
     "Project metadata may disclose internal paths.", 3.7,
     ["exposure", "idea"], None, True),
    ("/swagger-ui.html", "low", "Swagger UI Exposed",
     "API documentation is publicly reachable.", 3.7,
     ["exposure", "api", "swagger"], None, True),
    ("/swagger-ui/index.html", "low", "Swagger UI Exposed",
     "API documentation is publicly reachable.", 3.7,
     ["exposure", "api", "swagger"], None, True),
    ("/v2/api-docs", "medium", "Swagger API Docs Exposed",
     "Full API definition is downloadable.", 6.5,
     ["exposure", "api", "swagger"], re.compile(r'"swagger"|"openapi"'), True),
    ("/v3/api-docs", "medium", "OpenAPI Docs Exposed",
     "Full API definition is downloadable.", 6.5,
     ["exposure", "api", "openapi"], re.compile(r'"openapi"|"swagger"'), True),
    ("/openapi.json", "low", "OpenAPI Specification Exposed",
     "API definition is downloadable.", 3.7,
     ["exposure", "api", "openapi"], re.compile(r'"openapi"|"swagger"'), True),
    ("/api-docs", "medium", "API Documentation Exposed",
     "API documentation is downloadable.", 6.5,
     ["exposure", "api"], re.compile(r'"swagger"|"openapi"|"paths"'), True),
    ("/actuator", "medium", "Spring Boot Actuator Exposed",
     "Actuator endpoints may reveal internals and enable further attacks.", 5.3,
     ["exposure", "spring", "actuator"], re.compile(r"_links|actuator"), True),
    ("/actuator/env", "high", "Spring Boot Actuator Env Exposed",
     "Environment properties (often credentials) are exposed.", 8.1,
     ["exposure", "spring", "actuator", "credentials"], None, True),
    ("/actuator/heapdump", "critical", "Spring Boot Heap Dump Exposed",
     "Heap dump may contain secrets and session data.", 9.1,
     ["exposure", "spring", "actuator", "credentials"], None, True),
    ("/actuator/trace", "medium", "Spring Boot Actuator Trace Exposed",
     "Request traces may leak headers and tokens.", 5.3,
     ["exposure", "spring", "actuator"], None, True),
    ("/metrics", "low", "Metrics Endpoint Exposed",
     "Application metrics are publicly reachable.", 3.7,
     ["exposure", "metrics"], None, True),
    ("/graphql", "low", "GraphQL Endpoint Exposed",
     "GraphQL endpoint may allow introspection.", 3.7,
     ["exposure", "api", "graphql"], re.compile(r"__schema|GraphQL|query"), True),
    ("/graphiql", "low", "GraphiQL Console Exposed",
     "GraphQL IDE is publicly reachable.", 3.7,
     ["exposure", "api", "graphql"], None, True),
    ("/solr/", "medium", "Apache Solr Admin Exposed",
     "Solr admin interface is reachable.", 6.5,
     ["exposure", "solr"], None, True),
    ("/elasticsearch", "high", "Elasticsearch Exposed",
     "Elasticsearch cluster is publicly reachable.", 8.1,
     ["exposure", "elasticsearch"], re.compile(r'"cluster_name"|elasticsearch'), True),
    ("/kibana", "low", "Kibana Exposed",
     "Kibana dashboard is reachable.", 3.7,
     ["exposure", "kibana"], None, True),
    ("/grafana", "low", "Grafana Exposed",
     "Grafana dashboard is reachable.", 3.7,
     ["exposure", "grafana"], None, True),
    ("/jenkins", "medium", "Jenkins Exposed",
     "Jenkins server is reachable; may allow script console.", 6.5,
     ["exposure", "jenkins"], None, True),
    ("/jira", "low", "Jira Exposed",
     "Jira instance is reachable.", 3.7,
     ["exposure", "jira"], None, True),
    ("/gitlab", "low", "GitLab Exposed",
     "GitLab instance is reachable.", 3.7,
     ["exposure", "gitlab"], None, True),
    ("/phpmyadmin", "medium", "phpMyAdmin Exposed",
     "Database administration panel is reachable.", 6.5,
     ["exposure", "phpmyadmin", "database"], None, True),
    ("/pma", "medium", "phpMyAdmin Exposed",
     "Database administration panel is reachable.", 6.5,
     ["exposure", "phpmyadmin", "database"], None, True),
    ("/adminer.php", "medium", "Adminer Exposed",
     "Database administration tool is reachable.", 6.5,
     ["exposure", "adminer", "database"], None, True),
    ("/mysql", "medium", "MySQL Admin Exposed",
     "MySQL administration interface is reachable.", 6.5,
     ["exposure", "database"], None, True),
    ("/wp-admin/", "low", "WordPress Admin Exposed",
     "WordPress admin panel is reachable.", 3.7,
     ["exposure", "wordpress"], None, True),
    ("/wp-login.php", "low", "WordPress Login Exposed",
     "WordPress login page is reachable.", 3.7,
     ["exposure", "wordpress"], None, True),
    ("/xmlrpc.php", "medium", "WordPress xmlrpc.php Exposed",
     "xmlrpc enables brute-force and SSRF amplification.", 6.5,
     ["exposure", "wordpress", "xmlrpc"], re.compile(r"XML-RPC|xmlrpc"), True),
    ("/manager/html", "high", "Tomcat Manager Exposed",
     "Tomcat manager is reachable; may allow WAR deployment.", 8.1,
     ["exposure", "tomcat", "rce"], None, True),
    ("/host-manager/html", "medium", "Tomcat Host Manager Exposed",
     "Tomcat host manager is reachable.", 6.5,
     ["exposure", "tomcat"], None, True),
    ("/jmx-console/", "high", "JBoss JMX Console Exposed",
     "JMX console may allow MBean invocation / RCE.", 8.1,
     ["exposure", "jboss", "rce"], None, True),
    ("/web-console/", "medium", "WebLogic Console Exposed",
     "WebLogic admin console is reachable.", 6.5,
     ["exposure", "weblogic"], None, True),
    ("/console", "low", "Admin Console Exposed",
     "An administration console is reachable.", 3.7,
     ["exposure", "console"], None, True),
    ("/cgi-bin/", "low", "CGI Directory Exposed",
     "CGI directory is reachable.", 3.7,
     ["exposure", "cgi"], None, True),
    ("/crossdomain.xml", "low", "Permissive crossdomain.xml",
     "Flash cross-domain policy may be too permissive.", 3.7,
     ["exposure", "crossdomain", "flash"], re.compile(r"allow-access-from"), True),
    ("/clientaccesspolicy.xml", "low", "Permissive clientaccesspolicy.xml",
     "Silverlight cross-domain policy may be too permissive.", 3.7,
     ["exposure", "crossdomain"], re.compile(r"domain uri"), True),
    ("/robots.txt", "info", "robots.txt Exposed",
     "Search-engine directives reveal hidden paths.", 1.0,
     ["info-disclosure", "robots"], None, True),
    ("/sitemap.xml", "info", "Sitemap Exposed",
     "Sitemap reveals URL structure.", 1.0,
     ["info-disclosure", "sitemap"], None, True),
    ("/.well-known/security.txt", "info", "security.txt Exposed",
     "Security contact/policy file is reachable.", 1.0,
     ["info-disclosure", "security.txt"], None, True),
    ("/backup/", "medium", "Backup Directory Exposed",
     "A backup directory listing is reachable.", 6.5,
     ["exposure", "backup"], re.compile(r"Index of|backup", re.I), True),
    ("/old/", "low", "Old Directory Exposed",
     "An 'old' directory is reachable.", 3.7,
     ["exposure", "backup"], re.compile(r"Index of", re.I), True),
    ("/test/", "low", "Test Directory Exposed",
     "A test directory is reachable.", 3.7,
     ["exposure", "test"], re.compile(r"Index of", re.I), True),
    ("/dev/", "low", "Development Directory Exposed",
     "A development directory is reachable.", 3.7,
     ["exposure", "dev"], re.compile(r"Index of", re.I), True),
    ("/admin/", "info", "Admin Path Reachable",
     "An administration path responds.", 2.1,
     ["exposure", "admin"], None, False),
    ("/api/", "info", "API Path Reachable",
     "An API path responds.", 2.1,
     ["exposure", "api"], None, False),
]

_SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options"),
    ("strict-transport-security", "Strict-Transport-Security"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
]


def _add(findings: List[VulnResult], host: str, url: str, severity: str, name: str,
         desc: str, cvss: float, tags: List[str], evidence: str,
         matcher: Optional[str] = None, require_200: bool = False) -> None:
    findings.append(
        VulnResult(
            template_id=(matcher or name).strip("/").replace("/", "-")[:64] or "builtin",
            name=name,
            severity=severity,
            url=url,
            matched_at=host,
            description=desc,
            evidence=evidence[:600].replace("\n", " "),
            cvss=cvss,
            tags=tags,
        )
    )


def _check_landing(resp, host: str, base: str, findings: List[VulnResult]) -> None:
    if resp is None or resp.status_code >= 500:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text or ""
    shown = {f.template_id for f in findings}

    # Directory listing (skip when the landing page itself is a sensitive path).
    if re.search(r"<title>\s*Index of /", body, re.IGNORECASE) and base.rstrip("/").split("/")[-1] not in (
        "backup", "old", "test", "dev", "admin", "api", "logs", "files"
    ):
        _add(findings, host, base + "/", "medium", "Directory Listing Enabled",
             "The web server exposes a directory index.", 5.3,
             ["misconfiguration", "info-disclosure"], body[:300],
             "directory-listing")

    # Missing security headers.
    missing = [label for header, label in _SECURITY_HEADERS if header not in headers]
    if missing and "missing-security-headers" not in shown:
        _add(findings, host, base + "/", "low", "Missing Security Headers",
             "Security headers absent: " + ", ".join(missing), 3.7,
             ["headers", "misconfiguration"],
             f"HTTP {resp.status_code}; missing: {', '.join(missing)}",
             "missing-security-headers")

    # CORS misconfiguration.
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao and (acao.strip() == "*" or "evil" in acao.lower() or
                 (acao.strip().lower() not in ("", "null") and acac.lower() == "true")):
        _add(findings, host, base + "/", "medium", "Permissive CORS Configuration",
             f"Access-Control-Allow-Origin: {acao} (credentials: {acac or 'no'})",
             6.1, ["cors", "misconfiguration"],
             f"ACAO={acao}; ACAC={acac}", "cors-misconfiguration")

    # Cookie flags.
    set_cookie = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    for cookie in set_cookie:
        if cookie and ("httpOnly" not in cookie or "Secure" not in cookie):
            _add(findings, host, base + "/", "low", "Cookie Without HttpOnly/Secure",
                 "A session cookie is set without HttpOnly/Secure flags.", 3.7,
                 ["cookies", "misconfiguration"], cookie[:200], "cookie-flags")
            break

    # Outdated software from headers.
    for source in (headers.get("server", ""), headers.get("x-powered-by", "")):
        for pattern, severity, name, desc, cvss, tags in _OUTDATED_SOFTWARE:
            match = pattern.search(source)
            if match:
                _add(findings, host, base + "/", severity, name, desc, cvss, tags,
                     f"{source}", f"outdated-{name.lower().replace(' ', '-')}")

    # WordPress core version from generator meta.
    wp = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([0-9.]+)',
                   body, re.IGNORECASE)
    if wp and wp.group(1).startswith(("0.", "1.", "2.", "3.", "4.")):
        _add(findings, host, base + "/", "medium", "Outdated WordPress",
             f"WordPress {wp.group(1)} core is outdated.", 6.5,
             ["outdated", "wordpress"], wp.group(0)[:200], "outdated-wordpress")


def _behaviour_checks(client, host: str, base: str, findings: List[VulnResult]) -> None:
    # TRACE method.
    trace = client.request("TRACE", base + "/")
    if trace is not None and trace.status_code in (200, 405) and \
            trace.headers.get("allow", "").lower().find("trace") != -1:
        _add(findings, host, base + "/", "medium", "HTTP TRACE Enabled",
             "The TRACE method is allowed (XST / information disclosure).", 5.3,
             ["methods", "xst"], f"HTTP {trace.status_code}", "trace-enabled")
    elif trace is not None and trace.status_code == 200:
        _add(findings, host, base + "/", "medium", "HTTP TRACE Enabled",
             "The TRACE method is allowed (XST / information disclosure).", 5.3,
             ["methods", "xst"], f"HTTP {trace.status_code}", "trace-enabled")

    # Open redirect.
    for path in ("/login?redirect=https://evil.example/",
                 "/redirect?url=https://evil.example/",
                 "/logout?redirect=//evil.example/"):
        resp = client.get(base + path, follow_redirects=False)
        if resp is None:
            continue
        location = resp.headers.get("location", "")
        if "evil.example" in location:
            _add(findings, host, base + path, "medium", "Open Redirect",
                 "A redirect parameter is reflected in Location.", 6.1,
                 ["open-redirect", "validation"], f"Location: {location}",
                 "open-redirect")
            break

    # Reflected XSS probe.
    payload = "<script>ravenxssprobe()</script>"
    for path in ("/search?q=", "/index.php?q=", "/?s="):
        resp = client.get(base + path + payload.replace(">", "%3E").replace("<", "%3C"))
        if resp is not None and payload in (resp.text or ""):
            _add(findings, host, base + path + "<script>", "high",
                 "Reflected XSS (Probable)",
                 "The search parameter reflects input without encoding.", 7.8,
                 ["xss", "reflected"], f"Reflected payload: {payload}",
                 "reflected-xss")
            break

    # SQL error disclosure.
    for path in ("/index.php?id=1'", "/product?id=1'", "/news?id=1'"):
        resp = client.get(base + path)
        if resp is not None and _SQL_ERROR_RE.search(resp.text or ""):
            _add(findings, host, base + path, "high", "SQL Injection (Probable)",
                 "A SQL error message is disclosed for a malformed parameter.", 8.1,
                 ["sqli", "injection"], _SQL_ERROR_RE.search(resp.text).group(0)[:200],
                 "sqli-probable")
            break


def _builtin_scan(
    alive: List[SubdomainResult], ctx: ScanContext,
    endpoints: Optional[List] = None,
) -> List[VulnResult]:
    client = RateLimitedClient(rate_limit=ctx.settings.request_rate_limit)
    findings: List[VulnResult] = []
    max_hosts = ctx.settings.builtin_max_hosts
    max_findings = 500
    try:
        for host in alive[:max_hosts]:
            if len(findings) >= max_findings:
                break
            base = f"https://{host.subdomain}"
            landing = client.get(base + "/")
            if landing is None:
                base = f"http://{host.subdomain}"
                landing = client.get(base + "/")

            for path, severity, name, desc, cvss, tags, matcher, require_200 in _SENSITIVE_PATHS:
                if len(findings) >= max_findings:
                    break
                resp = client.get(base + path)
                if resp is None:
                    continue
                if require_200 and resp.status_code != 200:
                    continue
                if not require_200 and resp.status_code not in (200, 401, 403):
                    continue
                body = resp.text or ""
                if matcher and not matcher.search(body):
                    continue
                if not matcher and not require_200 and resp.status_code in (401, 403):
                    evidence = f"HTTP {resp.status_code} (panel reachable)"
                else:
                    evidence = body[:400]
                _add(findings, host.subdomain, base + path, severity, name, desc,
                     cvss, tags, evidence, path)

            _check_landing(landing, host.subdomain, base, findings)
            _behaviour_checks(client, host.subdomain, base, findings)

        # Outdated JS libraries / tech across discovered endpoints.
        for ep in (endpoints or [])[:40]:
            if len(findings) >= max_findings:
                break
            url = ep.url if hasattr(ep, "url") else str(ep)
            if not url.lower().split("?")[0].endswith((".js", ".mjs", ".jsx")):
                continue
            resp = client.get(url)
            if resp is None:
                continue
            for pattern, severity, name, desc, cvss, tags in _OUTDATED_SOFTWARE:
                match = pattern.search(resp.text or "")
                if match:
                    _add(findings, "js", url, severity, name, desc, cvss, tags,
                         match.group(0)[:200], f"outdated-{name.lower().replace(' ', '-')}")
    finally:
        client.close()
    # de-duplicate by (template_id, url)
    seen = set()
    unique: List[VulnResult] = []
    for f in findings:
        key = (f.template_id, f.url)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique[:max_findings]


def run(
    ctx: ScanContext, alive: List[SubdomainResult],
    endpoints: Optional[List] = None,
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
            # Merge with the built-in engine instead of replacing it: nuclei and
            # the Python checks cover different classes of issues.
            builtin = _builtin_scan(alive, ctx, endpoints)
            known = {(f.template_id, f.url) for f in findings}
            for item in builtin:
                if (item.template_id, item.url) not in known:
                    findings.append(item)
            ctx.logger.success(
                f"nuclei: {len(findings)} bulgu (nuclei + yerleşik kontroller)"
            )
            return findings, EngineReport(
                engine="nuclei", command=" ".join(cmd),
                detail=f"{len(findings)} bulgu (nuclei + builtin)"
            )
        ctx.logger.warning("nuclei bulgu döndürmedi, yerel taramaya geçiliyor")

    findings = _builtin_scan(alive, ctx, endpoints)
    ctx.logger.success(f"Yerel tarama: {len(findings)} bulgu")
    return findings, EngineReport(engine="builtin", detail=f"{len(findings)} bulgu")
