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


# --- Extra wordlist for the pure-Python DNS brute force ----------------------
# The built-in list is intentionally broad; subfinder remains the primary engine.
EXTRA_SUBDOMAINS = [
    "www2", "www3", "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "pop", "imap", "owa", "autodiscover", "sip", "lyncdiscover", "meet",
    "zoom", "vdi", "rdp", "citrix", "terminal", "thinclient", "office",
    "exchange", "ews", "mapi", "hybrid", "o365", "login-microsoftonline",
    "azure", "aws", "gcp", "s3", "s3-eu-west-1", "ec2", "eks", "lambda",
    "elasticbeanstalk", "cloudfront", "cdn1", "cdn2", "img", "images",
    "media", "video", "download", "dl", "files", "share", "fileshare",
    "sync", "backup", "storage", "minio", "s3-internal", "sftp", "scp",
    "npm", "pypi", "maven", "artifactory", "nexus", "harbor", "registry",
    "docker", "k8s", "kube", "openshift", "rancher", "vault", "consul",
    "nomad", "terraform", "argocd", "spinnaker", "cd", "ci", "ci-cd",
    "build", "buildkite", "travis", "circleci", "bamboo", "teamcity",
    "sonar", "sonarqube", "nagios", "zabbix", "prometheus", "alertmanager",
    "loki", "jaeger", "zipkin", "consul-ui", "traefik", "nginx", "haproxy",
    "pm2", "netdata", "cockpit", "minio-console", "pgadmin", "phpmyadmin",
    "dba", "mysql-admin", "sql", "sqlserver", "oracle", "mongo", "mongodb",
    "redisinsight", "rabbitmq", "kafka", "kafka-ui", "elastic", "opensearch",
    "logstash", "kibana", "opensearch-dashboards", "sentry", "bugsnag",
    "datadog", "newrelic", "pagerduty", "opsgenie", "status", "statuspage",
    "helpdesk", "servicedesk", "ticket", "tickets", "support", "kb", "wiki",
    "confluence", "notion", "sharepoint", "teams", "slack", "chat", "im",
    "mattermost", "rocket", "discourse", "forum", "community", "community2",
    "forum2", "discuss", "feedback", "survey", "form", "forms", "signup",
    "register", "account", "accounts", "my", "myaccount", "profile",
    "customer", "customers", "client", "clients", "clientes", "portal2",
    "partner", "partners", "affiliate", "affiliates", "reseller", "resellers",
    "vendor", "vendors", "supplier", "suppliers", "buyer", "buyers", "pay",
    "payment", "payments", "billing", "invoice", "invoices", "checkout",
    "cart", "store", "stores", "ecommerce", "eshop", "webshop", "pos",
    "loyalty", "coupons", "offers", "deals", "promo", "promotions", "campaign",
    "marketing", "ads", "adserver", "tracking", "analytics", "gtm",
    "stats", "metrics", "reports", "report", "bi", "dashboards", "kpi",
    "crm", "erp", "sap", "hr", "hrm", "payroll", "finance", "accounting",
    "legal", "compliance", "risk", "audit", "soc", "siem", "soc2", "pentest",
    "bugbounty", "security", "secure2", "vpn2", "wifi", "radius", "ldap",
    "ad", "adfs", "saml", "okta", "auth0", "keycloak", "identity",
    "identity-provider", "idp", "sso2", "onelogin", "ping", "pingidentity",
    "duo", "mfa", "otp", "totp", "recover", "recovery", "reset",
    "password-reset", "unlock", "verify", "verification", "confirm",
    "activation", "activate", "invitation", "invite", "join", "recruit",
    "careers", "jobs", "job", "apply", "intern", "internship", "campus",
    "training", "learn", "learning", "academy", "university", "school",
    "education", "course", "courses", "elearning", "lms", "moodle",
    "canvas", "blackboard", "classroom", "student", "students", "teacher",
    "faculty", "library", "catalog", "search", "browse", "explore",
    "news", "newsletter", "press", "media2", "pr", "brand", "brands",
    "events", "event", "calendar", "schedule", "booking", "bookings",
    "reservation", "reservations", "ticket2", "tickets2", "cinema",
    "movie", "movies", "tv", "radio", "music", "audio", "podcast",
    "photo", "photos", "gallery", "album", "albums", "camera", "live",
    "live2", "stream", "streaming", "cast", "webcam", "cam", "monitor",
    "remote2", "access", "access2", "entry", "gateway2", "gw2", "edge2",
    "core", "core2", "main", "main2", "primary", "secondary", "dr",
    "dr-site", "failover", "ha", "cluster", "node", "node1", "node2",
    "worker", "worker1", "queue", "worker2", "scheduler", "cron",
    "batch", "etl", "pipeline", "airflow", "dagster", "prefect", "luigi",
    "ml", "mlflow", "jupyter", "notebook", "colab", "gpu", "ai", "ml-api",
    "inference", "training2", "models", "dataset", "datasets", "data",
    "data2", "lake", "warehouse", "dwh", "olap", "oltp", "bigdata",
    "hadoop", "spark", "hive", "presto", "trino", "flink", "storm",
    "druid", "pinot", "clickhouse", "cassandra", "hbase", "neo4j",
    "couchdb", "riak", "etcd", "zookeeper", "nats", "pulsar", "rabbitmq",
    "activemq", "mq", "queue2", "worker3", "scheduler2", "cron2",
]


def run(ctx: ScanContext) -> Tuple[List[str], EngineReport]:
    """Return a deduplicated list of discovered subdomains."""
    out_file = os.path.join(ctx.workdir, "subdomains.txt")
    binary = resolve_binary("subfinder", ctx.settings)
    subs: List[str] = []

    if ctx.settings.demo_mode:
        subs = _demo_subdomains(ctx.domain)
        write_lines(out_file, subs)
        ctx.logger.info(f"[DEMO] {len(subs)} subdomain bulundu")
        return subs, EngineReport(engine="demo", detail="sentetik veri")
    if ctx.expired():
        return subs, EngineReport(engine="timeout", detail="tarama süresi doldu")

    if binary:
        cmd = [binary, "-d", ctx.domain, "-silent", "-all", "-o", out_file]
        if not ctx.deep:
            cmd.remove("-all")
        ctx.logger.info(f"subfinder çalıştırılıyor: {ctx.domain}")
        result = run_cmd(cmd, timeout=ctx.command_timeout(), cwd=ctx.workdir)
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

    # Local target (host:port) — no subdomain brute force possible.
    if ":" in ctx.domain:
        host = ctx.domain.split(":", 1)[0]
        write_lines(out_file, [ctx.domain])
        ctx.logger.success(f"Yerel hedef: {ctx.domain}")
        return [ctx.domain], EngineReport(engine="builtin-dns", detail="yerel hedef")

    # --- Pure-Python fallback: DNS brute force over a common-name list ------
    ctx.logger.info("Yerel DNS keşfi çalışıyor (ortak alt alan adları)")
    found: List[str] = []
    names = list(dict.fromkeys([*COMMON_SUBDOMAINS, *EXTRA_SUBDOMAINS]))
    if not ctx.deep:
        # fast mode: keep the probe budget reasonable (~150 DNS lookups)
        names = names[:150]
    for name in names:
        host = f"{name}.{ctx.domain}"
        if resolve_host(host):
            found.append(host)
    found = sorted({ctx.domain, *found})
    write_lines(out_file, found)
    ctx.logger.success(f"DNS keşfi: {len(found)} host çözümlendi")
    return found[: ctx.settings.max_subdomains], EngineReport(
        engine="builtin-dns", detail=f"{len(found)} host"
    )
