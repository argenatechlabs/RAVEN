"""Transport-layer / TLS health checks.

Pure-stdlib TLS inspection: protocol versions, certificate validity window,
self-signed certificates and hostname mismatches. Runs only against hosts that
already answered HTTPS, so it is cheap and safe to include in every scan.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List, Tuple
from urllib.parse import urlparse

from app.scanners.common import EngineReport
from app.scanners.context import ScanContext
from app.scanners.types import SubdomainResult, VulnResult

# Hosts that were already probed over HTTPS (scheme is remembered by the tech
# stage through the ``ports`` field: 443 == https).
_HTTPS_PORT = 443


def _host_port(subdomain: str) -> Tuple[str, int]:
    if ":" in subdomain:
        host, _, port = subdomain.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return subdomain, _HTTPS_PORT
    return subdomain, _HTTPS_PORT


def _connect(host: str, port: int, version: ssl.TLSVersion, timeout: float):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except (ValueError, AttributeError):  # pragma: no cover - platform dependent
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return cert, tls.version()
    except (ssl.SSLError, OSError, socket.timeout, ValueError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _check_host(host: str, port: int) -> List[VulnResult]:
    findings: List[VulnResult] = []
    url = f"https://{host}" + (f":{port}" if port != _HTTPS_PORT else "")

    # Certificate inspection with a normal, verifying context.
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6.0)
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            raw = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", "") or str(exc)
        findings.append(
            VulnResult(
                template_id="tls-certificate-invalid",
                name="Invalid TLS Certificate",
                severity="medium",
                url=url,
                matched_at=host,
                description=f"TLS certificate could not be verified: {reason[:200]}",
                evidence=reason[:400],
                cvss=5.3,
                tags=["tls", "certificate", "misconfiguration"],
            )
        )
        return findings
    except (ssl.SSLError, OSError, socket.timeout, ValueError):
        return findings
    finally:
        try:
            sock.close()
        except OSError:
            pass

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days = (expiry - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(
                    VulnResult(
                        template_id="tls-certificate-expired",
                        name="Expired TLS Certificate",
                        severity="high",
                        url=url,
                        matched_at=host,
                        description=f"Certificate expired {abs(days)} days ago.",
                        evidence=f"notAfter={not_after}",
                        cvss=7.4,
                        tags=["tls", "certificate"],
                    )
                )
            elif days < 30:
                findings.append(
                    VulnResult(
                        template_id="tls-certificate-expiring",
                        name="TLS Certificate Expiring Soon",
                        severity="low",
                        url=url,
                        matched_at=host,
                        description=f"Certificate expires in {days} days.",
                        evidence=f"notAfter={not_after}",
                        cvss=3.7,
                        tags=["tls", "certificate"],
                    )
                )
        except (ValueError, TypeError):
            pass

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    if issuer.get("organizationName") == subject.get("organizationName") and \
            issuer.get("commonName") == subject.get("commonName"):
        findings.append(
            VulnResult(
                template_id="tls-self-signed",
                name="Self-Signed TLS Certificate",
                severity="medium",
                url=url,
                matched_at=host,
                description="The server presents a self-signed certificate.",
                evidence=f"issuer={issuer}",
                cvss=5.3,
                tags=["tls", "certificate", "misconfiguration"],
            )
        )

    # Deprecated protocol versions.
    for version, name, severity, cvss in (
        (ssl.TLSVersion.TLSv1, "TLS 1.0", "medium", 5.3),
        (ssl.TLSVersion.TLSv1_1, "TLS 1.1", "medium", 5.3),
    ):
        result = _connect(host, port, version, timeout=5.0)
        if result is not None:
            findings.append(
                VulnResult(
                    template_id=f"tls-{name.lower().replace(' ', '-')}-enabled",
                    name=f"{name} Enabled",
                    severity=severity,
                    url=url,
                    matched_at=host,
                    description=f"The server still negotiates {name}.",
                    evidence=f"negotiated={name}",
                    cvss=cvss,
                    tags=["tls", "protocol", "misconfiguration"],
                )
            )
    return findings


def run(
    ctx: ScanContext, alive: List[SubdomainResult]
) -> Tuple[List[VulnResult], EngineReport]:
    """Inspect HTTPS hosts. Non-HTTPS hosts are skipped silently."""
    if not alive:
        return [], EngineReport(engine="none", detail="canlı host yok")
    if ctx.settings.demo_mode:
        return [], EngineReport(engine="demo", detail="sentetik veri")

    findings: List[VulnResult] = []
    checked = 0
    for host in alive[: ctx.settings.builtin_max_hosts]:
        if _HTTPS_PORT not in (host.ports or []):
            continue
        name, port = _host_port(host.subdomain)
        if not name:
            continue
        findings.extend(_check_host(name, port))
        checked += 1
    ctx.logger.info(f"TLS kontrolü: {checked} HTTPS host")
    return findings, EngineReport(engine="builtin-tls", detail=f"{checked} host")
