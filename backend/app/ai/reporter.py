"""Executive summary generation for the final report."""
from __future__ import annotations

from typing import Any, Dict, List

from app.ai.provider import LocalProvider, Provider

SUMMARY_SYSTEM = (
    "Sen bir siber güvenlik raporu yazarısın. Yönetim özeti yazarken "
    "teknik detayı sadece gerekirse verir, oyuncaklaştırılmış bir tablo çizersin. "
    "Yanıt Türkçe ve Markdown formatında olmalıdır."
)

SUMMARY_USER = """Hedef: {domain}
Tarama tipi: {scan_type}
Risk skoru: {risk}/100
Toplam alt alan: {subdomain_count} (canlı: {alive_count})
Toplam bulgu: {finding_count}
Motorlar: {engines}
{warning}
Bulgular:
{findings}

Görev:
1. 3-5 cümlelik Yönetim Özeti (hedefin genel güvenlik durumu).
2. "Düzeltme Öncelik Listesi" başlığı altında en kritik 5 maddeyi kısa ve aksiyon odaklı yaz.
3. False positive olarak işaretlenen bulguları belirtme.
Markdown kullan. Başlıklar ## ile.
"""


def _markdown_escape(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _engine_line(scan: Dict[str, Any]) -> str:
    engines = (scan.get("meta") or {}).get("engines") or {}
    if not engines:
        return ""
    order = ["recon", "liveness", "tls", "crawler", "vulnerability", "secrets"]
    labels = {
        "recon": "Alt alan keşfi", "liveness": "Canlılık/teknoloji",
        "tls": "TLS sertifikası", "crawler": "Tarama/endpoint",
        "vulnerability": "Zafiyet", "secrets": "Sır tespiti",
    }
    parts = [
        f"{labels.get(stage, stage)}: {engines[stage]}"
        for stage in order
        if engines.get(stage) and engines[stage] != "none"
    ]
    return "Kullanılan motorlar — " + ", ".join(parts) + "."


def _owasp_line(findings: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for f in findings:
        category = f.get("owasp_category")
        if category:
            counts[category] = counts.get(category, 0) + 1
    if not counts:
        return ""
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
    return "OWASP dağılımı — " + ", ".join(f"{k} ({v})" for k, v in ordered) + "."


def _local_summary(scan: Dict[str, Any], findings: List[Dict[str, Any]],
                   subdomains: List[Dict[str, Any]]) -> str:
    counts = _severity_counts(findings)
    real = [f for f in findings if not f.get("is_false_positive")]
    critical_high = [f for f in real if f.get("severity") in ("critical", "high")]
    alive = sum(1 for s in subdomains if s.get("is_alive"))

    lines = [
        "## Yönetim Özeti",
        "",
        f"`{scan.get('target_domain')}` hedefi için otomatik sızma testi tamamlandı. "
        f"Toplam **{len(subdomains)}** alt alan adı keşfedildi, bunların **{alive}** tanesi "
        f"canlı olarak doğrulandı. Tarama sonucunda **{len(findings)}** bulgu üretildi; "
        f"bunların **{len(real)}** tanesi false positive olarak filtrelendi.",
        "",
        f"Kritik **{counts['critical']}**, yüksek **{counts['high']}**, "
        f"orta **{counts['medium']}**, düşük **{counts['low']}** seviye bulgu mevcut. "
        f"Hedefin risk skoru **{scan.get('risk_score', 0)}/100** olarak hesaplandı.",
        "",
    ]
    engine_line = _engine_line(scan)
    if engine_line:
        lines += [engine_line, ""]
    owasp_line = _owasp_line(findings)
    if owasp_line:
        lines += [owasp_line, ""]
    if (scan.get("meta") or {}).get("warning") == "no_findings":
        lines += [
            "> ⚠️ Bu tarama 0 bulgu üretti. Hedef erişilebilir olmayabilir, "
            "tarayıcı binary'leri kurulu olmayabilir veya hedef gerçekten temiz "
            "olabilir. Motor durumu yukarıda belirtildiği gibidir.",
            "",
        ]
    lines += ["## Düzeltme Öncelik Listesi", ""]
    if critical_high:
        for i, f in enumerate(critical_high[:5], start=1):
            lines.append(
                f"{i}. **{_markdown_escape(str(f.get('title')))}** "
                f"({_markdown_escape(str(f.get('severity')))}) — "
                f"`{_markdown_escape(str(f.get('url') or ''))}`"
            )
    else:
        lines.append("1. Kritik/yüksek seviye bulgu yok; orta seviye bulguları takip edin.")
    lines += [
        "",
        "> Bu özet RAVEN'in yerel analiz motoru tarafından üretildi. "
        "LLM tabanlı analiz için OpenAI anahtarı veya Ollama yapılandırın.",
    ]
    return "\n".join(lines)


def generate_executive_summary(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    subdomains: List[Dict[str, Any]],
    provider: Provider,
    logger=None,
) -> str:
    if isinstance(provider, LocalProvider):
        return _local_summary(scan, findings, subdomains)

    real = [f for f in findings if not f.get("is_false_positive")]
    ordered = sorted(
        real,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            str(f.get("severity")).lower(), 9
        ),
    )
    engines = (scan.get("meta") or {}).get("engines") or {}
    engine_text = ", ".join(
        f"{stage}={engine}" for stage, engine in engines.items() if engine != "none"
    ) or "belirtilmedi"
    warning = (scan.get("meta") or {}).get("warning")
    user = SUMMARY_USER.format(
        domain=scan.get("target_domain"),
        scan_type=scan.get("scan_type"),
        risk=scan.get("risk_score", 0),
        subdomain_count=len(subdomains),
        alive_count=sum(1 for s in subdomains if s.get("is_alive")),
        finding_count=len(findings),
        engines=engine_text,
        warning=(
            "Bu tarama 0 bulgu üretti (motorlar yukarıda); bunu özette açıkça belirt."
            if warning == "no_findings" else ""
        ),
        findings="\n".join(
            f"- [{f.get('severity')}] {f.get('title')} — {f.get('url')} "
            f"(CVSS {f.get('cvss')})"
            for f in ordered[:30]
        ) or "- (bulgu yok)",
    )
    try:
        text = provider.complete(SUMMARY_SYSTEM, user)
        if text and text.strip():
            return text.strip()
    except Exception as exc:
        if logger:
            logger.warning(f"Özet üretilemedi ({provider.name}): {exc}; yerel özet kullanılacak")
    return _local_summary(scan, findings, subdomains)
