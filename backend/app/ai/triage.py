"""AI triage: analyse scanner findings, drop false positives, assign severity,
CVSS, an exploit scenario and a fix snippet."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.ai.provider import LocalProvider, Provider

SYSTEM_PROMPT = (
    "Sen kıdemli bir penetration testi uzmanısın (OSCP/OSWE seviyesinde). "
    "Güvenlik taraması bulgularını analiz edersin, false positive'leri eleersin "
    "ve düzeltme önerisi sunarsın. Yanıtın Türkçe olmalıdır. "
    "KESİNLİKLE geçerli JSON döndür, başka metin yazma."
)

USER_TEMPLATE = """Aşağıda {count} adet tarama bulgusu var. Her biri için analiz yap.

Bulgular (index ile eşleştir):
{findings}

SADECE şu anahtarlara sahip JSON dizisi döndür (başka metin yazma):
[
  {{
    "index": 0,
    "severity": "critical|high|medium|low",
    "is_false_positive": false,
    "confidence": 0.85,
    "reason": "neden gerçek/false positive olduğunu 2-3 cümleyle açıkla",
    "cvss": 8.5,
    "exploit_scenario": "tek cümlelik sömürü senaryosu",
    "fix_code": "çözüm kodu veya yapılandırması",
    "owasp_category": "A03:2021-Injection"
  }}
]

Kurallar:
- False positive'leri (generic eşleşme, etkisiz/eski ama zararsız ipucu) is_false_positive=true yap.
- Gerçek tehlikeleri critical/high yap.
- cvss 0.0-10.0 arasında sayı olsun.
- confidence 0.0-1.0 arasında, tespite olan güvenin.
- owasp_category OWASP Top 10 2021 kodunu kullan (ör. A03:2021-Injection).
- SADECE JSON döndür; açıklama yazma.
"""


@dataclass
class TriageResult:
    severity: str
    is_false_positive: bool
    reason: str
    cvss: Optional[float]
    exploit_scenario: str
    fix_code: str
    owasp_category: Optional[str]
    provider: str
    confidence: float = 0.5
    attempts: int = 1


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_CVSS = {"critical": 9.1, "high": 7.8, "medium": 5.5, "low": 3.1, "info": 0.0}

OWASP_RULES = [
    (("sqli", "sql", "injection", "rce", "lfi", "rfi", "path-traversal", "deserialization", "xxe"),
     "A03:2021-Injection"),
    (("xss", "csrf"), "A03:2021-Injection"),
    (("auth", "jwt", "session", "login", "sso", "password"),
     "A07:2021-Identification and Authentication Failures"),
    (("exposure", "git", "env", "backup", "info-disclosure", "phpinfo", "actuator",
      "source-code", "credentials"),
     "A05:2021-Security Misconfiguration"),
    (("cve", "outdated", "version", "jquery", "wordpress"),
     "A06:2021-Vulnerable and Outdated Components"),
    (("headers", "csp", "cors", "misconfiguration", "ssl", "tls"),
     "A05:2021-Security Misconfiguration"),
    (("ssrf",), "A10:2021-Server-Side Request Forgery"),
    (("secret", "token", "api-key", "api key", "access key", "aws", "stripe",
      "private key", "jwt"), "A02:2021-Cryptographic Failures"),
]
DEFAULT_OWASP = "A05:2021-Security Misconfiguration"


def _owasp_for(title: str, tags: List[str]) -> Optional[str]:
    haystack = (title + " " + " ".join(tags)).lower()
    for needles, code in OWASP_RULES:
        if any(n in haystack for n in needles):
            return code
    return DEFAULT_OWASP


def _fix_code(title: str, tags: List[str]) -> str:
    haystack = (title + " " + " ".join(tags)).lower()
    if "header" in haystack or "csp" in haystack or "cors" in haystack:
        return (
            "# Nginx — güvenlik başlıkları\n"
            "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
            "add_header X-Frame-Options \"DENY\" always;\n"
            "add_header Strict-Transport-Security \"max-age=63072000\" always;\n"
            "add_header X-Content-Type-Options \"nosniff\" always;"
        )
    if "git" in haystack or "env" in haystack or "backup" in haystack:
        return (
            "# Nginx — hassas dosyaları engelle\n"
            "location ~* /(\\.|backup|env) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n"
            "# Ayrıca dosyayı sunucudan kaldırın ve git geçmişini temizleyin."
        )
    if "phpinfo" in haystack:
        return "phpinfo sayfasını üretimden kaldırın; gerekirse IP allowlist ile sınırlandırın."
    if "auth" in haystack or "jwt" in haystack or "login" in haystack:
        return (
            "# Örnek: Flask-JWT güçlendirme\n"
            "JWT_ALGORITHM = 'HS256'\n"
            "JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)\n"
            "# Refresh token + httpOnly cookie + rate limit + MFA uygulayın."
        )
    if "wordpress" in haystack or "jquery" in haystack or "outdated" in haystack:
        return (
            "Bileşenleri güncelleyin (WordPress çekirdek + eklentiler + tema).\n"
            "Eklentileri gereksizse kaldırın; güncelleyemediğiniz eklentiler için WAF kuralı ekleyin."
        )
    return (
        "Girdi doğrulaması + çıktı kodlama uygulayın, en az ayrıcalık ilkesine geçin,\n"
        "bileşenleri güncel tutun ve erişim günlüklerini SOC'a iletin."
    )


def local_analysis(finding: Dict[str, Any]) -> TriageResult:
    """Deterministic fallback used when no LLM provider is configured."""
    severity = str(finding.get("severity") or "info").lower()
    if severity not in SEVERITY_CVSS:
        severity = "info"
    title = str(finding.get("title") or "")
    tags = list(finding.get("tags") or [])
    fp = False
    cvss = finding.get("cvss")
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    if cvss is None:
        cvss = SEVERITY_CVSS[severity]
    reason = (
        f"{title} bulgusu {severity} seviyesinde değerlendirildi. "
        + ("False positive olarak işaretlendi (düşük etki / generic eşleşme). "
           if fp else
           "Hedef sistemde doğrulandı; sömürü için kullanılabilir bir yüzey tespit edildi. ")
        + "Otomatik yerel analiz ile üretildi."
    )
    if fp:
        exploit = "—"
        fix_code = _fix_code(title, tags)
    else:
        exploit = (
            "Saldırgan, bulguya konu bileşeni/endpoint'i doğrudan istismar ederek "
            "yetkisiz erişim veya veri sızdırma sağlayabilir."
        )
        fix_code = _fix_code(title, tags)
    return TriageResult(
        severity=severity,
        is_false_positive=fp,
        reason=reason,
        cvss=cvss,
        exploit_scenario=exploit,
        fix_code=fix_code,
        owasp_category=_owasp_for(title, tags) if not fp else None,
        provider="local",
        confidence=0.6 if fp else 0.5,
    )


def _extract_json_array(text: str) -> Optional[List[Dict[str, Any]]]:
    text = text.strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end > start:
        try:
            parsed = json.loads(text[start : end + 1])
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return None
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return [json.loads(text[start : end + 1])]
        except json.JSONDecodeError:
            return None
    return None


def _coerce_severity(value: Any, default: str) -> str:
    value = str(value or "").lower()
    return value if value in SEVERITY_CVSS else default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "1", "yes", "evet")


def _coerce_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, confidence))


def _coerce_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def triage_findings(
    findings: List[Dict[str, Any]],
    provider: Provider,
    logger=None,
    max_per_request: int = 25,
) -> Dict[int, TriageResult]:
    """Analyse findings and return a mapping ``finding_id -> TriageResult``."""
    results: Dict[int, TriageResult] = {}
    if not findings:
        return results

    for finding in findings:
        results[int(finding["id"])] = local_analysis(finding)

    if isinstance(provider, LocalProvider):
        if logger:
            logger.info("AI triage: yerel analiz motoru kullanılıyor (API anahtarı yok)")
        return results

    batches = [findings[i : i + max_per_request] for i in range(0, len(findings), max_per_request)]
    applied = 0
    for batch in batches:
        payload = [
            {
                "index": idx,
                "title": f.get("title"),
                "severity": f.get("severity"),
                "url": f.get("url"),
                "evidence": (f.get("evidence") or "")[:800],
                "tags": f.get("tags") or [],
            }
            for idx, f in enumerate(batch)
        ]
        user = USER_TEMPLATE.format(
            count=len(batch),
            findings=json.dumps(payload, ensure_ascii=False, indent=1),
        )
        parsed = None
        attempts = 0
        for attempt in range(2):
            attempts = attempt + 1
            prompt = user
            if attempt:
                prompt = (
                    user + "\n\nÖnceki yanıtın geçerli JSON değildi. "
                    "SADECE geçerli JSON dizisi döndür, başka metin yazma."
                )
            try:
                raw = provider.complete(SYSTEM_PROMPT, prompt)
            except Exception as exc:
                if logger:
                    logger.warning(f"AI triage isteği başarısız ({provider.name}): {exc}")
                parsed = None
                break
            parsed = _extract_json_array(raw)
            if parsed:
                break
            if logger:
                logger.warning(
                    f"AI yanıtı parse edilemedi ({provider.name}), "
                    f"yeniden deneme {attempts}/2"
                )
        if not parsed:
            if logger:
                logger.warning(f"AI yanıtı alınamadı ({provider.name}); yerel analze dönülüyor")
            continue
        by_index = {}
        for item in parsed:
            if not isinstance(item, dict):
                continue
            idx = item.get("index")
            if isinstance(idx, int) and 0 <= idx < len(batch):
                by_index[idx] = item
            elif "id" in item:
                by_index.setdefault(int(item["id"]), item)
        for idx, finding in enumerate(batch):
            item = by_index.get(idx)
            if not item:
                continue
            default_sev = str(finding.get("severity") or "info").lower()
            severity = _coerce_severity(item.get("severity"), default_sev)
            results[int(finding["id"])] = TriageResult(
                severity=severity,
                is_false_positive=_coerce_bool(item.get("is_false_positive")),
                reason=str(item.get("reason") or "").strip() or "AI analizi uygulandı.",
                cvss=_coerce_float(item.get("cvss")),
                exploit_scenario=str(item.get("exploit_scenario") or "").strip(),
                fix_code=str(item.get("fix_code") or "").strip(),
                owasp_category=item.get("owasp_category"),
                provider=provider.name,
                confidence=_coerce_confidence(item.get("confidence")),
                attempts=attempts,
            )
            applied += 1
    if logger:
        if applied == 0 and findings:
            logger.warning(
                f"{provider.name} yanıt vermedi; {len(results)} bulgu yerel analizle dolduruldu"
            )
        else:
            logger.success(
                f"AI triage tamamlandı ({provider.name}): "
                f"{applied}/{len(results)} bulgu LLM ile analiz edildi"
            )
    return results
