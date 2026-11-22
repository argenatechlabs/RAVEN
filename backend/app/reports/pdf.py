"""Professional PDF report generation (reportlab)."""
from __future__ import annotations

import io
import os
import re
from typing import Any, Dict, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# --- Theme -------------------------------------------------------------------
BG_DARK = colors.HexColor("#0a0a0a")
NEON = colors.HexColor("#00ff41")
NEON_DIM = colors.HexColor("#00b32d")
GREY = colors.HexColor("#6b7280")
LIGHT = colors.HexColor("#f4f4f5")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#16a34a"),
    "info": colors.HexColor("#6b7280"),
}

_TR_MAP = str.maketrans({
    "ç": "c", "Ç": "C", "ğ": "g", "Ğ": "G", "ı": "i", "I": "I",
    "İ": "i", "ö": "o", "Ö": "O", "ş": "s", "Ş": "S", "ü": "u", "Ü": "U",
    "–": "-", "—": "-", "’": "'", "‘": "'", "“": '"', "”": '"',
})


def _s(text: Any) -> str:
    """Keep Turkish glyphs when a TrueType font is available.

    The base-14 fonts have no Turkish coverage, so in that fallback the text is
    transliterated; with DejaVu registered (the Docker image installs it) the
    original characters are kept.
    """
    if _TTF_OK:
        return str(text if text is not None else "")
    return str(text if text is not None else "").translate(_TR_MAP)


def _clip(text: Any, limit: int = 160) -> str:
    """Trim evidence at a word boundary so the report does not end mid-token."""
    value = " ".join(str(text or "").split())
    if len(value) <= limit:
        return value
    return value[:limit].rsplit(" ", 1)[0] + " …"


def _clip_block(text: Any, limit: int = 4000) -> str:
    """Trim a preformatted block on a line boundary instead of mid-tag."""
    value = str(text or "")
    if len(value) <= limit:
        return value
    return value[:limit].rsplit("\n", 1)[0] + "\n…"


_FONT_REGISTERED = False
_TTF_OK = False
FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"


def _mono_font() -> str:
    """Prefer the monospace face that actually carries Turkish glyphs."""
    if _TTF_OK:
        from reportlab.pdfbase import pdfmetrics

        for name in ("RavenMono", "DejaVuSansMono", "Courier"):
            if name in pdfmetrics.getRegisteredFontNames():
                return name
    return "Courier"


def _register_fonts() -> bool:
    """Best-effort TrueType registration so Turkish glyphs render natively.

    Falls back to the transliteration in ``_s`` when no font is installed.
    """
    global _FONT_REGISTERED, _TTF_OK
    if _FONT_REGISTERED:
        return _TTF_OK
    _FONT_REGISTERED = True
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ]
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    normal = next((path for path in candidates if os.path.exists(path)), None)
    bold = normal.replace("DejaVuSans.ttf", "DejaVuSans-Bold.ttf") if normal else None
    if not normal or not os.path.exists(bold):
        return False
    mono = normal.replace("DejaVuSans.ttf", "DejaVuSansMono.ttf")
    try:
        pdfmetrics.registerFont(TTFont("RavenSans", normal))
        pdfmetrics.registerFont(TTFont("RavenSans-Bold", bold))
        if os.path.exists(mono):
            pdfmetrics.registerFont(TTFont("RavenMono", mono))
    except Exception:  # pragma: no cover - platform dependent
        return False
    global FONT, FONT_BOLD
    FONT = "RavenSans"
    FONT_BOLD = "RavenSans-Bold"
    _TTF_OK = True
    return True


def _p(text: Any, style) -> Paragraph:
    escaped = escape(_s(text))
    # Minimal Markdown: **bold** -> <b>
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    return Paragraph(escaped, style)


def _header_footer(canvas, doc) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(BG_DARK)
    canvas.rect(0, 0, width, height, stroke=0, fill=1)
    canvas.setFillColor(NEON)
    canvas.setFont("RavenSans-Bold" if _TTF_OK else "Helvetica-Bold", 8)
    canvas.drawString(18 * mm, height - 12 * mm, "RAVEN // AUTONOMOUS AI PENTESTER")
    canvas.setStrokeColor(NEON_DIM)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
    canvas.setFillColor(GREY)
    canvas.setFont("RavenSans" if _TTF_OK else "Helvetica", 7)
    canvas.drawString(18 * mm, 10 * mm, "Gizli — Yetkili personele özel")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Sayfa {doc.page}")
    canvas.restoreState()


def _styles() -> dict:
    base = getSampleStyleSheet()
    _register_fonts()
    font = FONT
    font_bold = FONT_BOLD
    styles = {
        "title": ParagraphStyle(
            "rav-title", parent=base["Title"], fontName=font_bold,
            fontSize=26, textColor=NEON, leading=30, alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "rav-sub", parent=base["Normal"], fontName=font,
            fontSize=11, textColor=colors.white, leading=15,
        ),
        "h2": ParagraphStyle(
            "rav-h2", parent=base["Heading2"], fontName=font_bold,
            fontSize=14, textColor=NEON, leading=18, spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "rav-body", parent=base["Normal"], fontName=font,
            fontSize=9.5, textColor=LIGHT, leading=14,
        ),
        "cell": ParagraphStyle(
            "rav-cell", parent=base["Normal"], fontName=font,
            fontSize=8.5, textColor=LIGHT, leading=11,
        ),
        "mono": ParagraphStyle(
            "rav-mono", parent=base["Normal"], fontName=_mono_font(),
            fontSize=8, textColor=colors.HexColor("#d1fae5"), leading=10.5,
            wordWrap="CJK", splitLongWords=1,
        ),
    }
    return styles


def _md_to_flowables(markdown: str, styles: dict) -> list:
    """Render the small Markdown subset used by the summary into flowables."""
    flow = []
    for raw in (markdown or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            flow.append(Spacer(1, 4))
            continue
        if line.startswith("## "):
            flow.append(_p(line[3:], styles["h2"]))
        elif line.startswith("# "):
            flow.append(_p(line[2:], styles["h2"]))
        elif line.strip() == "---":
            flow.append(Spacer(1, 6))
        elif line.startswith(("- ", "* ")):
            flow.append(_p("• " + line[2:], styles["body"]))
        else:
            flow.append(_p(line, styles["body"]))
    return flow


def render_pdf(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    subdomains: List[Dict[str, Any]],
    executive_summary: str,
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=16 * mm,
        title=f"RAVEN Rapor - {scan.get('target_domain')}",
        author="RAVEN Autonomous AI Pentester",
    )
    styles = _styles()
    story: list = []

    # --- Cover ---------------------------------------------------------------
    story.append(Spacer(1, 10 * mm))
    story.append(_p("RAVEN", styles["title"]))
    story.append(_p("Autonomous AI Pentester — Sızma Testi Raporu", styles["subtitle"]))
    story.append(Spacer(1, 6 * mm))
    meta_rows = [
        ["Hedef", _s(scan.get("target_domain"))],
        ["Tarama Tipi", _s(scan.get("scan_type"))],
        ["Durum", _s(scan.get("status"))],
        ["Risk Skoru", f"{scan.get('risk_score', 0)} / 100"],
    ]
    ai_meta = (scan.get("meta") or {}).get("ai") or {}
    if ai_meta.get("provider"):
        meta_rows.append([
            "AI Motoru",
            f"{_s(ai_meta.get('provider'))} · {_s(ai_meta.get('model') or '-')}",
        ])
    meta_rows += [
        ["Başlangıç", _s(scan.get("created_at"))],
        ["Bitiş", _s(scan.get("completed_at") or "-")],
    ]
    meta = Table(meta_rows, colWidths=[35 * mm, 120 * mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (0, -1), NEON),
        ("FONTNAME", (0, 0), (0, -1), FONT_BOLD),
        ("FONTNAME", (1, 0), (1, -1), FONT),
        ("TEXTCOLOR", (1, 0), (1, -1), LIGHT),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#262626")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta)
    story.append(Spacer(1, 6 * mm))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    sev_rows = [["Kritik", "Yüksek", "Orta", "Düşük", "Bilgi", "Toplam"]]
    sev_rows.append([
        str(counts["critical"]), str(counts["high"]), str(counts["medium"]),
        str(counts["low"]), str(counts["info"]), str(len(findings)),
    ])
    sev_table = Table(sev_rows, colWidths=[26 * mm] * 6)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), NEON),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TEXTCOLOR", (0, 1), (0, 1), SEVERITY_COLORS["critical"]),
        ("TEXTCOLOR", (1, 1), (1, 1), SEVERITY_COLORS["high"]),
        ("TEXTCOLOR", (2, 1), (2, 1), SEVERITY_COLORS["medium"]),
        ("TEXTCOLOR", (3, 1), (3, 1), SEVERITY_COLORS["low"]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#262626")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 5 * mm))

    counts_meta = (scan.get("meta") or {}).get("counts") or {}
    scope_rows = [
        ["Alt Alan", "Canlı", "Endpoint", "Zafiyet", "Sır Fitili"],
        [
            str(counts_meta.get("subdomains", len(subdomains))),
            str(counts_meta.get("alive", "-")),
            str(counts_meta.get("endpoints", "-")),
            str(counts_meta.get("vulnerabilities", "-")),
            str(counts_meta.get("secrets", "-")),
        ],
    ]
    scope = Table(scope_rows, colWidths=[34 * mm] * 5)
    scope.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), NEON),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#262626")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(scope)
    if (scan.get("meta") or {}).get("warning") == "no_findings":
        story.append(Spacer(1, 3 * mm))
        story.append(_p(
            "<b>Dikkat:</b> bu tarama 0 bulgu üretti. Hedef erişilebilir "
            "olmayabilir veya tarayıcı binary'leri kurulu olmayabilir.",
            styles["body"],
        ))
    story.append(PageBreak())

    # --- Executive summary ---------------------------------------------------
    story.append(_p("Yönetici Özeti", styles["h2"]))
    story.extend(_md_to_flowables(executive_summary, styles))
    inventory = (scan.get("meta") or {}).get("client_inventory")
    if inventory:
        story.append(_p("İstemci Kaynak Envanteri", styles["h2"]))
        story.append(_p(
            f"Durum: {_s(inventory.get('status'))}; dosya: {len(inventory.get('files') or [])}; "
            f"form: {len(inventory.get('forms') or [])}; API yolu adayı: {len(inventory.get('api_paths') or [])}; "
            f"source map: {len(inventory.get('source_maps') or [])}. "
            "Bunlar gözlemdir; doğrulanmış güvenlik açığı veya tam site kopyası değildir.", styles["body"]))
    story.append(Spacer(1, 4 * mm))

    # --- Findings table ------------------------------------------------------
    story.append(_p("Bulgular", styles["h2"]))
    if findings:
        by_type: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for f in findings:
            by_type[str(f.get("type") or "vulnerability")] = \
                by_type.get(str(f.get("type") or "vulnerability"), 0) + 1
            by_source[str(f.get("source") or "unknown")] = \
                by_source.get(str(f.get("source") or "unknown"), 0) + 1
        label_map = {"vulnerability": "Zafiyet", "secret": "Sır Fitili"}
        type_cells = [
            f"{label_map.get(k, k)}: {v}" for k, v in sorted(by_type.items())
        ]
        source_cells = [f"{k}: {v}" for k, v in sorted(by_source.items())]
        breakdown = Table(
            [[_p("Tür", styles["cell"]), _p("Motor", styles["cell"])],
             [_p("  ".join(type_cells) or "-", styles["cell"]),
              _p("  ".join(source_cells) or "-", styles["cell"])]],
            colWidths=[80 * mm, 80 * mm],
        )
        breakdown.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#262626")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(breakdown)
        story.append(Spacer(1, 4 * mm))
        data = [[_p("Seviye", styles["cell"]), _p("Bulgu", styles["cell"]),
                 _p("URL", styles["cell"]), _p("CVSS", styles["cell"])]]
        for f in findings:
            data.append([
                _p(str(f.get("severity", "")).upper(), styles["cell"]),
                _p(str(f.get("title")), styles["cell"]),
                _p(str(f.get("url") or "-"), styles["cell"]),
                _p(str(f.get("cvss") if f.get("cvss") is not None else "-"), styles["cell"]),
            ])
        table = Table(data, colWidths=[20 * mm, 60 * mm, 72 * mm, 14 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#262626")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        # severity colouring
        for row_idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity") or "info").lower()
            table.setStyle(TableStyle([
                ("TEXTCOLOR", (0, row_idx), (0, row_idx), SEVERITY_COLORS.get(sev, GREY)),
            ]))
        story.append(table)
    else:
        story.append(_p("Bulgu yok.", styles["body"]))
    story.append(PageBreak())

    # --- Detailed findings ---------------------------------------------------
    story.append(_p("Bulgu Detayları ve AI Analizi", styles["h2"]))
    if not findings:
        story.append(_p("Detaylı bulgu yok.", styles["body"]))
    for idx, f in enumerate(findings, start=1):
        sev = str(f.get("severity") or "info").lower()
        header = (
            f"#{idx} [{str(f.get('severity', '')).upper()}] "
            f"{_s(f.get('title'))}  (CVSS: {f.get('cvss') if f.get('cvss') is not None else '-'})"
        )
        block = [_p(header, styles["body"])]
        if f.get("is_false_positive"):
            block.append(_p("<b>False Positive</b> olarak isaretlendi.", styles["body"]))
        if f.get("url"):
            block.append(_p(f"URL: {_s(f.get('url'))}", styles["cell"]))
        if f.get("ai_provider"):
            block.append(_p(f"Analiz motoru: {_s(f.get('ai_provider'))}; AI güveni: {_s(f.get('ai_confidence'))} (doğrulama değildir)", styles["cell"]))
        if f.get("ai_analysis"):
            block.append(_p(f"<b>AI Analizi:</b> {_s(f.get('ai_analysis'))}", styles["body"]))
        if f.get("exploit_scenario"):
            block.append(_p(f"<b>Sömürü Senaryosu:</b> {_s(f.get('exploit_scenario'))}", styles["body"]))
        if f.get("evidence"):
            block.append(_p("<b>Kanit:</b>", styles["body"]))
            block.append(Preformatted(_s(_clip_block(f.get("evidence"), 4000)), styles["mono"]))
        if f.get("fix_code"):
            block.append(_p("<b>Düzeltme:</b>", styles["body"]))
            block.append(Preformatted(_s(_clip_block(f.get("fix_code"), 4000)), styles["mono"]))
        block.append(Spacer(1, 4 * mm))
        story.append(KeepTogether(block))

    # --- Subdomains ----------------------------------------------------------
    story.append(PageBreak())
    story.append(_p("Alt Alan Adları", styles["h2"]))
    rows = [[_p("Host", styles["cell"]), _p("IP", styles["cell"]),
             _p("Canli", styles["cell"]), _p("Teknolojiler", styles["cell"])]]
    for s in subdomains[:300]:
        rows.append([
            _p(str(s.get("subdomain")), styles["cell"]),
            _p(str(s.get("ip") or "-"), styles["cell"]),
            _p("Evet" if s.get("is_alive") else "Hayır", styles["cell"]),
            _p(", ".join(s.get("technologies") or []) or "-", styles["cell"]),
        ])
    sub_table = Table(rows, colWidths=[62 * mm, 30 * mm, 16 * mm, 64 * mm], repeatRows=1)
    sub_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#262626")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 6 * mm))
    story.append(_p(
        "Bu rapor RAVEN tarafından otomatik üretilmiştir. Tarama yalnızca hedef "
        "sahibinin yazılı izniyle yapılmalıdır. Bulguların doğruluğu yapay zekâ "
        "modellerine ve imza setine bağlıdır; kritik kararlar insan uzman "
        "tarafından yeniden değerlendirilmelidir.",
        styles["cell"],
    ))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
