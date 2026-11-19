"""Professional PDF report generation (reportlab)."""
from __future__ import annotations

import io
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
    """Make arbitrary text safe for the PDF base fonts."""
    return str(text if text is not None else "").translate(_TR_MAP)


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
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(18 * mm, height - 12 * mm, "RAVEN // AUTONOMOUS AI PENTESTER")
    canvas.setStrokeColor(NEON_DIM)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(18 * mm, 10 * mm, "Gizli - Yetkili personele ozel")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Sayfa {doc.page}")
    canvas.restoreState()


def _styles() -> dict:
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "rav-title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=26, textColor=NEON, leading=30, alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "rav-sub", parent=base["Normal"], fontName="Helvetica",
            fontSize=11, textColor=colors.white, leading=15,
        ),
        "h2": ParagraphStyle(
            "rav-h2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, textColor=NEON, leading=18, spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "rav-body", parent=base["Normal"], fontName="Helvetica",
            fontSize=9.5, textColor=LIGHT, leading=14,
        ),
        "cell": ParagraphStyle(
            "rav-cell", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, textColor=LIGHT, leading=11,
        ),
        "mono": ParagraphStyle(
            "rav-mono", parent=base["Normal"], fontName="Courier",
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
    story.append(_p("Autonomous AI Pentester - Sızma Testi Raporu", styles["subtitle"]))
    story.append(Spacer(1, 6 * mm))
    meta_rows = [
        ["Hedef", _s(scan.get("target_domain"))],
        ["Tarama Tipi", _s(scan.get("scan_type"))],
        ["Durum", _s(scan.get("status"))],
        ["Risk Skoru", f"{scan.get('risk_score', 0)} / 100"],
        ["Baslangic", _s(scan.get("created_at"))],
        ["Bitis", _s(scan.get("completed_at") or "-")],
    ]
    meta = Table(meta_rows, colWidths=[35 * mm, 120 * mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (0, -1), NEON),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
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
    sev_rows = [["Kritik", "Yuksek", "Orta", "Dusuk", "Bilgi", "Toplam"]]
    sev_rows.append([
        str(counts["critical"]), str(counts["high"]), str(counts["medium"]),
        str(counts["low"]), str(counts["info"]), str(len(findings)),
    ])
    sev_table = Table(sev_rows, colWidths=[26 * mm] * 6)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), NEON),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
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
    story.append(PageBreak())

    # --- Executive summary ---------------------------------------------------
    story.append(_p("Yonetici Ozeti", styles["h2"]))
    story.extend(_md_to_flowables(executive_summary, styles))
    story.append(Spacer(1, 4 * mm))

    # --- Findings table ------------------------------------------------------
    story.append(_p("Bulgular", styles["h2"]))
    if findings:
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
    story.append(_p("Bulgu Detaylari ve AI Analizi", styles["h2"]))
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
        if f.get("ai_analysis"):
            block.append(_p(f"<b>AI Analizi:</b> {_s(f.get('ai_analysis'))}", styles["body"]))
        if f.get("exploit_scenario"):
            block.append(_p(f"<b>Somuru Senaryosu:</b> {_s(f.get('exploit_scenario'))}", styles["body"]))
        if f.get("evidence"):
            block.append(_p("<b>Kanit:</b>", styles["body"]))
            block.append(Preformatted(_s(f.get("evidence"))[:4000], styles["mono"]))
        if f.get("fix_code"):
            block.append(_p("<b>Duzeltme:</b>", styles["body"]))
            block.append(Preformatted(_s(f.get("fix_code"))[:4000], styles["mono"]))
        block.append(Spacer(1, 4 * mm))
        story.append(KeepTogether(block))

    # --- Subdomains ----------------------------------------------------------
    story.append(PageBreak())
    story.append(_p("Alt Alan Adlari", styles["h2"]))
    rows = [[_p("Host", styles["cell"]), _p("IP", styles["cell"]),
             _p("Canli", styles["cell"]), _p("Teknolojiler", styles["cell"])]]
    for s in subdomains[:300]:
        rows.append([
            _p(str(s.get("subdomain")), styles["cell"]),
            _p(str(s.get("ip") or "-"), styles["cell"]),
            _p("Evet" if s.get("is_alive") else "Hayir", styles["cell"]),
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
        "Bu rapor RAVEN tarafindan otomatik üretmistir. Tarama yalnizca hedef "
        "sahibinin yazili izniyle yapilmalidir. Bulgularin dogrulugu yapay zekâ "
        "modellerine ve imza setine baglidir; kritik kararlar insan uzman "
        "tarafindan yeniden degerlendirilmelidir.",
        styles["cell"],
    ))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
