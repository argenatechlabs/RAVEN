#!/usr/bin/env python3
"""Render ``docs/demo.gif`` — a terminal-style recording of a real RAVEN scan.

The frames are built from the live log stream of a finished scan, so the demo
always shows the product's actual output instead of a hand-written mock.

Usage:
    python docs/make_demo_gif.py [--api http://127.0.0.1:8000] [--scan 12] \
        [--out docs/demo.gif]

Requires Pillow (``pip install pillow``); it is not part of the backend
requirements because the backend never renders the demo.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

from PIL import Image, ImageDraw, ImageFont

# --- palette (matrix / neon terminal) ---------------------------------------
BG = (10, 10, 10)
FG = (0, 255, 65)
DIM = (0, 140, 45)
CYAN = (0, 229, 255)
YELLOW = (255, 214, 10)
RED = (255, 77, 77)
GREY = (150, 150, 150)

WIDTH = 880
HEIGHT = 520
MARGIN = 24
LINE_H = 21
VISIBLE_LINES = 18
FONT_SIZE = 15
TITLE_SIZE = 18

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

# Real stage progress values, used for the progress bar.
STAGE_PROGRESS = [
    ("recon", 15),
    ("liveness", 32),
    ("crawler", 48),
    ("zafiyet", 68),
    ("secret", 78),
    ("ai", 92),
    ("tamamlandi", 100),
]


def _font(path: str, size: int) -> ImageFont.FreeTypeFont:
    if os.path.exists(path):
        return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _get(url: str) -> object:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _as_list(payload: object, keys: tuple[str, ...]) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


def progress_for(message: str, index: int, total: int) -> int:
    """Map a log line to the pipeline stage progress (0-100)."""
    low = message.lower()
    for needle, value in STAGE_PROGRESS:
        if needle in low:
            return value
    if total <= 1:
        return 100
    return min(100, round((index + 1) / total * 100))


def level_color(level: str) -> tuple[int, int, int]:
    return {
        "success": FG,
        "info": DIM,
        "warning": YELLOW,
        "error": RED,
    }.get(level, GREY)


def draw_progress(draw: ImageDraw.ImageDraw, pct: int) -> None:
    bar_w = WIDTH - 2 * MARGIN
    x0, y0 = MARGIN, HEIGHT - 34
    draw.rectangle([x0, y0, x0 + bar_w, y0 + 10], outline=DIM)
    filled = int(bar_w * max(0, min(100, pct)) / 100)
    if filled:
        draw.rectangle([x0, y0, x0 + filled, y0 + 10], fill=FG)
    label = f"  {pct:3d}%"
    draw.text((x0 + bar_w + 8, y0 - 3), label, font=_font(FONT_PATH, FONT_SIZE), fill=FG)


def new_frame() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, WIDTH, 30], fill=(16, 16, 16))
    draw.ellipse([MARGIN, 10, MARGIN + 10, 20], fill=FG)
    draw.text(
        (MARGIN + 18, 7),
        "RAVEN — autonomous AI pentester",
        font=_font(FONT_BOLD_PATH, TITLE_SIZE),
        fill=FG,
    )
    draw.line([0, 31, WIDTH, 31], fill=(40, 40, 40))
    return img, draw


def draw_log_frame(lines: list[tuple[str, str]], shown: int, pct: int) -> Image.Image:
    img, draw = new_frame()
    y = 46
    draw.text(
        (MARGIN, y),
        "$ raven scan --target 127.0.0.1:8099",
        font=_font(FONT_BOLD_PATH, FONT_SIZE),
        fill=CYAN,
    )
    y += LINE_H + 6

    visible = lines[max(0, shown - VISIBLE_LINES):shown]
    for level, message in visible:
        color = level_color(level)
        draw.text((MARGIN, y), "▶", font=_font(FONT_PATH, FONT_SIZE), fill=color)
        draw.text((MARGIN + 20, y), message, font=_font(FONT_PATH, FONT_SIZE), fill=color)
        y += LINE_H

    if shown < len(lines):
        draw.text((MARGIN + 20, y), "▌", font=_font(FONT_BOLD_PATH, FONT_SIZE), fill=FG)
    draw_progress(draw, pct)
    return img


def draw_summary_frame(scan: dict, findings: list[dict]) -> Image.Image:
    img, draw = new_frame()
    y = 52
    draw.text(
        (MARGIN, y),
        "✓ Tarama tamamlandı",
        font=_font(FONT_BOLD_PATH, 20),
        fill=FG,
    )
    y += 40

    risk = int(scan.get("risk_score") or 0)
    draw.text(
        (MARGIN, y),
        f"RİSK SKORU   {risk:3d} / 100",
        font=_font(FONT_BOLD_PATH, 18),
        fill=YELLOW if risk >= 50 else FG,
    )
    y += 34
    draw.text(
        (MARGIN, y),
        f"BULGU        {len(findings)}",
        font=_font(FONT_BOLD_PATH, 18),
        fill=FG,
    )
    y += 34

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.get("severity", "info")] = counts.get(finding.get("severity", "info"), 0) + 1
    for severity, color in (
        ("critical", RED),
        ("high", RED),
        ("medium", YELLOW),
        ("low", CYAN),
        ("info", DIM),
    ):
        if counts.get(severity):
            draw.text(
                (MARGIN, y),
                f"  {severity.upper():<8} {counts[severity]}",
                font=_font(FONT_BOLD_PATH, FONT_SIZE),
                fill=color,
            )
            y += LINE_H

    y += 14
    draw.line([MARGIN, y, WIDTH - MARGIN, y], fill=(40, 40, 40))
    y += 16
    for finding in findings[:4]:
        title = str(finding.get("title", ""))[:58]
        draw.text((MARGIN, y), f"• {title}", font=_font(FONT_PATH, FONT_SIZE), fill=GREY)
        y += LINE_H

    y += 12
    draw.text(
        (MARGIN, y),
        "PDF/JSON raporu hazır — docker-compose up",
        font=_font(FONT_BOLD_PATH, FONT_SIZE),
        fill=CYAN,
    )
    return img


def build_frames(api: str, scan_id: int) -> list[tuple[Image.Image, int]]:
    scan = _get(f"{api}/api/scans/{scan_id}")
    if isinstance(scan, list):  # pragma: no cover - defensive
        scan = scan[0]
    logs = _as_list(_get(f"{api}/api/scans/{scan_id}/logs"), ("items", "logs"))
    findings = _as_list(
        _get(f"{api}/api/scans/{scan_id}/findings"), ("items", "findings")
    )

    lines = [
        (str(entry.get("level", "info")), str(entry.get("message", "")))
        for entry in logs
    ]
    if not lines:
        lines = [("info", "Tarama baslatildi"), ("success", "Tarama tamamlandi")]

    frames: list[tuple[Image.Image, int]] = []
    total = len(lines)
    for shown in range(1, total + 1):
        pct = progress_for(lines[shown - 1][1], shown - 1, total)
        frames.append((draw_log_frame(lines, shown, pct), 90))

    # Hold the finished log screen, then the summary screen.
    frames.append((draw_log_frame(lines, total, 100), 400))
    summary = draw_summary_frame(scan, findings)
    frames.extend([(summary, 500), (summary, 500), (summary, 500)])
    return frames


def main() -> int:
    parser = argparse.ArgumentParser(description="Render docs/demo.gif")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--scan", type=int, default=12)
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "demo.gif"))
    args = parser.parse_args()

    frames = build_frames(args.api, args.scan)
    images = [img for img, _ in frames]
    durations = [dur for _, dur in frames]
    images[0].save(
        args.out,
        save_all=True,
        append_images=images[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    size = os.path.getsize(args.out)
    print(f"wrote {args.out}: {len(images)} frames, {size / 1024:.0f} KiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
