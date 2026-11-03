#!/usr/bin/env python3
"""Generate the site's brand images (banner, favicon, avatar, social card, post teasers).

Everything is drawn as SVG from the palette below and rasterised with rsvg-convert, so the
assets can be regenerated at any time and stay consistent.

Usage: python scripts/build_images.py            # rebuild everything
       python scripts/build_images.py --svg-only # just write the .svg sources
Requires: rsvg-convert (librsvg2-bin) on PATH.
"""
from __future__ import annotations

import shutil
from html import escape
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "images"
SRC = OUT / "src"

MIDNIGHT = "#0A0F1F"
MIDNIGHT_2 = "#111A2E"
GREEN = "#6AFB73"
GREEN_DIM = "#2E7D3A"
GRAY = "#2C3542"
WHITE = "#F7FAFC"
MUTED = "#8B98AE"
RED = "#E63946"

SANS = "Inter, 'DejaVu Sans', Arial, sans-serif"
MONO = "'DejaVu Sans Mono', Menlo, monospace"


def radar_mark(cx: float, cy: float, r: float, stroke: float = 3, sweep: bool = True) -> str:
    """Crosshair/radar emblem used across all assets."""
    g = GREEN
    parts = [
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{g}" stroke-width="{stroke}" opacity="0.95"/>',
        f'<circle cx="{cx}" cy="{cy}" r="{r*0.62}" fill="none" stroke="{g}" stroke-width="{stroke*0.7}" opacity="0.7"/>',
        f'<circle cx="{cx}" cy="{cy}" r="{r*0.28}" fill="none" stroke="{g}" stroke-width="{stroke*0.7}" opacity="0.7"/>',
        f'<line x1="{cx-r*1.18}" y1="{cy}" x2="{cx-r*0.12}" y2="{cy}" stroke="{g}" stroke-width="{stroke}"/>',
        f'<line x1="{cx+r*0.12}" y1="{cy}" x2="{cx+r*1.18}" y2="{cy}" stroke="{g}" stroke-width="{stroke}"/>',
        f'<line x1="{cx}" y1="{cy-r*1.18}" x2="{cx}" y2="{cy-r*0.12}" stroke="{g}" stroke-width="{stroke}"/>',
        f'<line x1="{cx}" y1="{cy+r*0.12}" x2="{cx}" y2="{cy+r*1.18}" stroke="{g}" stroke-width="{stroke}"/>',
        f'<circle cx="{cx}" cy="{cy}" r="{stroke*1.2}" fill="{g}"/>',
    ]
    if sweep:
        # radar sweep wedge
        parts.append(
            f'<path d="M{cx},{cy} L{cx+r},{cy} A{r},{r} 0 0 0 {cx+r*0.3},{cy-r*0.954} Z" '
            f'fill="url(#sweep)" opacity="0.55"/>'
        )
        # a couple of "contacts"
        parts.append(f'<circle cx="{cx+r*0.45}" cy="{cy-r*0.35}" r="{stroke*1.4}" fill="{g}"/>')
        parts.append(f'<circle cx="{cx-r*0.5}" cy="{cy+r*0.4}" r="{stroke*1.1}" fill="{RED}"/>')
    return "\n".join(parts)


def defs() -> str:
    return f"""
<defs>
  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="{MIDNIGHT}"/>
    <stop offset="1" stop-color="{MIDNIGHT_2}"/>
  </linearGradient>
  <linearGradient id="sweep" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="{GREEN}" stop-opacity="0"/>
    <stop offset="1" stop-color="{GREEN}" stop-opacity="0.9"/>
  </linearGradient>
  <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
    <path d="M40 0H0V40" fill="none" stroke="{GREEN}" stroke-opacity="0.07" stroke-width="1"/>
  </pattern>
</defs>"""


def banner(w: int = 1600, h: int = 480) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{defs()}
<rect width="{w}" height="{h}" fill="url(#bg)"/>
<rect width="{w}" height="{h}" fill="url(#grid)"/>
{radar_mark(250, h/2, 150, stroke=6)}
<text x="470" y="{h/2 - 20}" font-family="{SANS}" font-weight="800" font-size="118" fill="{WHITE}" letter-spacing="-3">HUNT<tspan fill="{GREEN}">-</tspan>SAGE</text>
<text x="476" y="{h/2 + 50}" font-family="{MONO}" font-size="34" fill="{GREEN}">seek · analyze · neutralize</text>
<text x="476" y="{h/2 + 110}" font-family="{SANS}" font-size="30" fill="{MUTED}">The one-stop threat hunting knowledge hub</text>
<g font-family="{MONO}" font-size="20" fill="{MUTED}" opacity="0.8">
  <text x="{w-470}" y="{h-40}">github.com/iamjammie/hunt-sage</text>
</g>
</svg>"""


def social(w: int = 1200, h: int = 630) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{defs()}
<rect width="{w}" height="{h}" fill="url(#bg)"/>
<rect width="{w}" height="{h}" fill="url(#grid)"/>
{radar_mark(210, 315, 130, stroke=6)}
<text x="400" y="290" font-family="{SANS}" font-weight="800" font-size="104" fill="{WHITE}" letter-spacing="-3">HUNT<tspan fill="{GREEN}">-</tspan>SAGE</text>
<text x="404" y="350" font-family="{MONO}" font-size="30" fill="{GREEN}">seek · analyze · neutralize</text>
<text x="404" y="410" font-family="{SANS}" font-size="28" fill="{MUTED}">Theory · 20 playbooks · Sigma rules · cheat sheets · labs</text>
<text x="404" y="560" font-family="{MONO}" font-size="22" fill="{MUTED}" opacity="0.8">iamjammie.github.io/hunt-sage</text>
</svg>"""


def hero(w: int = 1800, h: int = 640) -> str:
    """Text-free background for the home-page hero (title is rendered by the page)."""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{defs()}
<rect width="{w}" height="{h}" fill="url(#bg)"/>
<rect width="{w}" height="{h}" fill="url(#grid)"/>
<g opacity="0.55">{radar_mark(w-330, h/2, 230, stroke=6)}</g>
<g opacity="0.18">{radar_mark(220, h+40, 140, stroke=4, sweep=False)}</g>
</svg>"""


def icon(size: int = 512, rounded: bool = True) -> str:
    rx = size * 0.18 if rounded else 0
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">
{defs()}
<rect width="{size}" height="{size}" rx="{rx}" fill="url(#bg)"/>
{radar_mark(size/2, size/2, size*0.32, stroke=size*0.03)}
</svg>"""


def teaser(title: str, kicker: str, w: int = 1200, h: int = 630) -> str:
    # wrap title at ~26 chars
    words, lines, cur = title.split(), [], ""
    for wd in words:
        if len(cur) + len(wd) + 1 > 22 and cur:
            lines.append(cur)
            cur = wd
        else:
            cur = (cur + " " + wd).strip()
    if cur:
        lines.append(cur)
    y0 = h / 2 - (len(lines) - 1) * 38 + 10
    text = "".join(
        f'<text x="90" y="{y0 + i*76}" font-family="{SANS}" font-weight="800" font-size="62" fill="{WHITE}" letter-spacing="-1.5">{escape(ln)}</text>'
        for i, ln in enumerate(lines)
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{defs()}
<rect width="{w}" height="{h}" fill="url(#bg)"/>
<rect width="{w}" height="{h}" fill="url(#grid)"/>
{radar_mark(w-185, h/2, 118, stroke=5)}
<text x="90" y="{y0 - 70}" font-family="{MONO}" font-size="26" fill="{GREEN}">{escape(kicker)}</text>
{text}
<text x="90" y="{h-60}" font-family="{MONO}" font-size="22" fill="{MUTED}">HUNT-SAGE · iamjammie.github.io/hunt-sage</text>
</svg>"""


TEASERS = {
    "posts/threat-hunting-101": ("Threat Hunting Fundamentals", "// field notes"),
    "posts/lateral-movement": ("Hunting Lateral Movement & Pass-the-Hash", "// hunt write-up"),
    "posts/c2-beaconing": ("Hunting C2 Beaconing", "// hunt write-up"),
    "posts/persistence": ("Hunting Persistence", "// hunt write-up"),
    "posts/argon-nexus": ("Argon Dynamics: An End-to-End Case Study", "// case study"),
    "posts/stacking-baselining": ("Stacking & Baselining: A Worked Example", "// technique"),
    "ctf/argon-nexus-banner": ("Argon Nexus: The Internal Data Spill", "// CTF challenge"),
    "ctf/osint-flight": ("OSINT Flight", "// CTF challenge"),
    "ctf/reversing-echo": ("Reversing Echo", "// CTF challenge"),
}


def write(path: Path, svg: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(svg, encoding="utf-8")


def rasterise(svg: Path, png: Path, width: int | None = None) -> None:
    png.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["rsvg-convert", "-f", "png", "-o", str(png)]
    if width:
        cmd += ["-w", str(width)]
    cmd.append(str(svg))
    subprocess.run(cmd, check=True)


def main() -> int:
    svg_only = "--svg-only" in sys.argv
    jobs: list[tuple[str, str, int | None]] = []  # (svg name, png name, width)

    write(SRC / "hunt-sage-banner.svg", banner())
    jobs.append(("hunt-sage-banner.svg", "hunt-sage-banner.png", None))
    write(SRC / "hero-bg.svg", hero())
    jobs.append(("hero-bg.svg", "hero-bg.png", None))
    write(SRC / "social-card.svg", social())
    jobs.append(("social-card.svg", "social-card.png", None))
    write(SRC / "icon.svg", icon())
    jobs.append(("icon.svg", "avatar.png", 512))
    jobs.append(("icon.svg", "favicon.png", 64))
    jobs.append(("icon.svg", "apple-touch-icon.png", 180))
    write(SRC / "logo-mark.svg", icon(256, rounded=True))
    jobs.append(("logo-mark.svg", "logo-mark.png", 128))
    for name, (title, kicker) in TEASERS.items():
        write(SRC / f"{name}.svg", teaser(title, kicker))
        jobs.append((f"{name}.svg", f"{name}.png", None))

    if svg_only:
        print(f"wrote {len(jobs)} SVG sources to {SRC}")
        return 0
    if not shutil.which("rsvg-convert"):
        print("rsvg-convert not found; install librsvg2-bin (or run with --svg-only)")
        return 1
    for svg_name, png_name, width in jobs:
        rasterise(SRC / svg_name, OUT / png_name, width)
        print("built", OUT / png_name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
