#!/usr/bin/env python3
"""Build the cheat-sheet PDFs in cheatsheets/ from the markdown sources in scripts/cheatsheets/.

Every page of every PDF carries a diagonal "iamjammie/hunt-sage" watermark and a footer with the
repository URL, licence note and page numbers. Hyperlinks to site pages stay clickable.

Requirements (see CONTRIBUTING.md):
  pip install markdown pygments pyyaml
  Node.js + Playwright with Chromium (npm i -g playwright && npx playwright install chromium)

Usage: python scripts/build_cheatsheets.py [name ...]    # default: all sheets
"""
import datetime
import html
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown
import yaml
from pygments.formatters import HtmlFormatter

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "scripts" / "cheatsheets"
OUT_DIR = ROOT / "cheatsheets"
CONFIG = yaml.safe_load((ROOT / "_config.yml").read_text(encoding="utf-8"))
SITE = (CONFIG["url"].rstrip("/") + CONFIG.get("baseurl", "")).rstrip("/")
REPO = "github.com/iamjammie/hunt-sage"
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)

CSS = """
@page { size: A4; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: 'Inter', 'Helvetica Neue', Arial, 'DejaVu Sans', sans-serif; font-size: 8.6pt;
       line-height: 1.38; color: #1b2230; margin: 0; }
/* repeating watermark: position:fixed elements print on every page in Chromium */
.wm { position: fixed; inset: 0; z-index: -1; display: flex; align-items: center; justify-content: center;
      pointer-events: none; }
.wm > div { transform: rotate(-35deg); text-align: center; color: #0A0F1F; opacity: 0.09; white-space: nowrap; }
.wm .big { font-size: 66pt; font-weight: 800; letter-spacing: 2pt; line-height: 1; }
.wm .small { font-size: 22pt; font-weight: 600; margin-top: 6pt; }
.cover { background: #0A0F1F; color: #F7FAFC; padding: 14pt 16pt 12pt; border-radius: 6pt;
         border-left: 6pt solid #6AFB73; margin-bottom: 12pt; }
.cover .brand { font-size: 7.5pt; letter-spacing: 1.6pt; text-transform: uppercase; color: #6AFB73; font-weight: 700; }
.cover h1 { font-size: 20pt; margin: 3pt 0 4pt; line-height: 1.15; color: #fff; border: 0; }
.cover p { margin: 0; font-size: 9pt; color: #c9d3e3; }
.cover .meta { margin-top: 7pt; font-size: 7.4pt; color: #8fa0bb; }
h1 { font-size: 15pt; } 
h2 { font-size: 11.5pt; color: #0A0F1F; border-bottom: 1.6pt solid #6AFB73; padding-bottom: 2pt;
     margin: 13pt 0 5pt; break-after: avoid; }
h3 { font-size: 9.6pt; color: #0b5d3a; margin: 9pt 0 3pt; break-after: avoid; }
h4 { font-size: 8.8pt; margin: 7pt 0 2pt; break-after: avoid; }
p { margin: 3pt 0 5pt; }
a { color: #0b6b9a; text-decoration: none; word-break: break-word; }
ul, ol { margin: 3pt 0 5pt; padding-left: 14pt; } li { margin: 1pt 0; }
blockquote { margin: 5pt 0; padding: 4pt 8pt; background: #f1f6f3; border-left: 3pt solid #6AFB73; color: #34404f; }
blockquote p { margin: 2pt 0; }
table { width: 100%; border-collapse: collapse; margin: 4pt 0 8pt; font-size: 7.9pt; }
th { background: #0A0F1F; color: #fff; text-align: left; padding: 3pt 5pt; font-weight: 600; }
td { padding: 2.6pt 5pt; border-bottom: 0.6pt solid #d6dde8; vertical-align: top; word-break: break-word; }
tr { break-inside: avoid; }
tbody tr:nth-child(even) td { background: rgba(244, 247, 251, 0.85); }
code { font-family: 'DejaVu Sans Mono', Menlo, Consolas, monospace; font-size: 0.88em; background: #eef2f7;
       padding: 0.5pt 2.5pt; border-radius: 2pt; word-break: break-word; }
pre, .codehilite { margin: 4pt 0 7pt; }
pre { background: #f5f7fa; border: 0.6pt solid #d6dde8; border-left: 2.4pt solid #0A0F1F; border-radius: 3pt;
      padding: 5pt 7pt; white-space: pre-wrap; word-break: break-all; font-size: 7.3pt; line-height: 1.32;
      break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; word-break: break-all; }
hr { border: 0; border-top: 0.6pt solid #d6dde8; margin: 8pt 0; }
"""

FOOTER = (
    '<div style="width:100%;font-family:Inter,Arial,sans-serif;font-size:6.8pt;color:#5b6678;'
    'padding:0 12mm;display:flex;justify-content:space-between;-webkit-print-color-adjust:exact;">'
    f'<span><b style="color:#0A0F1F">{REPO}</b> &nbsp;·&nbsp; © 2025 iamjammie · educational use with attribution</span>'
    '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
)


def render(src: Path, today: str) -> tuple[str, str]:
    text = src.read_text(encoding="utf-8")
    m = FM_RE.match(text)
    fm = yaml.safe_load(m.group(1)) if m else {}
    body = text[m.end():] if m else text
    body = body.replace("{{ site.baseurl }}", SITE)
    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "sane_lists", "codehilite", "toc"],
        extension_configs={"codehilite": {"guess_lang": False, "css_class": "codehilite", "noclasses": False}},
    )
    content = md.convert(body)
    title = fm.get("title", src.stem)
    excerpt = fm.get("excerpt", "")
    css = CSS + HtmlFormatter(style="default").get_style_defs(".codehilite")
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)} - Hunt-Sage cheat sheet</title><style>{css}</style></head><body>
<div class="wm"><div><div class="big">HUNT-SAGE</div><div class="small">{REPO.replace('github.com/', '')}</div></div></div>
<div class="cover"><div class="brand">Hunt-Sage · Threat Hunting Cheat Sheet</div>
<h1>{html.escape(title)}</h1><p>{html.escape(excerpt)}</p>
<div class="meta">{REPO} &nbsp;·&nbsp; {SITE.replace('https://', '')} &nbsp;·&nbsp; Built {today}</div></div>
{content}</body></html>"""
    return title, page


def main() -> int:
    names = sys.argv[1:] or sorted(p.stem for p in SRC_DIR.glob("*.md"))
    today = datetime.date.today().isoformat()
    OUT_DIR.mkdir(exist_ok=True)
    jobs = []
    with tempfile.TemporaryDirectory() as tmp:
        for name in names:
            src = SRC_DIR / f"{name}.md"
            if not src.exists():
                print(f"no such source: {src}", file=sys.stderr)
                return 1
            _, page = render(src, today)
            html_path = Path(tmp) / f"{name}.html"
            html_path.write_text(page, encoding="utf-8")
            jobs.append((html_path, OUT_DIR / f"{name}.pdf"))
        env = dict(os.environ)
        if "NODE_PATH" not in env:
            try:
                env["NODE_PATH"] = subprocess.check_output(["npm", "root", "-g"], text=True).strip()
            except (OSError, subprocess.CalledProcessError):
                pass
        args = ["node", str(ROOT / "scripts" / "html2pdf.js"), FOOTER] + [str(x) for job in jobs for x in job]
        subprocess.run(args, check=True, env=env)
    for _, pdf in jobs:
        print(f"wrote {pdf.relative_to(ROOT)} ({pdf.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
