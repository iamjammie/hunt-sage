#!/usr/bin/env python3
"""Check internal links and front matter of the Jekyll site (offline).

* every page that is rendered has front matter with a title
* internal links resolve to a page, a static file or an asset
* internal absolute links use {{ site.baseurl }} (a bare "/foo/" breaks on GitHub Pages)
* #anchors exist in the target page (GitHub-style heading ids)
* nav entries in _data/navigation.yml resolve

Usage: python scripts/check_links.py
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BASEURL = yaml.safe_load((ROOT / "_config.yml").read_text(encoding="utf-8")).get("baseurl", "")
SKIP_DIRS = {".git", "scripts", "node_modules", "vendor", ".github", "_site"}
SKIP_FILES = {"README.md", "CONTRIBUTING.md"}
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)
LINK_RE = re.compile(r"\]\(([^)\s]+)\)|href=\"([^\"]+)\"")


def split_front_matter(text):
    m = FM_RE.match(text)
    if not m:
        return None, text
    return yaml.safe_load(m.group(1)) or {}, text[m.end():]


def strip_code(body):
    body = re.sub(r"^```.*?^```", "", body, flags=re.S | re.M)
    return re.sub(r"`[^`\n]*`", "", body)


def gfm_id(heading):
    text = re.sub(r"[`*_]", "", heading).strip().lower()
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def permalink_for(path: Path, fm: dict) -> str | None:
    rel = path.relative_to(ROOT).as_posix()
    if fm.get("permalink"):
        return fm["permalink"]
    if rel == "index.md":
        return "/"
    if rel.startswith("_posts/"):
        slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", path.stem)
        return f"/blog/{slug}/"
    if rel.startswith("_ctf/"):
        return f"/ctf/{path.stem}/"
    return None


def norm(p: str) -> str:
    return p if p.endswith("/") or "." in p.rsplit("/", 1)[-1] else p + "/"


def main() -> int:
    errors: list[str] = []
    pages: dict[str, tuple[Path, dict, str]] = {}
    statics: set[str] = set()

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts) or rel.name in SKIP_FILES:
            continue
        if path.suffix == ".md":
            fm, body = split_front_matter(path.read_text(encoding="utf-8"))
            if fm is None:
                errors.append(f"{rel}: markdown file without front matter is not rendered by Jekyll")
                continue
            if not fm.get("title"):
                errors.append(f"{rel}: missing title in front matter")
            link = permalink_for(path, fm)
            if link is None:
                errors.append(f"{rel}: no permalink (add one so links to it are stable)")
                continue
            if norm(link) in pages:
                errors.append(f"{rel}: duplicate permalink {link}")
            pages[norm(link)] = (path, fm, body)
        elif not rel.parts[0].startswith("_") and path.suffix in {".yml", ".png", ".css", ".scss", ".js"}:
            statics.add("/" + rel.as_posix())

    anchors: dict[str, set[str]] = {}
    for link, (path, fm, body) in pages.items():
        ids = set()
        for line in re.sub(r"^```.*?^```", "", body, flags=re.S | re.M).splitlines():
            m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
            if m:
                ids.add(gfm_id(m.group(1)))
        anchors[link] = ids

    for link, (path, fm, body) in pages.items():
        rel = path.relative_to(ROOT)
        for m in LINK_RE.finditer(strip_code(body)):
            url = m.group(1) or m.group(2)
            if re.match(r"^(https?:|mailto:|tel:)", url):
                continue
            url = url.replace("{{ site.baseurl }}", "\0BASE\0")
            if url.startswith("{{") or url.startswith("{%"):
                continue
            has_base = url.startswith("\0BASE\0")
            url = url.replace("\0BASE\0", "")
            if url.startswith("#"):
                if url[1:] and url[1:] not in anchors[link]:
                    errors.append(f"{rel}: anchor {url} not found on the page")
                continue
            if not url.startswith("/"):
                continue  # relative links are not used in this repo
            if not has_base:
                errors.append(f"{rel}: internal link '{url}' lacks {{{{ site.baseurl }}}} (breaks on GitHub Pages)")
            target, _, frag = url.partition("#")
            target = target.split("?")[0]
            if target in statics or ("/" + target.strip("/")) in statics:
                continue
            key = norm(target)
            if key not in pages:
                errors.append(f"{rel}: broken internal link {url}")
            elif frag and frag not in anchors[key]:
                errors.append(f"{rel}: anchor #{frag} not found in {target}")

    nav = yaml.safe_load((ROOT / "_data" / "navigation.yml").read_text(encoding="utf-8"))

    def walk(items):
        for it in items:
            if "url" in it:
                u = it["url"]
                if BASEURL and u.startswith(BASEURL):
                    u = u[len(BASEURL):] or "/"
                if norm(u) not in pages:
                    errors.append(f"_data/navigation.yml: '{it['url']}' does not resolve")
            walk(it.get("children", []))

    for items in nav.values():
        walk(items)

    if errors:
        print(f"FAILED: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        return 1
    print(f"OK: {len(pages)} pages, {len(statics)} static files checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
