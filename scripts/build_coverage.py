#!/usr/bin/env python3
"""Build the ATT&CK coverage data from the content itself (no hand-maintained tables).

Sources
  * hunt/playbooks/*.md       front matter `attack: [T1234, T1234.001]`
  * research/sigma/*.yml      `tags: [attack.t1234, ...]`
  * _posts/*.md, _ctf/*.md    front matter `attack: [...]` (write-ups)
  * hunt/packs/*.md           front matter `attack: [...]`, `playbooks: [...]` (scenario packs)
  * hunt/hypotheses.md        H-xxx rows, matched to playbooks by the link in the last column
  * _data/attack.yml          technique names, tactic membership, planned gaps

Outputs
  * _data/coverage.yml                               summary counts, per-tactic rows, per-playbook rules/hypotheses (for Liquid)
  * _includes/coverage-heatmap.html                   the heatmap + per-tactic tables (static HTML)
  * research/mitre-mapping/hunt-sage-navigator-layer.json   importable into ATT&CK Navigator
  * _includes/sigma-rules-table.html                 rule index tables for research/sigma/

Usage: python scripts/build_coverage.py            # write the outputs
       python scripts/build_coverage.py --check    # exit 1 if outputs are stale (CI)
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from html import escape
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ATTACK = yaml.safe_load((ROOT / "_data" / "attack.yml").read_text(encoding="utf-8"))
FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)
OUT_DATA = ROOT / "_data" / "coverage.yml"
OUT_HTML = ROOT / "_includes" / "coverage-heatmap.html"
OUT_LAYER = ROOT / "research" / "mitre-mapping" / "hunt-sage-navigator-layer.json"
OUT_RULES = ROOT / "_includes" / "sigma-rules-table.html"

STATUS_LABEL = {
    "full": "Sigma rule + playbook",
    "rule": "Sigma rule",
    "hunt": "Playbook only",
    "note": "Write-up only",
    "gap": "Planned",
}
STATUS_ICON = {"full": "✅", "rule": "✅", "hunt": "🔍", "note": "📝", "gap": "🔜"}
STATUS_CLASS = {"full": "full", "rule": "full", "hunt": "hunt", "note": "note", "gap": "gap"}
NAV_COLOR = {"full": "#6afb73", "rule": "#6afb73", "hunt": "#f5b942", "note": "#8b98ae", "gap": "#ffffff"}
NAV_SCORE = {"full": 100, "rule": 100, "hunt": 66, "note": 33, "gap": 0}


def front_matter(path: Path) -> dict:
    m = FM_RE.match(path.read_text(encoding="utf-8"))
    return yaml.safe_load(m.group(1)) if m else {}


def norm_ids(values) -> list[str]:
    out = []
    for v in values or []:
        v = str(v).strip().upper()
        if re.fullmatch(r"T\d{4}(\.\d{3})?", v):
            out.append(v)
    return out


RULES: list[dict] = []


def collect() -> tuple[dict, dict, list[str]]:
    """Return (techniques -> {playbooks, rules, notes}, known techniques, errors)."""
    known = {t["id"]: t for t in ATTACK["techniques"]}
    cov: dict[str, dict] = defaultdict(lambda: {"playbooks": [], "rules": [], "notes": []})
    errors: list[str] = []

    def check(tid: str, where: str) -> bool:
        if tid not in known:
            errors.append(f"{where}: {tid} is not in _data/attack.yml (add id, name and tactics)")
            return False
        return True

    for p in sorted((ROOT / "hunt" / "playbooks").glob("*.md")):
        fm = front_matter(p)
        ids = norm_ids(fm.get("attack"))
        if not ids:
            errors.append(f"{p.relative_to(ROOT)}: no `attack:` list in front matter")
        title = re.sub(r"^Playbook:\s*", "", fm.get("title", p.stem))
        for tid in ids:
            if check(tid, p.name):
                cov[tid]["playbooks"].append({"title": title, "url": fm.get("permalink", f"/hunt/playbooks/{p.stem}/")})

    for r in sorted((ROOT / "research" / "sigma").glob("*.yml")):
        data = yaml.safe_load(r.read_text(encoding="utf-8"))
        ids = [t.split(".", 1)[1].upper() for t in data.get("tags", []) if re.match(r"^attack\.t\d{4}", t)]
        tactics = [t.split(".", 1)[1] for t in data.get("tags", []) if re.match(r"^attack\.[a-z_]+$", t)]
        RULES.append({"file": r.name, "title": data["title"], "techniques": ids, "tactics": tactics,
                      "level": data.get("level", ""), "status": data.get("status", ""),
                      "logsource": " / ".join(str((data.get("logsource") or {}).get(k)) for k in ("product", "category", "service") if (data.get("logsource") or {}).get(k))})
        for tid in ids:
            if check(tid, r.name):
                cov[tid]["rules"].append({"title": data["title"], "url": f"/research/sigma/{r.name}", "level": data.get("level"), "status": data.get("status")})

    for p in sorted(list((ROOT / "_posts").glob("*.md")) + list((ROOT / "_ctf").glob("*.md")) + [x for x in (ROOT / "hunt" / "packs").glob("*.md") if x.stem != "index"]):
        fm = front_matter(p)
        ids = norm_ids(fm.get("attack"))
        if not ids:
            continue
        if p.parent.name == "_posts":
            url = fm.get("permalink") or "/blog/" + re.sub(r"^\d{4}-\d{2}-\d{2}-", "", p.stem) + "/"
            kind = "post"
        elif p.parent.name == "packs":
            url = fm.get("permalink") or f"/hunt/packs/{p.stem}/"
            kind = "pack"
        else:
            url = fm.get("permalink") or f"/ctf/{p.stem}/"
            kind = "ctf"
        for tid in ids:
            if check(tid, p.name):
                cov[tid]["notes"].append({"title": fm.get("title", p.stem), "url": url, "kind": kind})

    for tid, t in known.items():
        if t.get("planned") and tid in cov:
            errors.append(f"_data/attack.yml: {tid} is marked planned but content references it; remove `planned`")
    return cov, known, errors


HYP_RE = re.compile(r"^\|\s*(H-\d{3})\s*\|.*\|\s*(.*?)\s*\|\s*$")
LINK_RE = re.compile(r"\]\(\{\{\s*site\.baseurl\s*\}\}(/hunt/playbooks/[^)#]+/)")


def hypotheses_by_playbook() -> dict[str, list[str]]:
    """H-ids per playbook permalink, from the link in the last column of each row in hunt/hypotheses.md."""
    out: dict[str, list[str]] = defaultdict(list)
    for line in (ROOT / "hunt" / "hypotheses.md").read_text(encoding="utf-8").splitlines():
        m = HYP_RE.match(line)
        if not m:
            continue
        for url in LINK_RE.findall(m.group(2)):
            if m.group(1) not in out[url]:
                out[url].append(m.group(1))
    return out


def playbook_rows(cov: dict) -> list[dict]:
    """One row per playbook: front matter + the Sigma rules and hypotheses mapped to it."""
    hyps = hypotheses_by_playbook()
    rows = []
    for p in sorted((ROOT / "hunt" / "playbooks").glob("*.md")):
        fm = front_matter(p)
        url = fm.get("permalink", f"/hunt/playbooks/{p.stem}/")
        rules: list[dict] = []
        seen = set()
        for tid in norm_ids(fm.get("attack")):
            for r in cov.get(tid, {}).get("rules", []):
                if r["url"] not in seen:
                    seen.add(r["url"])
                    rules.append(r)
        rows.append({
            "slug": p.stem,
            "title": re.sub(r"^Playbook:\s*", "", fm.get("title", p.stem)),
            "url": url,
            "tactic": fm.get("tactic", ""),
            "difficulty": fm.get("difficulty", 2),
            "timebox": fm.get("timebox", ""),
            "data": list(fm.get("data") or []),
            "attack": norm_ids(fm.get("attack")),
            "rules": sorted(rules, key=lambda r: r["title"]),
            "hypotheses": hyps.get(url, []),
        })
    return sorted(rows, key=lambda r: r["title"].lower())


def status_of(tid: str, c: dict, known: dict) -> str:
    if c["rules"] and c["playbooks"]:
        return "full"
    if c["rules"]:
        return "rule"
    if c["playbooks"]:
        return "hunt"
    if c["notes"]:
        return "note"
    return "gap"


def build() -> tuple[dict, str, dict, list[str]]:
    cov, known, errors = collect()
    tactics = ATTACK["tactics"]
    rows_by_tactic: dict[str, list[dict]] = {t["key"]: [] for t in tactics}
    summary = {k: 0 for k in STATUS_LABEL}
    seen_ids = set()

    for tid in sorted(set(cov) | {k for k, t in known.items() if t.get("planned")}):
        t = known[tid]
        c = cov.get(tid, {"playbooks": [], "rules": [], "notes": []})
        st = status_of(tid, c, known)
        if tid not in seen_ids:
            summary[st] += 1
            seen_ids.add(tid)
        row = {
            "id": tid, "name": t["name"], "status": st, "label": STATUS_LABEL[st], "icon": STATUS_ICON[st],
            "playbooks": c["playbooks"], "rules": c["rules"], "notes": c["notes"],
        }
        for key in t["tactics"]:
            if key in rows_by_tactic:
                rows_by_tactic[key].append(row)

    pb_rows = playbook_rows(cov)
    hyp_count = sum(1 for line in (ROOT / "hunt" / "hypotheses.md").read_text(encoding="utf-8").splitlines() if HYP_RE.match(line))
    data = {
        "generated_by": "scripts/build_coverage.py (do not edit by hand)",
        "summary": {"techniques": len(seen_ids), "rules": len(RULES), "playbooks": len(pb_rows),
                    "packs": len([x for x in (ROOT / "hunt" / "packs").glob("*.md") if x.stem != "index"]), "hypotheses": hyp_count,
                    "cheatsheets": len(list((ROOT / "scripts" / "cheatsheets").glob("*.md"))), **summary},
        "tactics": [
            {"id": t["id"], "name": t["name"], "key": t["key"], "techniques": rows_by_tactic[t["key"]]}
            for t in tactics
        ],
        "playbooks": pb_rows,
    }
    return data, render_html(data), render_layer(data), errors


def link(url: str, text: str) -> str:
    return f'<a href="{{{{ site.baseurl }}}}{escape(url)}">{escape(text)}</a>'


def render_html(data: dict) -> str:
    s = data["summary"]
    out = ['<!-- generated by scripts/build_coverage.py; edit the content, not this file -->']
    out.append('<div class="hs-legend">'
               '<span class="l-full">Sigma rule (+ playbook)</span>'
               '<span class="l-hunt">Playbook only</span>'
               '<span class="l-note">Write-up or hunt pack only</span>'
               '<span class="l-gap">Planned</span></div>')
    out.append('<div class="hs-heatmap hs-no-attack-links">')
    for t in data["tactics"]:
        out.append(f'<div class="hs-heatmap__tactic"><h4>{escape(t["name"])}<small>{t["id"]} · {len(t["techniques"])}</small></h4>')
        for r in t["techniques"]:
            target = (r["playbooks"] or r["rules"] or r["notes"] or [{"url": "/research/mitre-mapping/"}])[0]["url"]
            short = r["name"].split(": ", 1)[-1]
            out.append(
                f'<a class="hs-heatmap__cell hs-heatmap__cell--{STATUS_CLASS[r["status"]]}" '
                f'href="{{{{ site.baseurl }}}}{escape(target)}" title="{escape(r["name"])} — {r["label"]}">'
                f'<code>{r["id"]}</code>{escape(short)}</a>'
            )
        out.append("</div>")
    out.append("</div>")

    out.append('<p class="hs-stats-inline">'
               f'<strong>{s["techniques"]}</strong> techniques mapped · '
               f'<strong>{s["full"] + s["rule"]}</strong> with a Sigma rule · '
               f'<strong>{s["hunt"]}</strong> playbook-only · '
               f'<strong>{s["note"]}</strong> write-up-only · '
               f'<strong>{s["gap"]}</strong> planned</p>')

    for t in data["tactics"]:
        out.append(f'\n<h2 id="{t["id"].lower()}-{t["key"].replace("_", "-")}">{t["id"]} · {escape(t["name"])}</h2>')
        out.append("<table><thead><tr><th>Technique</th><th>ID</th><th>Status</th><th>Content</th></tr></thead><tbody>")
        for r in t["techniques"]:
            parts = [link(x["url"], "Sigma: " + x["title"]) for x in r["rules"]]
            parts += [link(x["url"], "Playbook: " + x["title"]) for x in r["playbooks"]]
            parts += [link(x["url"], {"ctf": "CTF: ", "pack": "Pack: ", "post": "Post: "}.get(x["kind"], "Post: ") + x["title"]) for x in r["notes"]]
            content = " · ".join(parts) if parts else "-"
            out.append(f'<tr><td>{escape(r["name"])}</td><td><code>{r["id"]}</code></td>'
                       f'<td title="{r["label"]}">{r["icon"]}</td><td>{content}</td></tr>')
        out.append("</tbody></table>")
    return "\n".join(out) + "\n"


def render_rules() -> str:
    tactic_names = {t["key"]: t["name"] for t in ATTACK["tactics"]}
    out = ['<!-- generated by scripts/build_coverage.py; edit the rules, not this file -->']
    out.append("<table><thead><tr><th>Rule</th><th>Technique</th><th>Log source</th><th>Level</th><th>Status</th><th>Tactics</th></tr></thead><tbody>")
    for r in sorted(RULES, key=lambda x: x["file"]):
        techs = ", ".join(f"<code>{t}</code>" for t in r["techniques"])
        tacs = ", ".join(tactic_names.get(t, t) for t in r["tactics"])
        out.append(f'<tr><td>{link("/research/sigma/" + r["file"], r["title"])}</td><td>{techs}</td>'
                   f'<td><code>{escape(r["logsource"])}</code></td><td>{escape(r["level"])}</td>'
                   f'<td><span class="hs-chip">{escape(r["status"])}</span></td><td>{tacs}</td></tr>')
    out.append("</tbody></table>")
    out.append('<h2 id="rules-by-tactic">Rules by tactic</h2>')
    for t in ATTACK["tactics"]:
        rules = [r for r in RULES if t["key"] in r["tactics"]]
        if not rules:
            continue
        out.append(f'<h3 id="tactic-{t["key"].replace("_", "-")}">{escape(t["name"])} <small>({len(rules)})</small></h3><ul>')
        for r in sorted(rules, key=lambda x: x["file"]):
            out.append(f'<li>{link("/research/sigma/" + r["file"], r["title"])} ({", ".join(r["techniques"])}, {escape(r["level"])})</li>')
        out.append("</ul>")
    return "\n".join(out) + "\n"


def render_layer(data: dict) -> dict:
    techniques = []
    seen = set()
    for t in data["tactics"]:
        for r in t["techniques"]:
            key = (r["id"], t["key"])
            if key in seen:
                continue
            seen.add(key)
            comment = "; ".join(
                [f"Sigma: {x['title']}" for x in r["rules"]] + [f"Playbook: {x['title']}" for x in r["playbooks"]]
                + [f"Write-up: {x['title']}" for x in r["notes"]]
            )
            techniques.append({
                "techniqueID": r["id"],
                "tactic": t["key"].replace("_", "-"),
                "score": NAV_SCORE[r["status"]],
                "color": NAV_COLOR[r["status"]],
                "comment": comment or "planned",
                "enabled": True,
                "showSubtechniques": False,
            })
    return {
        "name": "Hunt-Sage coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by Hunt-Sage playbooks, Sigma rules and write-ups. Green = Sigma rule, amber = playbook only, grey = write-up only.",
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True, "showAggregateScores": False, "countUnscored": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#f5b942", "#6afb73"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Sigma rule (+ playbook)", "color": "#6afb73"},
            {"label": "Playbook only", "color": "#f5b942"},
            {"label": "Write-up only", "color": "#8b98ae"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0a0f1f",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def main() -> int:
    data, html, layer, errors = build()
    if errors:
        print(f"FAILED: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        return 1
    yml = "# generated by scripts/build_coverage.py; do not edit by hand\n" + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=1000)
    layer_txt = json.dumps(layer, indent=2) + "\n"
    rules_html = render_rules()
    if "--check" in sys.argv:
        stale = [str(p.relative_to(ROOT)) for p, txt in ((OUT_DATA, yml), (OUT_HTML, html), (OUT_LAYER, layer_txt), (OUT_RULES, rules_html))
                 if not p.exists() or p.read_text(encoding="utf-8") != txt]
        if stale:
            print("FAILED: coverage outputs are stale, run `python scripts/build_coverage.py`:")
            for s in stale:
                print("  -", s)
            return 1
        print("OK: coverage data up to date")
        return 0
    OUT_DATA.write_text(yml, encoding="utf-8")
    OUT_HTML.write_text(html, encoding="utf-8")
    OUT_LAYER.parent.mkdir(parents=True, exist_ok=True)
    OUT_LAYER.write_text(layer_txt, encoding="utf-8")
    OUT_RULES.write_text(rules_html, encoding="utf-8")
    s = data["summary"]
    print(f"OK: {s['techniques']} techniques ({s['full'] + s['rule']} rule, {s['hunt']} hunt, {s['note']} note, {s['gap']} planned); {len(RULES)} Sigma rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
