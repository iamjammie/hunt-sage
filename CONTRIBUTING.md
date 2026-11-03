# Contributing to Hunt-Sage

Thanks for helping build the one-stop threat hunting reference. Everything must be **defensive**, **accurate** and **useful in practice**.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r scripts/requirements.txt
python scripts/validate_rules.py      # Sigma metadata, ATT&CK tags, pySigma conversion
python scripts/check_links.py         # front matter, internal links, anchors, nav
python scripts/build_coverage.py      # regenerates the coverage map, rule index, Navigator layer and per-playbook data
python scripts/build_cheatsheet_pages.py   # regenerates the cheat-sheet web pages from scripts/cheatsheets/
```

All four must pass (the last one in `--check` mode in CI, so commit the regenerated files). CI also builds the site with Jekyll (`bundle exec jekyll build --strict_front_matter`); to preview locally:

```bash
bundle install
bundle exec jekyll serve --livereload      # http://localhost:4000/hunt-sage/
```

## Generated files (do not edit by hand)

| File | Generated from | By |
|---|---|---|
| `_data/coverage.yml`, `_includes/coverage-heatmap.html` | playbook/pack/post `attack:` front matter + Sigma tags + `_data/attack.yml` + the H-ids in `hunt/hypotheses.md` | `scripts/build_coverage.py` |
| `cheatsheets/*.md` (web pages) | `scripts/cheatsheets/*.md` | `scripts/build_cheatsheet_pages.py` |
| `_includes/sigma-rules-table.html` | `research/sigma/*.yml` | `scripts/build_coverage.py` |
| `research/mitre-mapping/hunt-sage-navigator-layer.json` | same | `scripts/build_coverage.py` |
| `cheatsheets/*.pdf` | `scripts/cheatsheets/*.md` | `scripts/build_cheatsheets.py` |
| `assets/images/*.png` | `scripts/build_images.py` (SVG sources in `assets/images/src/`) | `scripts/build_images.py` |

If a technique is new to the site, add its id, name and tactics to `_data/attack.yml` first; the coverage builder refuses unknown ids.

## Adding or editing pages

- Every page needs front matter with `title`, `permalink` and a one-line `excerpt`.
- **Internal links must use `{{ site.baseurl }}`**, e.g. `[Playbooks]({{ site.baseurl }}/hunt/)`. A bare `/hunt/` works locally but breaks on GitHub Pages.
- Add new pages to the right sidebar in `_data/navigation.yml` (paths there are **without** the baseurl) and to the section index page.
- Avoid `{{` and `{%` inside code blocks (Jekyll treats them as Liquid). Use `{% raw %}...{% endraw %}` if you must.
- Write for practitioners: concrete queries, field names, thresholds, and the *why*.

## Cheat sheets (web page + PDF)

Each cheat sheet is published twice from one markdown source in `scripts/cheatsheets/<name>.md`: as a web page at `/cheatsheets/<name>/` (with the live row filter) and as a watermarked PDF. Edit the source, then rebuild and commit both outputs:

```bash
python scripts/build_cheatsheet_pages.py                  # web pages (no extra dependencies)
pip install markdown pygments pyyaml
npm i -g playwright && npx playwright install chromium   # once; Chromium renders the PDF
python scripts/build_cheatsheets.py                       # all PDFs, or name one: ... kql
```

- Every page is watermarked `iamjammie/hunt-sage` and carries a repo/licence footer; don't remove them.
- Keep each sheet to roughly 2-3 A4 pages: tables and short code blocks, no long prose.
- In a table cell, a literal pipe inside code must be written as `&#124;`.
- Link to site pages with `{{ site.baseurl }}/...` (converted to absolute URLs in the PDF). `check_links.py` verifies the links and that every source has a built PDF.
- New sheet: add the source, build the page and the PDF, add a row to `cheatsheets/index.md` and an entry in `_data/navigation.yml`.

## Hunt playbooks (`hunt/playbooks/`)

Front matter carries structured metadata that drives the playbook table and the coverage map:

```yaml
---
title: "Playbook: <Name>"
permalink: /hunt/playbooks/<slug>/
excerpt: "<one line>"
tactic: "<primary ATT&CK tactic name, e.g. Lateral Movement>"
attack: [T1021.001, T1021.006]      # every technique the playbook hunts
difficulty: 2                        # 1, 2 or 3
timebox: "2-3 hours"
data: [windows-security, sysmon, edr]   # keys from _data/datasources.yml (add a new key there first)
---
```

The front matter drives the header card (`{% include playbook-meta.html %}`, first line of the body), the playbook table on `/hunt/`, the playbook finder and the coverage map; the footer (`{% include playbook-footer.html %}`, last line) lists the Sigma rules and hypotheses mapped to the playbook automatically, so there is nothing to maintain by hand. Follow the existing structure: header include → `**Data used:**` line → **Background** → **Hypothesis** → **Data required** → **Hunt steps** (KQL and SPL, simplest first) → **Triage** → **Common false positives** → **Escalate when** → **Validate and operationalise**. State assumptions about log sources and field names, and note platform differences. Do not include working malware, weaponised exploit code, or instructions for attacking systems you don't own.

## Hunt packs (`hunt/packs/`)

A pack chains playbooks into a scenario campaign. Copy an existing pack: `pack: true`, `playbooks: [slugs]`, `attack: [ids]`, `duration`, then the fixed section order (kill chain table → telemetry → five-day plan → pivot map → detections → what good looks like → tabletop prompts → hardening → related). Reference hypotheses by their `H-xxx` id. The `playbooks` list links the pack from each playbook's footer; `attack` puts it on the coverage map.

## Hypotheses (`hunt/hypotheses.md`)

One table row per hypothesis, numbered sequentially (`H-123`), in the form *"If X is occurring, then we would see Y in Z"*. The last column links the playbook that runs it; `build_coverage.py` reads that link to list hypotheses on the playbook page. Ids are stable: never renumber, only append.

## Sigma rules (`research/sigma/`)

- File name: `T<technique-id>-<short-description>.yml` (e.g. `T1490-shadow-copy-deletion.yml`).
- Standard Sigma only: `title`, `id` (new UUIDv4), `status`, `description`, `references`, `author`, `date`, `logsource`, `detection`, `falsepositives`, `level`, `tags` (ATT&CK tactic **and** technique).
- `status` is `experimental` until you've emulated the technique and the rule fired (`test`), and `stable` only after ≥30 days in production with measured precision.
- Document specific false positives. Prefer stable fields (`OriginalFileName`, access masks, GUIDs) over easily-changed strings.
- Run `python scripts/build_coverage.py`; it regenerates the rule index and the coverage map from the rule file (there is nothing to add by hand).

## Style

- Plain, direct language; British or American spelling is fine, be consistent within a page.
- Tables for comparisons, code blocks (with language tag) for queries.
- Cite sources for factual claims (ATT&CK, vendor reports, documentation).

## Reporting problems

Open an issue with the page, what is wrong, and a correction if you have one. Inaccurate detection guidance is a bug.

## License

By contributing you agree that your contribution may be included under the repository's license terms (see the README).
