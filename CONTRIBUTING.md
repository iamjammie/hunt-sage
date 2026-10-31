# Contributing to Hunt-Sage

Thanks for helping build the one-stop threat hunting reference. Everything must be **defensive**, **accurate** and **useful in practice**.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r scripts/requirements.txt
python scripts/validate_rules.py
python scripts/check_links.py
```

Both scripts must pass; CI runs them on every PR.

## Adding or editing pages

- Every page needs front matter with `title`, `permalink` and a one-line `excerpt`.
- **Internal links must use `{{ site.baseurl }}`**, e.g. `[Playbooks]({{ site.baseurl }}/hunt/)`. A bare `/hunt/` works locally but breaks on GitHub Pages.
- Add new pages to the right sidebar in `_data/navigation.yml` (paths there are **without** the baseurl) and to the section index page.
- Avoid `{{` and `{%` inside code blocks (Jekyll treats them as Liquid). Use `{% raw %}...{% endraw %}` if you must.
- Write for practitioners: concrete queries, field names, thresholds, and the *why*.

## Hunt playbooks (`hunt/playbooks/`)

Follow the existing structure: metadata table → **Hypothesis** → **Data required** → **Hunt steps** (KQL and SPL, simplest first) → **Triage** → **Common false positives** → **Escalate when** → **Validate and operationalise**. State assumptions about log sources and field names, and note platform differences. Do not include working malware, weaponised exploit code, or instructions for attacking systems you don't own.

## Sigma rules (`research/sigma/`)

- File name: `T<technique-id>-<short-description>.yml` (e.g. `T1490-shadow-copy-deletion.yml`).
- Standard Sigma only: `title`, `id` (new UUIDv4), `status`, `description`, `references`, `author`, `date`, `logsource`, `detection`, `falsepositives`, `level`, `tags` (ATT&CK tactic **and** technique).
- `status` is `experimental` until you've emulated the technique and the rule fired (`test`), and `stable` only after ≥30 days in production with measured precision.
- Document specific false positives. Prefer stable fields (`OriginalFileName`, access masks, GUIDs) over easily-changed strings.
- Add the rule to the table in `research/sigma/index.md` and to the coverage map (`research/mitre-mapping/index.md`).

## Style

- Plain, direct language; British or American spelling is fine, be consistent within a page.
- Tables for comparisons, code blocks (with language tag) for queries.
- Cite sources for factual claims (ATT&CK, vendor reports, documentation).

## Reporting problems

Open an issue with the page, what is wrong, and a correction if you have one. Inaccurate detection guidance is a bug.

## License

By contributing you agree that your contribution may be included under the repository's license terms (see the README).
