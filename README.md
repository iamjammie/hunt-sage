<!-- Banner -->
<p align="center">
  <img src="assets/images/hunt-sage-banner.png" alt="Hunt-Sage: seek, analyze, neutralize" width="100%">
</p>

<h1 align="center">Hunt-Sage</h1>
<p align="center"><strong>The one-stop threat hunting knowledge hub.</strong><br>
Theory, hunt playbooks, a hypothesis library, query patterns, printable cheat sheets, labs and CI-validated Sigma rules, all mapped to MITRE ATT&amp;CK.</p>

<p align="center">
  <a href="https://iamjammie.github.io/hunt-sage/"><img alt="Website" src="https://img.shields.io/badge/site-iamjammie.github.io%2Fhunt--sage-6AFB73?style=flat-square&labelColor=0A0F1F"></a>
  <a href="https://github.com/iamjammie/hunt-sage/actions/workflows/validate.yml"><img alt="Validate content" src="https://img.shields.io/github/actions/workflow/status/iamjammie/hunt-sage/validate.yml?branch=main&style=flat-square&label=validate&labelColor=0A0F1F"></a>
  <a href="https://github.com/iamjammie/hunt-sage/actions/workflows/pages.yml"><img alt="Deploy" src="https://img.shields.io/github/actions/workflow/status/iamjammie/hunt-sage/pages.yml?branch=main&style=flat-square&label=deploy&labelColor=0A0F1F"></a>
  <img alt="Playbooks" src="https://img.shields.io/badge/playbooks-20-6AFB73?style=flat-square&labelColor=0A0F1F">
  <img alt="Sigma rules" src="https://img.shields.io/badge/sigma%20rules-33-6AFB73?style=flat-square&labelColor=0A0F1F">
  <img alt="ATT&CK techniques" src="https://img.shields.io/badge/ATT%26CK%20techniques-99-6AFB73?style=flat-square&labelColor=0A0F1F">
  <a href="LICENSE.md"><img alt="Licence" src="https://img.shields.io/badge/licence-educational%20use-2C3542?style=flat-square&labelColor=0A0F1F"></a>
</p>

<p align="center">
  <a href="https://iamjammie.github.io/hunt-sage/"><strong>Visit the site</strong></a> ·
  <a href="https://iamjammie.github.io/hunt-sage/hunt/">Playbooks</a> ·
  <a href="https://iamjammie.github.io/hunt-sage/hunt/hypotheses/">Hypothesis library</a> ·
  <a href="https://iamjammie.github.io/hunt-sage/research/mitre-mapping/">ATT&amp;CK coverage</a> ·
  <a href="https://iamjammie.github.io/hunt-sage/cheatsheets/">Cheat sheets</a> ·
  <a href="https://github.com/iamjammie/hunt-sage/issues">Report an issue</a>
</p>

---

## What is Hunt-Sage?

A public knowledge base that takes you from **"what is threat hunting?"** to **running hunts, shipping detections and building a hunt program**, with the theory and the practical, copy-paste-ready material in one place. Everything is defensive, vendor-neutral where it can be, and written for people who have a SIEM open in the next tab.

```text
Learn the theory → pick a hypothesis → run a playbook → practise in the lab → write the Sigma rule → track it on the coverage map
```

## What's inside

| Section | What you get | Start here |
|---|---|---|
| 📘 **Learn** | 9 chapters + glossary (90+ terms): hunting vs. detection vs. IR, the hunt loop, PEAK / TaHiTI / Sqrrl / HMM, hypotheses and intel, data & telemetry, hunting techniques, adversary tradecraft, detection engineering, building a program, **careers & 40 interview questions** | [`learn/`](learn/index.md) |
| 🎯 **Hunt** | **20 playbooks**, each with hypothesis, data checks, **KQL + SPL** queries, triage, false positives, escalation criteria, Atomic Red Team emulation and hardening: phishing & initial execution, PowerShell, LOLBins, DLL hijacking, process injection, LSASS, Kerberoasting, DCSync, **AD CS abuse**, AD discovery & BloodHound, lateral movement, RDP/WinRM anomalies, persistence, defense evasion, C2/DNS, exfiltration, ransomware precursors, web shells, Linux, cloud & identity | [`hunt/`](hunt/index.md) |
| 💡 **Hypothesis library** | 100+ ready-to-run hunt hypotheses (H-001…) in "if X, then Y in Z" form, mapped to ATT&CK, data sources, analytical technique and playbook | [`hunt/hypotheses.md`](hunt/hypotheses.md) |
| 🔎 **Query index** | 29 reusable hunting patterns in KQL and SPL side by side: rarity stacking, baselining, first-seen, beacon timing, process↔network joins, cloud sign-in anomalies | [`hunt/query-index.md`](hunt/query-index.md) |
| 🧾 **Cheat sheets** | 8 watermarked A4 PDFs: Windows & Sysmon event IDs, Linux logs/auditd, KQL, Splunk SPL, Zeek/network, LOLBins, AD attack artefacts | [`cheatsheets/`](cheatsheets/index.md) |
| 🧪 **Labs** | Build a hunting lab, Atomic Red Team emulate-then-detect exercises, public datasets and ranges | [`labs/`](labs/index.md) |
| 🧬 **Research** | **33 ATT&CK-mapped Sigma rules** validated in CI, an **ATT&CK coverage heatmap generated from the content**, an importable **Navigator layer**, and detection-engineering notes | [`research/`](research/index.md) |
| 📋 **Templates** | Hunt hypothesis card, hunt report, backlog, data-source assessment, IR hand-off | [`templates/`](templates/index.md) |
| 📚 **Resources** | Tooling, rule repositories, reports, podcasts, newsletters, courses, books, communities | [`resources/`](resources/index.md) |
| 📝 **Blog** & 🚩 **CTF** | Field notes, a worked stacking/baselining example, an end-to-end case study, and three defender-focused CTF challenges | [`_posts/`](_posts), [`_ctf/`](_ctf) |

## Repository layout

```text
learn/              Theory chapters, careers guide, glossary
hunt/               Playbook library, hypothesis library, query index
  playbooks/        20 hunt playbooks (front matter drives the tables and the coverage map)
cheatsheets/        Built PDF cheat sheets (sources in scripts/cheatsheets/)
labs/               Lab build, emulation exercises, datasets
templates/          Hunt templates
resources/          Curated tools, rule repos, reading, courses, communities
research/
  sigma/            Sigma rules (validated by CI)
  mitre-mapping/    Coverage map page + ATT&CK Navigator layer (generated)
_data/attack.yml    ATT&CK technique names/tactics used by the coverage builder
_data/coverage.yml  Generated coverage data (do not edit)
_includes/          Generated heatmap + rule tables, theme masthead override
_posts/ _ctf/       Blog posts and CTF challenges
assets/             Theme CSS/JS, brand images (SVG sources in assets/images/src/)
scripts/            Validators and builders used by CI
```

## How the pieces fit

```text
 intel / incident ─► hypothesis (hunt/hypotheses) ─► playbook (hunt/playbooks) ─► lab emulation (labs)
                                                                   │
                                                                   ▼
                     coverage map ◄── build_coverage.py ◄── Sigma rule (research/sigma) ◄── tuning
```

Playbooks declare the techniques they hunt in front matter, Sigma rules carry ATT&CK tags, and `scripts/build_coverage.py` turns both into the heatmap, the rule index and a Navigator layer. If a page says a rule exists, the rule exists; CI fails otherwise.

## Quality checks

CI runs on every push and pull request:

```bash
pip install -r scripts/requirements.txt
python scripts/validate_rules.py        # Sigma syntax, metadata, ATT&CK tags, Splunk/KQL conversion, index listing
python scripts/check_links.py           # front matter, internal links and anchors, nav entries
python scripts/build_coverage.py --check # generated coverage data is up to date
bundle exec jekyll build --strict_front_matter   # the site builds
```

### Rebuilding generated files

```bash
python scripts/build_coverage.py        # coverage map, rule index, Navigator layer
python scripts/build_images.py          # banner, favicon, social card, post teasers (needs rsvg-convert)
python scripts/build_cheatsheets.py     # PDF cheat sheets (needs Node.js + Playwright Chromium)
```

### Local preview

```bash
bundle install
bundle exec jekyll serve --livereload   # http://localhost:4000/hunt-sage/
```

> Sigma rules are marked `experimental` until validated in a lab (`test`) and in production (`stable`). Queries in the playbooks are starting points: adapt field names to your data schema and test them before relying on them.

## Built with

- GitHub Pages via GitHub Actions (static, no backend, no cookies, no tracking)
- Jekyll + the **Minimal Mistakes** theme, with a Hunt-Sage skin, dark/light toggle, copy buttons on every query and auto-linked ATT&CK ids
- Markdown, YAML (Sigma), a little CSS/JS, Python for the builders

## Roadmap

| Milestone | Status |
|---|:---:|
| Learn path, playbook library, cheat sheets, labs, templates | ✅ |
| Sigma rule pack with CI validation | ✅ 33 rules |
| Playbooks for RDP/WinRM anomalies, DLL hijacking, process injection, AD CS abuse | ✅ |
| Phishing/initial execution and AD discovery/BloodHound playbooks | ✅ |
| Hypothesis library, query index, generated ATT&CK coverage + Navigator layer | ✅ |
| Lab-validate rules and promote `experimental` → `test` | 🚧 |
| UAC bypass, network share discovery, automated exfiltration playbooks (the remaining map gaps) | 🔜 |
| Splunk ESA / Fortinet FortiAnalyzer rule packs | 🔜 |
| Downloadable CTF challenge artefacts | 🔜 |
| Community submission workflow & contributor hall of fame | 🕒 |

## Contributing

Contributions are welcome: playbooks, Sigma rules, hypotheses, corrections, new challenge ideas. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for conventions and the local checks to run, and use the issue templates for proposals.

1. Fork the repo and create a branch
2. Make your change, run the scripts above, commit any regenerated files
3. Open a pull request with a clear explanation

## Contact

- 📧 hunt-sage@gov.in
- 🔗 https://www.linkedin.com/in/ashok-kumar-5b62819b
- 🐙 https://github.com/iamjammie

## Responsible use

Everything here is for **defensive** purposes in environments you own or are authorised to test. Run attack emulation only in isolated labs or with written approval.

## Licence

All original content is © 2025-2026 iamjammie. Educational and defensive use is permitted with attribution; see [LICENSE.md](LICENSE.md).

---

<p align="center"><strong>Crafting defenders for the digital battlefield.</strong><br>© Hunt-Sage</p>
