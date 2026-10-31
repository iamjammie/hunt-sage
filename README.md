<!-- Banner -->
<p align="center">
  <img src="assets/images/hunt-sage-banner.png" alt="Hunt-Sage Banner" width="80%">
</p>

<h1 align="center">🔍 Hunt-Sage: The One-Stop Threat Hunting Hub</h1>
<p align="center">
  Seek. Analyze. Neutralize.
</p>

<p align="center">
  <a href="https://iamjammie.github.io/hunt-sage/"><strong>🌐 Visit the Website</strong></a> •
  <a href="https://github.com/iamjammie/hunt-sage/issues">Report Issue</a> •
  <a href="https://www.linkedin.com/in/ashok-kumar-5b62819b">Connect</a>
</p>

---

## 📌 What is Hunt-Sage?

A public knowledge base that takes you from **"what is threat hunting?"** to **running hunts, shipping detections and building a hunt program**, with both the theory and the practical, copy-paste-ready material in one place.

> _Built by iamjammie_

## 🗺️ What's inside

| Section | What you get | Start here |
|--------|--------------|-----------|
| 📘 **Learn** (theory) | 8 chapters + glossary: hunting vs. detection vs. IR, the hunt loop, PEAK / TaHiTI / Sqrrl / HMM, hypotheses and intel, data & telemetry, hunting techniques, adversary tradecraft, detection engineering, building a program | [`learn/`](learn/index.md) |
| 🎯 **Hunt** (practice) | 14 playbooks, each with hypothesis, data checks, **KQL + SPL** queries, triage, false positives, escalation criteria, emulation and hardening: PowerShell, LOLBins, LSASS, Kerberoasting, DCSync, lateral movement, persistence, defense evasion, C2/DNS, exfiltration, ransomware precursors, web shells, Linux, cloud & identity | [`hunt/`](hunt/index.md) |
| 🧾 **Cheat sheets** | Windows & Sysmon event IDs, Linux logs/auditd, KQL, Splunk SPL, Zeek/network, LOLBins, AD attack artefacts | [`cheatsheets/`](cheatsheets/index.md) |
| 🧪 **Labs** | Build a hunting lab, Atomic Red Team emulate-then-detect exercises, public datasets and ranges | [`labs/`](labs/index.md) |
| 🧬 **Research** | 20 ATT&CK-mapped **Sigma rules**, a coverage map and detection-engineering notes | [`research/`](research/index.md) |
| 📋 **Templates** | Hunt hypothesis card, hunt report, backlog, data-source assessment, IR hand-off | [`templates/`](templates/index.md) |
| 📚 **Resources** | Frameworks, tools, books, courses, communities | [`resources/`](resources/index.md) |
| 📝 **Blog** & 🚩 **CTF** | Field notes, an end-to-end case study, and a defender-focused CTF | [`_posts/`](_posts), [`_ctf/`](_ctf) |

### Suggested path

```text
Learn the theory → run a playbook → practise in the lab → write the Sigma rule → track it on the coverage map
```

## 🛠️ Repository layout

```text
learn/            Theory chapters
hunt/playbooks/   Hunt playbooks
cheatsheets/      One-page references
labs/             Lab build, emulation exercises, datasets
templates/        Hunt templates
resources/        Curated tools, books, courses
research/         Sigma rules, ATT&CK map, detection engineering notes
_posts/ _ctf/     Blog posts and CTF challenges
scripts/          Validation (Sigma rules, internal links) used by CI
```

## ✅ Quality checks

CI runs on every push and pull request:

```bash
pip install -r scripts/requirements.txt
python scripts/validate_rules.py   # Sigma syntax, metadata, ATT&CK tags, Splunk/KQL conversion, index listing
python scripts/check_links.py      # front matter, internal links and anchors, nav entries
```

> Sigma rules are marked `experimental` until validated in a lab (`test`) and in production (`stable`). Queries in the playbooks are starting points: adapt field names to your data schema and test them before relying on them.

## 🛠️ Built With

- GitHub Pages (static, no backend, no cookies; privacy by design)
- Jekyll + **Minimal Mistakes** theme
- Markdown, YAML (Sigma), a little CSS/JS
- 🌗 Dark / light theme toggle

## 🚀 Roadmap

| Milestone | Status |
|----------|:------:|
| Learn path, playbook library, cheat sheets, labs, templates | ✅ Done |
| Sigma rule pack with CI validation (20 rules) | ✅ Done |
| Lab-validate rules and promote `experimental` → `test` | 🚧 In progress |
| Playbooks for RDP/WinRM anomalies, DLL hijacking, process injection, AD CS abuse | 🔜 |
| Splunk ESA / Fortinet FortiAnalyzer rule packs | 🔜 |
| Downloadable CTF challenge artifacts | 🔜 |
| Community submission workflow & contributor hall of fame | 🕒 |

## 🤝 Contributing

Contributions are welcome: playbooks, Sigma rules, corrections, new challenge ideas. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for conventions and the local checks to run.

1. Fork the repo and create a branch
2. Make your change and run the two scripts above
3. Open a PR with a clear explanation

## 📬 Contact

📧 hunt-sage@gov.in  
🔗 https://www.linkedin.com/in/ashok-kumar-5b62819b  
🐙 GitHub: https://github.com/iamjammie

## ⚠️ Responsible use

Everything here is for **defensive** purposes in environments you own or are authorised to test. Run attack emulation only in isolated labs or with written approval.

## 📄 License

All **original content** in this repository is © 2025 iamjammie – All Rights Reserved.  
Educational use permitted with proper attribution.

---

<p align="center">
  <strong>Crafting defenders for the digital battlefield.</strong><br>
  © Hunt-Sage | Built with 🧠 + 💻
</p>
