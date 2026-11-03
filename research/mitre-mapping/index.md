---
title: "MITRE ATT&CK Detection Coverage Map"
permalink: /research/mitre-mapping/
layout: single
classes: wide
toc: false
excerpt: "Every technique Hunt-Sage covers, generated from the playbooks, Sigma rules and write-ups themselves, with an importable ATT&CK Navigator layer."
---

This page is **generated from the content**: each [playbook]({{ site.baseurl }}/hunt/) declares the techniques it hunts, each [Sigma rule]({{ site.baseurl }}/research/sigma/) carries ATT&CK tags, and write-ups list the techniques they cover. `scripts/build_coverage.py` turns that into the heatmap, the tables and a Navigator layer, and CI fails if the page is out of date. Use it to pick your next hunt: every dashed cell and every 🔍 is a gap.

**Download:** [ATT&CK Navigator layer (JSON)]({{ site.baseurl }}/research/mitre-mapping/hunt-sage-navigator-layer.json): open [attack.mitre.org Navigator](https://mitre-attack.github.io/attack-navigator/), choose *Open Existing Layer → Upload from local*, and overlay it on your own coverage.

## Status key

| Icon | Meaning |
|------|---------|
| ✅ | Sigma rule published (usually alongside a hunt playbook) |
| 🔍 | Hunt playbook / queries only, no Sigma rule yet |
| 📝 | Write-up (blog / case study / CTF) only |
| 🔜 | Planned, nothing published yet |

> Status means *content exists on this site*, not that the technique is *validated in your environment*. Prove it with [Emulate → Detect]({{ site.baseurl }}/labs/emulate-and-detect/) and track your own results in the [hunt backlog template]({{ site.baseurl }}/templates/).

## Heatmap

{% include coverage-heatmap.html %}

## Reading the map

- A technique can sit under several tactics (ATT&CK does the same), so counts in the tactic headers add up to more than the number of techniques.
- Parent techniques (for example `T1218`) and sub-techniques (`T1218.005`) are listed separately: a playbook that covers a family maps to the parent, a rule maps to the exact sub-technique it detects.
- "Rule" does not mean "alert": every Sigma rule here starts `experimental` and needs the tuning described on the [Sigma page]({{ site.baseurl }}/research/sigma/) before it belongs in production.

## Contributing coverage

1. Write the content: a playbook (add `attack: [T1234, T1234.001]` to its front matter), a Sigma rule (ATT&CK tags), or a post (`attack:` list).
2. If the technique is new to the site, add its id, name and tactics to `_data/attack.yml`.
3. Run `python scripts/build_coverage.py` and commit the regenerated files.

*[Suggest a technique or submit a rule →](https://github.com/iamjammie/hunt-sage/issues)*
