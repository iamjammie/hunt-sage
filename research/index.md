---
title: "Research & Detection Content"
permalink: /research/
excerpt: "ATT&CK coverage, Sigma detection rules and detection-engineering notes: where hunts become durable detections."
toc: false
---

| Resource | What it is |
|---|---|
| [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) | {{ site.data.coverage.summary.techniques }} techniques with their playbook, Sigma rule and write-ups, plus a downloadable ATT&CK Navigator layer |
| [Sigma rules]({{ site.baseurl }}/research/sigma/) | {{ site.data.coverage.summary.rules }} vendor-neutral detection rules with false positives and tuning notes, validated by CI |
| [Detection engineering notes]({{ site.baseurl }}/research/mitre-detection-engineering/) | Technique → telemetry → detection → test mappings; working notebook |

## How research feeds the rest of the site

```text
 Blog / intel ─► Hypothesis ─► Hunt playbook ─► Sigma rule ─► Coverage map ─► New backlog
```

- **Theory:** [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/) explains the lifecycle.
- **Practice:** every [hunt playbook]({{ site.baseurl }}/hunt/) ends with an "Operationalise" section linking to its rule.
- **Validation:** [Emulate → detect]({{ site.baseurl }}/labs/emulate-and-detect/) shows how to prove the rule fires.

## Contributing a rule

Open a pull request adding a Sigma file to `research/sigma/`, then run `python scripts/build_coverage.py` to regenerate the rule index and coverage map. Rules are validated by CI (`scripts/validate_rules.py`): see [CONTRIBUTING](https://github.com/iamjammie/hunt-sage/blob/main/CONTRIBUTING.md).
