---
title: "7. Detection Engineering"
permalink: /learn/detection-engineering/
excerpt: "Turn a finished hunt into a durable detection: design, write in Sigma, test, tune, deploy and maintain."
---

A hunt ends when you either find something or conclude there is nothing to find. **Detection engineering** is what makes the result permanent so nobody has to hunt it by hand again.

## Detection lifecycle

```text
 Hunt / intel ─► Requirements ─► Design ─► Develop ─► Test ─► Deploy ─► Tune ─► Retire/Review
       ▲                                                                       │
       └───────────────────────────────────────────────────────────────────────┘
```

| Stage | Questions / actions |
|---|---|
| **Requirements** | Which technique? What is the threat model? What is acceptable alert volume? |
| **Design** | Which log source? Atomic indicator or behavioural correlation? What response is expected? |
| **Develop** | Write the rule in Sigma; add metadata, references, false positives |
| **Test** | Positive test (emulate technique) + negative test (replay benign logs) |
| **Deploy** | Convert to platform query; stage as non-alerting first |
| **Tune** | Add allow-lists for documented benign behaviour; measure precision |
| **Review/retire** | Does it still fire? Still relevant? Telemetry changed? |

## Hunt query → detection: what changes

| Hunt query | Production detection |
|---|---|
| Wide net, analyst reviews thousands of rows | Narrow, each alert actionable |
| Run on demand | Scheduled / streaming |
| Context in analyst's head | Context in the alert (entities, MITRE tags, triage steps) |
| May be noisy | Must have measured false-positive rate and an owner |

## Design patterns

1. **Atomic indicator**: single event matches (e.g. `vssadmin delete shadows`). Simple, high-signal for rare activity.
2. **Threshold / frequency**: N events within T (e.g. >20 distinct SPNs in 5 minutes).
3. **Sequence / chain**: A then B within window (e.g. Office spawns script host, then script host makes a network connection).
4. **Rarity / first-seen**: new for entity or fleet.
5. **Statistical / anomaly**: deviation from baseline.
6. **Correlation/risk-based**: many low-fidelity signals add risk score per entity; alert when it crosses a threshold (reduces alert fatigue).

## The Pyramid of Pain for detections

Prefer rules at the top of the pyramid (behaviours, tools' invariant properties) over hashes and IPs. Pair: *behaviour rule* (durable) + *IOC rule* (cheap, short-lived, with expiry date).

## Writing rules in Sigma

[Sigma](https://sigmahq.io/) is a vendor-neutral rule format ("YARA for logs"). Write once, convert to Splunk SPL, KQL, Elastic, QRadar and more via pySigma backends.

Minimal rule skeleton:

```yaml
title: Short, specific title in Title Case
id: 00000000-0000-0000-0000-000000000000   # uuid4
status: experimental            # experimental | test | stable
description: What it detects and why it matters.
references:
  - https://attack.mitre.org/techniques/T1xxx/
author: your-name
date: 2025-01-01
logsource:
  category: process_creation    # or product/service
  product: windows
detection:
  selection:
    Image|endswith: '\tool.exe'
    CommandLine|contains: '--suspicious'
  filter_legit:
    ParentImage|endswith: '\approved.exe'
  condition: selection and not filter_legit
falsepositives:
  - Specific legitimate use
level: high                     # informational | low | medium | high | critical
tags:
  - attack.execution
  - attack.t1059
```

Field modifiers you will use constantly: `|contains`, `|startswith`, `|endswith`, `|re`, `|all` (all values must match), `|cidr`, `|base64offset|contains`, `|windash` (handles `-` vs `/`).

### Authoring principles

- **One rule, one behaviour.** Don't build a god rule.
- **Match on stable fields**: `OriginalFileName` over `Image` when available; `CommandLine|contains` with `|windash` for switches.
- **Document false positives specifically** ("SCCM client during software deployment"), not generically.
- **Set `level` by expected precision × impact**, not by how scary the technique is.
- **Tag with ATT&CK** so coverage can be computed.
- **Avoid case-sensitive traps**: Sigma matching is case-insensitive by default; keep that in mind when converting to platforms that are not.

## Testing detections

Detection without testing is hope. Three layers:

| Layer | How |
|---|---|
| **Syntax / schema** | `sigma check`, pySigma validators, CI on every PR (this repo's [`scripts/validate_rules.py`](https://github.com/iamjammie/hunt-sage/blob/main/scripts/validate_rules.py)) |
| **Positive test** | Emulate the technique ([Atomic Red Team]({{ site.baseurl }}/labs/emulate-and-detect/)) and confirm the alert fires in your pipeline |
| **Negative / regression test** | Replay 30 days of production-like logs through the rule; count hits; review each |

Track for each rule: **last tested date**, **test method**, **precision (true positives ÷ alerts)**, and **owner**.

## Tuning without blinding yourself

- Prefer **narrow, documented exclusions** (specific parent + command line + host group) over blanket ones.
- Exclusions should be **data-driven**: show the benign population, then exclude it.
- Put exclusions in version control with a reason and review date.
- Beware of exclusion by path alone: attackers drop into the path you excluded.
- Re-tune after environment changes (new EDR, new management tool).

## Detection-as-code

Treat detections like software:

1. Rules in Git; changes by pull request with review
2. CI: lint, schema-validate, convert to target backends, run unit tests
3. CD: deploy to SIEM via API / Terraform / content-management tooling
4. Metrics from production (alert volume, closure reasons) feed back into the repo

This repo's rules are validated in CI. See the [workflow](https://github.com/iamjammie/hunt-sage/blob/main/.github/workflows/validate.yml) for a minimal example.

## Measuring coverage honestly

| Metric | Meaning | Trap |
|---|---|---|
| Techniques with ≥1 rule / total | Breadth | One weak rule counts the same as ten strong ones |
| Techniques **tested** with emulation | Validated coverage | Needs lab discipline |
| Mean time to tune | Operational health | |
| Alert precision by rule | Quality | Needs consistent closure codes |
| Data-source coverage (% hosts reporting) | Foundation | A rule on a log you don't collect is dead |

See also: [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/), [Sigma rules]({{ site.baseurl }}/research/sigma/), [detection engineering notes]({{ site.baseurl }}/research/mitre-detection-engineering/).

## Next

→ [8. Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/)
