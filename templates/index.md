---
title: "Hunt Templates"
permalink: /templates/
excerpt: "Copy-paste templates for hunt hypotheses, hunt reports, a hunt backlog and a data-source assessment."
---

Copy these into your wiki, ticketing system or Git repo. Keep them short: a template people fill in beats a perfect one they skip.

## Hunt hypothesis card

One card per hunt idea. These make up your backlog.

```markdown
# HUNT-YYYY-NNN: <short title>

**Owner:** <name>        **Created:** <date>        **Status:** Backlog | Planned | Active | Done | Dropped
**Hunt type:** Hypothesis-driven | Intel-driven | Baseline/anomaly | Situational
**Priority score:** Relevance (1-3) × Impact (1-3) × Visibility (1-3) × Effort-inverse (1-3) = <n>

## Trigger
<intel report, ATT&CK gap, incident, CVE, anomaly...> with link

## Hypothesis
If <adversary behaviour> is occurring, we will observe <observable> in <data source>.

## ATT&CK
Tactic(s): <...>      Technique(s): <Txxxx[.xxx]>

## Scope
Assets / OUs / accounts: <...>      Time window: <last 30 days>

## Data required
- [ ] <source 1> (coverage verified: <date>, <% of hosts>)
- [ ] <source 2>

## Approach (queries / techniques)
<search | stacking | baseline | timing | sequence ...> Link to saved queries

## Success / failure criteria
Confirmed if: <...>      Refuted if: <...> (and data confirmed present)

## Time-box
<2h | 1d | 1w>

## Expected outputs
Detection | Hardening | Visibility fix | IR hand-off
```

## Hunt report

One page. Written for the next hunter and for leadership.

```markdown
# Hunt Report: HUNT-YYYY-NNN <title>

**Hunter(s):** <...>   **Dates:** <start - end>   **Time spent:** <hours>
**Outcome:** True positive found | Benign explained | Inconclusive | Negative (no evidence) | Blocked by data gap

## 1. Summary (3 sentences)
What we looked for, what we found, what we recommend.

## 2. Hypothesis and ATT&CK mapping
<hypothesis>      Techniques: <...>

## 3. Scope and data
Assets: <...>   Window: <...>
Data sources used and **coverage** (e.g. Sysmon on 412/430 servers; 18 unreported): <...>

## 4. Method
Key queries (link or paste), techniques used, tools.

## 5. Findings
| # | Finding | Evidence | Verdict (TP/FP/Benign/Unknown) | Confidence |
|---|---------|----------|--------------------------------|------------|

### Timeline (if TP)
| Time (UTC) | Host | Event | Source |
|---|---|---|---|

## 6. Benign activity documented (allow-list candidates)
| Pattern | Reason benign | Owner who confirmed |
|---|---|---|

## 7. Visibility gaps
| Gap | Impact | Fix | Owner | Ticket |
|---|---|---|---|---|

## 8. Actions
| Type | Description | Owner | Due | Ticket |
|---|---|---|---|---|
| Detection | Sigma rule for <...> | | | |
| Hardening | <...> | | | |
| IR hand-off | <...> | | | |
| Follow-up hunt | <...> | | | |

## 9. Metrics
Detections created: <n>   Gaps found: <n>   Incidents opened: <n>   Techniques validated: <list>

## 10. Lessons learned
```

## Hunt backlog

A simple table is enough.

| ID | Title | Technique | Type | Score | Data ready? | Owner | Status |
|---|---|---|---|---|---|---|---|
| HUNT-2025-001 | PowerShell encoded commands | T1059.001 | Hypothesis | 24 | ✔ | | Planned |
| HUNT-2025-002 | Run-key & task stacking | T1547.001, T1053.005 | Baseline | 18 | ✔ | | Backlog |
| HUNT-2025-003 | Kerberoasting | T1558.003 | Hypothesis | 27 | DC audit missing | | Blocked |

Sources for the backlog: [ATT&CK coverage gaps]({{ site.baseurl }}/research/mitre-mapping/), intel reports, pen-test/red-team findings, incident lessons, and the [playbook library]({{ site.baseurl }}/hunt/).

## Data source assessment

Run this before big hunts and quarterly.

| Source | Collected? | Coverage (% in-scope assets) | Retention | Fields parsed? | Latency | Owner | Notes |
|---|---|---|---|---|---|---|---|
| Windows Security (DC) | | | | | | | 4662/4768/4769 audited? |
| Windows Security (servers/workstations) | | | | | | | 4688 + command line? |
| Sysmon / EDR process | | | | | | | |
| PowerShell 4104 | | | | | | | |
| DNS | | | | | | | |
| Proxy / firewall | | | | | | | |
| Cloud IdP sign-ins & audit | | | | | | | |
| Cloud control plane (CloudTrail etc.) | | | | | | | |
| Linux auditd / auth | | | | | | | |

## Detection handoff checklist

Before a hunt query becomes a detection:

- [ ] Rule written in Sigma, tagged with ATT&CK, `status: experimental|test`
- [ ] Tested positive (emulation) and negative (historic data replay)
- [ ] False-positive sources documented; exclusions are specific and justified
- [ ] Severity and response/triage steps written
- [ ] Owner assigned; review date set
- [ ] Added to the [coverage map]({{ site.baseurl }}/research/mitre-mapping/)

## Handoff package to IR

```text
What we found (1-2 sentences) + confidence
Affected assets/accounts (hostnames, IPs, UPNs)
Timeline (UTC)
Indicators (hashes, domains, IPs, file paths, commands)
Queries used (links)
Evidence preserved (where)
Recommended immediate actions (isolate, disable account, reset credentials)
Unknowns / next questions
```
