---
title: "8. Building a Hunt Program"
permalink: /learn/building-a-hunt-program/
excerpt: "People, process, tooling, metrics and reporting: how to make hunting repeatable and show its value."
---

## Why programs fail

| Failure mode | Symptom | Fix |
|---|---|---|
| **No protected time** | Hunting happens "when the queue is empty" (never) | Schedule hunt days; rotate analysts |
| **No data** | Every hunt ends in "we don't collect that" | Treat visibility gaps as first-class findings with owners |
| **No hand-off** | Findings sit in a slide deck | Every hunt ends with a ticket to detection engineering or IT |
| **Hero dependency** | One expert runs everything | Playbooks, templates, pairing |
| **Vanity metrics** | "We ran 50 hunts" | Measure outcomes (below) |

## Roles

| Role | Responsibility |
|---|---|
| **Hunt lead** | Backlog, prioritisation, quality, stakeholder comms |
| **Hunter / analyst** | Execute hunts; document |
| **Detection engineer** | Productionise detections; test |
| **CTI analyst** | Supply intel, enrich hypotheses |
| **Data / platform engineer** | Onboard log sources, fix parsing, manage retention |
| **IR lead** | Receive escalations; give feedback; supply lessons learned |

Small teams combine roles. Make sure *someone owns each responsibility*.

## Process

1. **Backlog.** Maintain a prioritised list of hunt ideas ([hypothesis cards]({{ site.baseurl }}/templates/#hunt-hypothesis-card)). Sources: intel, ATT&CK gaps, incidents, red-team reports.
2. **Cadence.** Example: 2-day hunt sprint per fortnight; one standing "baseline review" per month.
3. **Execution.** Use the [hunt loop]({{ site.baseurl }}/learn/hunting-process-and-frameworks/). Peer-review hunt plans for quality.
4. **Reporting.** One page per hunt, using the [hunt report template]({{ site.baseurl }}/templates/#hunt-report).
5. **Hand-off.** Detections to engineering; gaps to platform; hardening to IT; incidents to IR.
6. **Retrospective.** What did we learn? What should the next hunt be?

## Tooling baseline

- Central log platform (SIEM/data lake) with adequate retention
- EDR with advanced hunting / raw telemetry query
- Notebook environment for analysis
- Case/notes tool; version-controlled query repo
- Threat-intel platform (even a spreadsheet to begin)
- A lab for testing hypotheses and detections ([lab guide]({{ site.baseurl }}/labs/))

## Metrics that matter

Avoid "number of hunts". Prefer **outcomes**:

| Metric | What it shows |
|---|---|
| **Detections created from hunts** (and their later precision) | Hunting's lasting output |
| **Visibility gaps identified / closed** | Improving foundation |
| **ATT&CK techniques hunted** and **techniques with validated detections** | Coverage growth |
| **Confirmed incidents found by hunting** and their dwell time vs alert-found incidents | Direct value |
| **Hardening changes enacted** | Reduced attack surface |
| **Time from hypothesis to hand-off** | Efficiency |
| **% hunts producing a documented outcome** (including negative) | Process discipline |

Be wary of using "incidents found" as the sole KPI: a team that finds nothing in a well-defended environment may be doing excellent work.

## Maturity self-assessment (HMM-based)

Answer honestly:

| Question | Yes → |
|---|---|
| Do we collect endpoint, identity and network data centrally with ≥30 days retention? | HMM1+ |
| Do we routinely search for indicators from intel reports? | HMM1 |
| Do analysts follow written hunt procedures (playbooks)? | HMM2 |
| Do analysts create *new* hunt procedures and analytics from their own research? | HMM3 |
| Are successful hunts automatically converted into detections or automated analytics? | HMM4 |

Next steps by level:

- **HMM0 → 1**: centralise logs; define the minimum viable dataset ([chapter 4]({{ site.baseurl }}/learn/data-and-telemetry/)).
- **HMM1 → 2**: adopt playbooks (start with ours); protect hunt time.
- **HMM2 → 3**: encourage original hypotheses; add statistical/baseline hunts.
- **HMM3 → 4**: detection-as-code pipeline; automate repeatable hunts.

## Reporting to leadership

Lead with **risk and decisions**, not queries.

- *What we looked for and why* (threat-driven, mapped to business risk)
- *What we found* (incidents, gaps, hardening wins)
- *What changed as a result* (detections shipped, logging fixed)
- *What we need* (data sources, time, tooling), tied to the hunts that were blocked

## Legal, ethical and operational guardrails

- Get written authorisation scope for hunting, especially for user-content and privacy-sensitive data (email, HR systems).
- Use least privilege and audit your own hunt queries on sensitive data.
- Follow evidence-handling procedures if you suspect incident-grade findings: stop, preserve, escalate to IR.
- Never run attack emulation on production without change control.

## Your first 90 days (suggested)

| Days | Focus |
|---|---|
| 0-30 | Inventory data sources; fix top three gaps; stand up lab; run two playbooks as dry runs |
| 31-60 | Run six hunts from the backlog; ship ≥3 detections; present first findings |
| 61-90 | Introduce metrics; start a baseline hunt; document playbooks specific to your environment |

## Done with the path

Pick a [playbook]({{ site.baseurl }}/hunt/) and hunt.
