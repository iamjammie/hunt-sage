---
title: "1. What Is Threat Hunting?"
permalink: /learn/what-is-threat-hunting/
excerpt: "Hunting is the proactive, human-led search for adversary activity that automated detection has not already surfaced."
---

## A working definition

> **Threat hunting** is the proactive, iterative, hypothesis-driven search through your environment for adversary activity that evaded existing detections.

Three words matter:

- **Proactive**: you start without an alert.
- **Hypothesis-driven**: you start with a testable idea about how an adversary could be operating, not with "let's look at the logs and see".
- **Evaded**: the point is to find what your controls missed. Re-running an existing alert is not a hunt.

## Hunting, detection, monitoring and IR

| | Monitoring / alert triage | Detection engineering | Threat hunting | Incident response |
|---|---|---|---|---|
| Starts from | An alert | A technique or threat | A hypothesis | A confirmed (or probable) incident |
| Question | "Is this alert real?" | "How do we reliably alert on X?" | "Is X happening here, and would we know?" | "What happened, how far did it go, how do we evict?" |
| Cadence | Continuous | Continuous | Time-boxed campaigns | On demand |
| Output | Ticket closed / escalated | Rule in production | Findings, new detections, visibility gaps | Contained and remediated incident |
| Scales by | Automation | Automation | Human skill + tooling | Process + people |

They form a loop, not a ladder. Hunts **produce** detections (chapter 7), detections reduce the noise hunters wade through, and IR findings **seed** new hunts.

## Why hunt?

1. **Dwell time.** Every day an intruder is undetected is a day to escalate privileges, steal data or stage ransomware. Mandiant's M-Trends reports show global median dwell time falling from months to around ten days in recent years, but that is a median: the tail is long, and compromises first reported by an external party (rather than found internally) have historically had longer dwell times.
2. **Detections are brittle.** Rules key on known indicators or known behaviours. Adversaries adapt, and some behaviours (valid accounts, admin tools, cloud APIs) look legitimate event by event.
3. **Assumed breach.** If you design your security on the premise that someone may already be inside, hunting is the verification step.
4. **Visibility and engineering gaps.** A hunt that finds nothing but reveals that you cannot see PowerShell script blocks or DNS queries is still a high-value result.
5. **Detection pipeline.** Hunts are the cheapest way to prototype detections against real data.

## Types of hunt

| Type | Starting point | Example |
|---|---|---|
| **Hypothesis-driven** | A behaviour-level idea, often from ATT&CK or a threat report | "Attackers who gained domain admin use DCSync; look for replication requests from non-DCs." |
| **Intelligence-driven (IOC/TTP)** | A specific intel report, indicator or actor profile | A vendor report lists a C2 domain pattern and a scheduled-task persistence trick; search for both. |
| **Data-driven / baseline-and-anomaly** | The data itself: rare, new or odd things | Stack all parent→child process pairs; investigate the ones seen on <3 hosts. |
| **Situational / entity-driven** | A crown jewel, a weak spot or an event | After a new CVE in an edge device, hunt the device's logs and downstream hosts. |

Mature teams use all four. Beginners should start with hypothesis-driven hunts on well-understood techniques, which is what the [playbooks]({{ site.baseurl }}/hunt/) are built for.

## What a hunt is *not*

- Running a vendor's saved query and closing the tab.
- A one-off IOC sweep (useful, but that is intel matching, not hunting).
- Pentesting. Hunts look for real adversaries, red teams *simulate* them.
- A substitute for logging, patching or identity hygiene.

## Prerequisites for effective hunting

You need four things. Missing one caps your results.

1. **Data**: centralised, searchable, retained long enough (chapter 4).
2. **Knowledge of normal**: you cannot spot abnormal without a baseline.
3. **Knowledge of the adversary**: tradecraft and TTPs (chapter 6).
4. **Time and mandate**: protected, scheduled time and permission to query and pivot.

## Outcomes of a hunt

A successful hunt is **not** only "found an intruder". Track all of these:

| Outcome | Example |
|---|---|
| Confirmed compromise → hand off to IR | Beaconing host with a rogue scheduled task |
| New or improved **detection** | Sigma rule for the technique |
| Closed **visibility gap** | Enabled PowerShell Script Block Logging on servers |
| **Hardening** recommendation | Disable NTLM from servers to DCs; remove local admin |
| Documented **negative result** | "No evidence of Kerberoasting over 90 days; RC4 disabled domain-wide" |

## Next

→ [2. The hunting process & frameworks]({{ site.baseurl }}/learn/hunting-process-and-frameworks/)
