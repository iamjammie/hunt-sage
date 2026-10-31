---
title: "2. The Hunting Process & Frameworks"
permalink: /learn/hunting-process-and-frameworks/
excerpt: "The hunt loop, plus the three frameworks you will meet in practice: Sqrrl's model, TaHiTI and PEAK."
---

## The hunt loop

Every published framework is a variation on the same cycle:

```text
   ┌────────────────────────────────────────────────────────────┐
   ▼                                                            │
 1. TRIGGER ─► 2. HYPOTHESIS ─► 3. SCOPE & DATA ─► 4. INVESTIGATE
 (intel, ATT&CK,   (testable,      (which logs,        (query, pivot,
  anomaly, news)    falsifiable)    which window)        enrich, stack)
                                                          │
   ┌──────────────────────────────────────────────────────┘
   ▼
 5. DECIDE ─► 6. RESPOND / ESCALATE ─► 7. OPERATIONALISE ─► 8. DOCUMENT
 (true pos?    (hand to IR with          (detection, hardening,    (report, metrics,
  false pos?    evidence)                 logging fix)              negative result)
  inconclusive?)
```

### Step by step

**1. Trigger.** What made you look? A threat report, a new ATT&CK technique, a pen-test finding, a spike on a dashboard, a CVE, a gut feeling from IR.

**2. Hypothesis.** One sentence, in the form *"If \<adversary behaviour\> were occurring in our environment, we would see \<observable\> in \<data source\>."* See [chapter 3]({{ site.baseurl }}/learn/hypotheses-and-intelligence/).

**3. Scope and data.** Define time window, assets (all servers? one OU? crown jewels?), and **confirm the data exists** before you start. Many hunts die here, and that is a legitimate outcome: *log the gap*.

**4. Investigate.** Query, then pivot. Typical pivots:

- Host → process tree → network connections → file writes → persistence
- Account → logon sources → other hosts → privileged group changes
- Destination IP/domain → all hosts that talked to it → first-seen time
- Hash/path → prevalence across fleet → signer → parent process

Keep a running timeline and record every query you run (you will need them for the report and for the detection).

**5. Decide.** Classify every lead as **true positive**, **benign** (and why), or **inconclusive**. Write down the reasoning.

**6. Respond.** True positives go to IR with a handoff package: timeline, affected assets and accounts, queries used, indicators, and your confidence level.

**7. Operationalise.** The step that separates hunting programs from hobbies:

- Convert reliable hunts to detections ([chapter 7]({{ site.baseurl }}/learn/detection-engineering/)).
- File logging/telemetry fixes.
- Propose hardening (disable the thing the attacker would abuse).

**8. Document.** Even null results. They prove coverage and prevent duplicate work.

## Framework 1: The Sqrrl Threat Hunting Loop and Reference Model

Sqrrl (later acquired by Amazon) popularised the model most hunters learned first:

1. **Create hypotheses** (informed by intel, situational awareness, domain expertise)
2. **Investigate** via tools and techniques
3. **Uncover** new patterns and TTPs
4. **Inform and enrich** analytics, which feeds step 1 again

It also introduced the **Hunting Maturity Model (HMM)**, authored by David Bianco, which grades organisations by how they use data and analytics:

| Level | Name | Description |
|---|---|---|
| HMM0 | Initial | Relies on automated alerting; little routine data collection |
| HMM1 | Minimal | Relies on alerting but incorporates threat intel indicator searches; moderate to high data collection |
| HMM2 | Procedural | Follows hunting procedures created by others; high data collection |
| HMM3 | Innovative | Creates new hunting procedures; high data collection |
| HMM4 | Leading | Automates most successful procedures so analysts can spend time on new hunts |

Use it as a self-assessment, not a scorecard. See [chapter 8]({{ site.baseurl }}/learn/building-a-hunt-program/).

## Framework 2: TaHiTI (Targeted Hunting integrating Threat Intelligence)

Developed by Dutch financial-sector organisations (ING, ABN AMRO, Rabobank and others), TaHiTI is a lightweight **methodology emphasising intel integration and documentation**. Three phases, six steps:

| Phase | Steps |
|---|---|
| **Initiate** | 1. Trigger → 2. Create an abstract (a short, standard summary of the hunt, stored in a backlog) |
| **Hunt** | 3. Define hunt (refine hypothesis, data, scope) → 4. Execute hunt → 5. Validate and handover (confirm findings, pass to IR/detection) |
| **Finalise** | 6. Document findings, update backlog, feed back intel |

What to borrow: the **hunt abstract/backlog discipline**. See our [hypothesis template]({{ site.baseurl }}/templates/#hunt-hypothesis-card).

## Framework 3: PEAK (Prepare, Execute, Act with Knowledge)

Published by Splunk's SURGe team (2023), PEAK explicitly covers **three hunt types** and a common lifecycle:

- **Hypothesis-driven** hunts
- **Baseline** hunts (establish "normal", then look for deviations)
- **Model-Assisted Threat Hunts (M-ATH)** (use machine learning/statistical models to surface candidates)

Lifecycle: **Prepare** (select topic, research, define scope and data) → **Execute** (run the hunt, analyse, iterate) → **Act** (document, create detections, communicate findings, feed back).

What to borrow: the **baseline hunt** as a first-class citizen, and the explicit "Act" phase.

## Choosing a framework

| If your team... | Use |
|---|---|
| Is new and needs a simple loop | Sqrrl-style loop (above) |
| Works closely with a CTI team and wants rigorous documentation | TaHiTI |
| Has strong data/analytics skills and wants to use baselines and ML | PEAK |
| Needs a maturity yardstick | HMM |

In practice, take the loop for flow, TaHiTI for the backlog and abstract, PEAK for hunt types, and HMM to explain progress to leadership.

## Time-boxing

A hunt that never ends never concludes. Typical effort:

| Hunt size | Duration | Example |
|---|---|---|
| Quick | 2-4 hours | Single-technique hunt on EDR data |
| Standard | 1-3 days | Persistence sweep across servers |
| Deep | 1-2 weeks | Baseline of service-account behaviour with statistical modelling |

When time is up, write down what you know and what you would do next.

## Next

→ [3. Hypotheses & threat intelligence]({{ site.baseurl }}/learn/hypotheses-and-intelligence/)
