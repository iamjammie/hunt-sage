---
title: "3. Hypotheses & Threat Intelligence"
permalink: /learn/hypotheses-and-intelligence/
excerpt: "How to turn intel, ATT&CK and anomalies into hypotheses you can actually test."
---

## Anatomy of a good hypothesis

A hypothesis must be **specific, testable and falsifiable**, and it must name the **data** that can prove or disprove it.

> *If an adversary has obtained Domain Admin, they may use DCSync to replicate credentials. We would see directory-replication access (Event 4662 with replication GUIDs) from accounts that are not domain controller computer accounts.*

| Element | In the example |
|---|---|
| Adversary behaviour | DCSync (ATT&CK T1003.006) |
| Observable | Event 4662 with GUIDs `1131f6aa-...`, `1131f6ad-...`, `89e95b76-...` |
| Data source | Domain controller Security log, "Directory Service Access" auditing |
| Disproving evidence | Only DC machine accounts and Azure AD Connect appear |

**Weak hypotheses** (avoid):

| Weak | Why | Better |
|---|---|---|
| "Look for malware." | Not testable | "Look for processes executing from `%TEMP%` that make outbound connections within 60s of creation." |
| "Check for lateral movement." | Too broad | "Find accounts with network logons (type 3) to more than 10 distinct servers in an hour." |
| "See if APT29 is here." | Actor-level, no observable | "Hunt for the three persistence and C2 techniques in report X, using the ATT&CK technique IDs." |

## Where hypotheses come from

### 1. Threat intelligence

Intel varies in lifespan. David Bianco's **Pyramid of Pain** ranks indicators by how much it hurts the adversary when you detect and deny them:

```text
          ▲  TTPs                    ← Tough!  (behaviours)
         ╱ ╲ Tools                   ← Challenging
        ╱   ╲ Network/Host artefacts ← Annoying
       ╱     ╲ Domain names          ← Simple
      ╱       ╲ IP addresses         ← Easy
     ╱         ╲ Hash values         ← Trivial
```

**Implication for hunters:** hash and IP sweeps are cheap and worth doing once, but hypotheses built on *TTPs* stay valid when the attacker rotates infrastructure. Convert every report's IOCs into a *behaviour* hypothesis as well.

**Intel-to-hypothesis recipe**

1. Read the report; extract ATT&CK techniques (most vendor reports list them).
2. For each technique, ask: "what artefacts does it leave, and in which of *our* logs?"
3. Check data availability. Rank by (likelihood of use in our sector) × (data we have) × (impact).
4. Write one hypothesis per technique; run IOC sweeps in parallel.

Useful sources: CISA advisories, vendor DFIR reports (Mandiant, Microsoft, CrowdStrike, Red Canary, DFIR Report), sector ISACs, MISP/OpenCTI feeds, and your own incident history.

### 2. MITRE ATT&CK

ATT&CK is a knowledge base of adversary tactics (the *why*) and techniques (the *how*), plus observed procedures, groups and software. For hunters it is:

- A **vocabulary** that makes hunts comparable and shareable
- A **backlog generator**: every technique you cannot yet see or detect is a candidate hunt
- A **coverage metric** (see our [coverage map]({{ site.baseurl }}/research/mitre-mapping/))

Practical workflow:

1. Open [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Layer 1: techniques used by threat groups relevant to you.
2. Layer 2: techniques you can detect today (DeTT&CT can build this from your data source inventory).
3. The difference is your hunt backlog, **prioritised by relevance, not by count**.

> **Caution:** coverage ≠ quality. One brittle rule per technique does not mean you detect that technique. ATT&CK describes categories, not signatures.

### 3. The Diamond Model and kill chains

- **Diamond Model**: every intrusion event has an *adversary*, *capability*, *infrastructure* and *victim*. Pivot along any edge: same infrastructure → other victims; same capability → other infrastructure.
- **Cyber Kill Chain** (Lockheed Martin): Recon → Weaponisation → Delivery → Exploitation → Installation → C2 → Actions on Objectives. Good for thinking *where* to interrupt.
- **Unified Kill Chain** and ATT&CK tactics extend this to the post-exploitation phases hunters spend most time on.

### 4. Environment-specific triggers

| Trigger | Example hypothesis |
|---|---|
| New CVE in an internet-facing product | "Web server process spawned a shell or dropped an `.aspx`/`.jsp` in the 14 days since disclosure." |
| Pen-test or red team report | "Techniques the red team used undetected are being used by real actors." |
| Crown-jewel review | "Access to the finance database from a host that isn't an app server." |
| Past incidents | "The same persistence mechanism exists on other hosts." |
| Business events | M&A, new cloud account, new vendor access, employee departure |

### 5. Data anomalies

Rare process pairs, first-seen domains, impossible travel, a service account logging on interactively. These are *hunting leads*, not hypotheses yet: convert them: "If X is malicious, we'd also see Y".

## Prioritisation

Score candidate hunts so you work on the best ones:

| Factor | Question | 1-3 |
|---|---|---|
| Relevance | Do actors targeting our sector use this? | |
| Impact | If present, how bad? | |
| Visibility | Do we have the data right now? | |
| Effort | Can we finish in the time-box? (invert: 3 = easy) | |

Multiply or sum, sort, and run from the top. Track the backlog with the [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card).

## Worked example

**Trigger:** vendor report: ransomware affiliates are using `rclone` for exfiltration before encryption.

**Hypothesis:** *If `rclone` (or a renamed copy) is used for exfiltration, we will see (a) a process with PE original filename `rclone.exe` or command lines containing `copy`/`sync` with a remote and `--config`, and (b) large outbound transfers to cloud storage from a server that normally has little egress.*

**Data:** EDR/Sysmon process creation with `OriginalFileName` (Sysmon 1), firewall/proxy byte counts.

**Falsifier:** no matches in 90 days *and* process telemetry confirmed present on all servers.

**Outcome options:** TP → IR; no hits → document negative result + add detection on `OriginalFileName == rclone.exe`; telemetry missing on 12 servers → log visibility gap.

See the [data exfiltration playbook]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/).

## Next

→ [4. Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/)
