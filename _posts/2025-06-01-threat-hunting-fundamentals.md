---
title: "Threat Hunting 101: From Alert Fatigue to Proactive Defense"
date: 2025-06-01
categories:
  - blog
tags:
  - threat-hunting
  - blue-team
  - SOC
  - fundamentals
toc: true
toc_label: "Contents"
header:
  teaser: /assets/images/posts/threat-hunting-101.png
excerpt: "Most SOC analysts react to alerts. Threat hunters go looking for what the alerts miss. Here's how to make the mental shift."
---

## The Problem With Purely Reactive Defense

Every SOC has the same problem: too many alerts, too little time, and adversaries who know exactly how long your SIEM takes to fire.

When you only respond to alerts, you're playing on the attacker's schedule. They've already been inside your environment for hours — sometimes weeks — before anything pings your dashboard. The 2024 Mandiant M-Trends report put the median dwell time at **10 days**. Ten days of unchallenged movement before detection.

Threat hunting flips that dynamic. Instead of waiting for the environment to tell you something went wrong, you go looking based on what you already know about adversary behaviour.

---

## What Threat Hunting Actually Is

Threat hunting is **hypothesis-driven investigation**. You form a theory — "an attacker using Living off the Land binaries (LOLBins) would look like this in my environment" — and then you go looking for evidence that confirms or denies it.

It has three characteristics that distinguish it from alert triage:

| Property | Alert Triage | Threat Hunting |
|----------|-------------|----------------|
| Trigger | System fires an alert | Human forms a hypothesis |
| Scope | Single event | Pattern across time/systems |
| Outcome | Resolve ticket | New detection rule or confirmed threat |

---

## The Hunting Loop

Every hunt follows roughly the same cycle:

```
1. HYPOTHESIS
   └─ Based on threat intel, MITRE ATT&CK, or anomaly observation

2. DATA COLLECTION
   └─ Pull relevant telemetry: EDR, logs, network, identity

3. INVESTIGATION
   └─ Query, visualise, pivot

4. FINDING
   └─ Either: confirmed threat activity
             OR: confirmed benign (still useful)

5. RESPONSE / IMPROVE
   └─ Escalate if threat found
   └─ Always: write a detection rule so a human doesn't have to do this manually again
```

The last step is the most skipped — and the most important. Every completed hunt should leave behind either a Sigma rule, a KQL query, or a saved search that automates the check going forward.

---

## Hypothesis Sources

Where do good hunt hypotheses come from?

### 1. MITRE ATT&CK
The ATT&CK framework maps adversary techniques to the tactics that drive them. Pick a technique your environment is likely exposed to and ask: "What would this look like in my logs?"

**Example**: T1059.001 (PowerShell) — Are there processes spawning `powershell.exe` with encoded command-line arguments? That's your hypothesis. Go look.

### 2. Threat Intelligence Reports
When a vendor publishes a campaign report (e.g., a new ransomware group's TTPs), hunt for those exact indicators and patterns in your environment. The IOCs go stale. The TTPs don't.

### 3. Environmental Anomalies
Anything that looks unusual but didn't fire an alert. A service account logging in at 3am. A user suddenly running `net.exe` commands. These are seeds for a hypothesis.

### 4. Previous Incident Learnings
After every incident, ask: "What would we have seen in logs two weeks before the detection?" Those are your next hunts.

---

## A Simple First Hunt: Suspicious PowerShell Execution

Let's walk through a real hunt from hypothesis to detection.

**Hypothesis**: Attackers frequently use PowerShell with Base64-encoded commands to evade command-line logging. If this is happening in our environment, we'd see `powershell.exe` processes with `-EncodedCommand` or `-enc` in their arguments.

**Where to look**: Windows Event Log, EDR process telemetry, Sysmon Event ID 1 (Process Create)

**KQL Query (Microsoft Sentinel / Defender)**:
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-ec ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Sigma Rule equivalent**:
```yaml
title: PowerShell Encoded Command Execution
id: f62b4d41-9c2f-4e8a-b9b3-3c5e7a2b1d0f
status: stable
description: Detects PowerShell execution with encoded command parameters
references:
  - https://attack.mitre.org/techniques/T1059/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - ' -enc '
      - ' -ec '
  condition: selection
falsepositives:
  - Legitimate automation scripts using encoded commands
  - Software deployment tools
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

**What to do with results**:
- Identify the parent process — what launched PowerShell?
- Decode the Base64 payload: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("BASE64HERE"))`
- If benign (e.g., SCCM deployment), add to allowlist and document it
- If malicious, escalate immediately and pivot: what did that PowerShell do next?

---

## Building Your First Hypothesis List

Before your next shift, write down five hypotheses based on your environment. Here's a starter template:

```
Hypothesis: [Actor/Technique] would appear as [observable behaviour] in [log source]
Data Source: [where to look]
Query: [KQL/SPL/Sigma]
Expected Benign Causes: [what legitimate activity looks the same]
```

Pick one. Go hunt. Write down what you find. Convert the query to a saved rule.

That's threat hunting. You just need to start.

---

## Further Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [The ThreatHunting Project](https://www.threathunting.net)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [SQRLL Threat Hunting Reference](https://www.threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf)

---

*Next post: Hunting for Lateral Movement — what NTLM pass-the-hash looks like in your logs.*
