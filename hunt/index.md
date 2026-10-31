---
title: "Hunt Playbook Library"
permalink: /hunt/
excerpt: "Fourteen field-ready hunt playbooks: hypothesis, data, queries (KQL + SPL), triage, false positives, escalation, validation and hardening."
toc: false
---

Each playbook is a self-contained, repeatable hunt. They follow the same structure so you can run them quickly and compare results:

1. **Hypothesis**: what you believe an adversary would do and what you'd see
2. **Data required**: and how to verify you have it
3. **Hunt steps**: queries in KQL (Microsoft Sentinel / Defender) and SPL (Splunk), simplest to most advanced
4. **Triage**: how to separate true from false positives
5. **Escalation criteria**: when to hand to IR
6. **Validate**: emulate the technique in your [lab]({{ site.baseurl }}/labs/) to prove the query works
7. **Operationalise**: the detection and hardening that make the hunt unnecessary next time

> **Before you start:** confirm the [data is actually being collected]({{ site.baseurl }}/learn/data-and-telemetry/). A query that returns nothing on a missing log source is not a negative result. Query field names vary by platform, parser and add-on version, so treat the queries as well-tested starting points and adapt them to your schema.

## Playbooks by tactic

| Tactic | Playbook | ATT&CK | Difficulty |
|---|---|---|---|
| Execution | [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) | T1059.001 | ★☆☆ |
| Execution / Evasion | [LOLBin proxy execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) | T1218, T1105, T1197 | ★★☆ |
| Credential access | [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) | T1003.001 | ★★☆ |
| Credential access | [Kerberoasting & AS-REP roasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) | T1558.003, T1558.004 | ★★☆ |
| Credential access | [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) | T1003.006 | ★★☆ |
| Lateral movement | [Lateral movement (SMB, RDP, WinRM, PtH)]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) | T1021, T1550 | ★★★ |
| Persistence | [Persistence (run keys, tasks, services, WMI)]({{ site.baseurl }}/hunt/playbooks/persistence/) | T1547, T1053, T1543, T1546 | ★★☆ |
| Defense evasion | [Defense evasion (log clearing, tampering, masquerading)]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) | T1070, T1562, T1036 | ★★☆ |
| Command & control | [C2 beaconing & DNS tunneling]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) | T1071, T1573 | ★★★ |
| Exfiltration | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) | T1041, T1048, T1567 | ★★★ |
| Impact | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) | T1490, T1486 | ★★☆ |
| Initial access / Persistence | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) | T1505.003, T1190 | ★★☆ |
| Cross-tactic (Linux) | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) | T1059.004, T1053.003, T1098.004 | ★★☆ |
| Cross-tactic (Cloud) | [Cloud & identity (Entra ID / AWS)]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) | T1078.004, T1098, T1528 | ★★★ |

Difficulty reflects analytical complexity and required data, not importance.

## Suggested first five hunts

1. [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/): high-yield, simple data.
2. [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/): stacking is easy and instructive.
3. [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/): few events, high-signal on a DC.
4. [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/): learn about access masks.
5. [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/): ties it all together.

## Related

- [Sigma rules]({{ site.baseurl }}/research/sigma/) that productionise these hunts
- [Cheat sheets]({{ site.baseurl }}/cheatsheets/) for event IDs and query syntax
- [Hunt report template]({{ site.baseurl }}/templates/#hunt-report)
- Blog deep-dives: [Fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/), [Pass-the-hash]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/), [C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/), [Persistence]({{ site.baseurl }}/blog/hunting-persistence/)
