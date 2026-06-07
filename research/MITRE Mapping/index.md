---
title: "MITRE ATT&CK Detection Coverage Map"
permalink: /research/mitre-mapping/
layout: single
toc: true
toc_label: "Tactics"
header:
  teaser: /assets/images/research/mitre-coverage.png
excerpt: "Detection rules and hunt queries mapped to MITRE ATT&CK techniques. Updated as new content is published."
---

This page maps all detection rules and hunting content on Hunt-Sage to the [MITRE ATT&CK Enterprise Framework](https://attack.mitre.org/). Coverage is growing — techniques with rules or queries are marked ✅.

---

## Coverage Status

| Colour | Meaning |
|--------|---------|
| ✅ | Sigma rule + hunt query published |
| 🔍 | Hunt query only (no Sigma rule yet) |
| 📝 | Blog post coverage only |
| 🔜 | Planned |

---

## TA0001 — Initial Access

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Phishing: Spearphishing Attachment | T1566.001 | 📝 | [Argon Dynamics Case Study](/blog/argon-dynamics-case-study) |
| Phishing: Spearphishing Link | T1566.002 | 🔜 | — |
| Valid Accounts | T1078 | ✅ | [T1078.002 Sigma Rule](/research/sigma/T1078.002-service-account-interactive-logon.yml) |

---

## TA0002 — Execution

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Command and Scripting: PowerShell | T1059.001 | ✅ | [Sigma Rule](/research/sigma/T1059.001-powershell-encoded-command.yml) · [Hunting 101](/blog/threat-hunting-fundamentals) |
| Command and Scripting: Windows Command Shell | T1059.003 | 🔜 | — |
| Scheduled Task/Job | T1053.005 | ✅ | [Persistence Post](/blog/hunting-persistence) |
| Windows Management Instrumentation | T1047 | 🔍 | [Persistence Post](/blog/hunting-persistence) |

---

## TA0003 — Persistence

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Boot/Logon Autostart: Registry Run Keys | T1547.001 | ✅ | [Sigma Rule](/research/sigma/) · [Persistence Post](/blog/hunting-persistence) |
| Scheduled Task/Job: Scheduled Task | T1053.005 | ✅ | [Persistence Post](/blog/hunting-persistence) |
| Create or Modify System Process: Windows Service | T1543.003 | ✅ | [Persistence Post](/blog/hunting-persistence) |
| Event Triggered Execution: WMI Subscription | T1546.003 | ✅ | [Sigma Rule](/research/sigma/T1546.003-wmi-event-subscription.yml) · [Persistence Post](/blog/hunting-persistence) |
| Hijack Execution Flow: DLL Search Order Hijacking | T1574.001 | 📝 | [Persistence Post](/blog/hunting-persistence) |

---

## TA0004 — Privilege Escalation

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Valid Accounts: Domain Accounts | T1078.002 | ✅ | [T1078.002 Sigma Rule](/research/sigma/T1078.002-service-account-interactive-logon.yml) |
| Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | 🔜 | — |

---

## TA0005 — Defense Evasion

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Obfuscated Files or Information | T1027 | ✅ | [PowerShell Sigma Rule](/research/sigma/T1059.001-powershell-encoded-command.yml) |
| Deobfuscate/Decode Files | T1140 | ✅ | [CertUtil Sigma Rule](/research/sigma/T1140-certutil-encode-lolbin.yml) · [Argon Case Study](/blog/argon-dynamics-case-study) |
| System Binary Proxy Execution: Certutil | T1218.003 | ✅ | [CertUtil Sigma Rule](/research/sigma/T1140-certutil-encode-lolbin.yml) |
| Masquerading | T1036 | 🔜 | — |

---

## TA0006 — Credential Access

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| OS Credential Dumping: LSASS Memory | T1003.001 | 🔍 | [Lateral Movement Post](/blog/hunting-lateral-movement-pass-the-hash) |
| Brute Force | T1110 | 🔜 | — |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | 🔜 | — |

---

## TA0007 — Discovery

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Account Discovery: Domain Account | T1087.002 | 📝 | [Argon Case Study](/blog/argon-dynamics-case-study) |
| Permission Groups Discovery: Domain Groups | T1069.002 | 📝 | [Argon Case Study](/blog/argon-dynamics-case-study) |
| Network Share Discovery | T1135 | 🔜 | — |

---

## TA0008 — Lateral Movement

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Use Alternate Auth Material: Pass the Hash | T1550.002 | ✅ | [Sigma Rule](/research/sigma/T1550.002-pass-the-hash.yml) · [Lateral Movement Post](/blog/hunting-lateral-movement-pass-the-hash) |
| Remote Services: SMB / Windows Admin Shares | T1021.002 | 🔜 | — |
| Remote Services: RDP | T1021.001 | 🔜 | — |

---

## TA0009 — Collection

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Data from Network Shared Drive | T1039 | 📝 | [Argon Case Study](/blog/argon-dynamics-case-study) |
| Archive Collected Data | T1560 | 📝 | [Argon Case Study](/blog/argon-dynamics-case-study) |

---

## TA0011 — Command and Control

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Application Layer Protocol: Web Protocols | T1071.001 | ✅ | [C2 Beaconing Post](/blog/hunting-c2-beaconing) |
| Application Layer Protocol: DNS | T1071.004 | ✅ | [C2 Beaconing Post](/blog/hunting-c2-beaconing) |
| Non-Application Layer Protocol | T1095 | 🔜 | — |

---

## TA0010 — Exfiltration

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Exfiltration Over C2 Channel | T1041 | 📝 | [Argon Case Study](/blog/argon-dynamics-case-study) |
| Exfiltration Over Alternative Protocol | T1048 | 📝 | [Argon Case Study](/blog/argon-dynamics-case-study) |
| Automated Exfiltration | T1020 | 🔜 | — |

---

## Sigma Rules Index

All Sigma rules are available in the [`/research/sigma/`](/research/sigma/) directory and follow the [Sigma specification](https://github.com/SigmaHQ/sigma).

| Rule | Technique | Level |
|------|-----------|-------|
| [T1059.001 - PowerShell Encoded Command](/research/sigma/T1059.001-powershell-encoded-command.yml) | T1059.001 | Medium |
| [T1078.002 - Service Account Interactive Logon](/research/sigma/T1078.002-service-account-interactive-logon.yml) | T1078.002 | High |
| [T1140 - CertUtil LOLBin Abuse](/research/sigma/T1140-certutil-encode-lolbin.yml) | T1140 | High |
| [T1550.002 - Pass-the-Hash](/research/sigma/T1550.002-pass-the-hash.yml) | T1550.002 | Medium |
| [T1546.003 - WMI Event Subscription](/research/sigma/T1546.003-wmi-event-subscription.yml) | T1546.003 | High |

---

*Coverage map updated: June 2025. [Submit a rule or suggest a technique →](https://github.com/iamjammie/hunt-sage/issues)*
