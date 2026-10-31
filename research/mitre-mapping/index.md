---
title: "MITRE ATT&CK Detection Coverage Map"
permalink: /research/mitre-mapping/
layout: single
toc: true
toc_label: "Tactics"
excerpt: "Detection rules, hunt playbooks and write-ups mapped to MITRE ATT&CK techniques."
---

This page maps the rules, playbooks and posts on Hunt-Sage to the [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/). Use it to pick your next hunt: every 🔜 is a gap.

## Status key

| Icon | Meaning |
|------|---------|
| ✅ | Sigma rule **and** hunt playbook/query published |
| 🔍 | Hunt playbook / query only (no Sigma rule yet) |
| 📝 | Write-up (blog / case study) only |
| 🔜 | Planned |

> Status means *content exists*, not that the technique is *validated in your environment*. Validate with [Emulate → Detect]({{ site.baseurl }}/labs/emulate-and-detect/) and track your own results.


---

## TA0001 - Initial Access

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Exploit Public-Facing Application | T1190 | 🔍 | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) |
| Phishing: Spearphishing Attachment | T1566.001 | 📝 | [Argon Dynamics case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) |
| Phishing: Spearphishing Link | T1566.002 | 🔜 | - |
| Valid Accounts: Domain / Cloud | T1078.002 / T1078.004 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1078.002-service-account-interactive-logon.yml) · [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |

---

## TA0002 - Execution

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| PowerShell | T1059.001 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) |
| Windows Command Shell | T1059.003 | 🔍 | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) · [Sigma]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml) |
| Unix Shell | T1059.004 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1059.004-linux-reverse-shell.yml) · [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| Windows Management Instrumentation | T1047 | 🔍 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| Scheduled Task | T1053.005 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) · [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| Service Execution (PsExec) | T1569.002 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) · [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |

---

## TA0003 - Persistence

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Registry Run Keys / Startup Folder | T1547.001 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml) · [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| Scheduled Task | T1053.005 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) · [Persistence post]({{ site.baseurl }}/blog/hunting-persistence/) |
| Windows Service | T1543.003 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) |
| WMI Event Subscription | T1546.003 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1546.003-wmi-event-subscription.yml) · [Persistence post]({{ site.baseurl }}/blog/hunting-persistence/) |
| DLL Search Order Hijacking | T1574.001 | 📝 | [Persistence post]({{ site.baseurl }}/blog/hunting-persistence/) |
| Web Shell | T1505.003 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/web-shells/) |
| Create Account: Local | T1136.001 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1136.001-local-account-created-cli.yml) · [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| SSH Authorized Keys / Cron / Systemd (Linux) | T1098.004 / T1053.003 / T1543.002 | 🔍 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| BITS Jobs | T1197 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml) |
| Cloud: Account Manipulation | T1098.001 / T1098.003 | 🔍 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |

---

## TA0004 - Privilege Escalation

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Valid Accounts: Domain Accounts | T1078.002 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1078.002-service-account-interactive-logon.yml) |
| Abuse Elevation Control: Bypass UAC | T1548.002 | 🔜 | - |
| Process Injection | T1055 | 🔜 | [Defense evasion (notes)]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |

---

## TA0005 - Defense Evasion

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Obfuscated Files or Information | T1027 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) |
| Deobfuscate/Decode Files or Information | T1140 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml) · [Argon case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) |
| System Binary Proxy Execution: Certutil / Mshta / Rundll32 / Regsvr32 | T1218.* | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml) · [LOLBin playbook]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml) · [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| Impair Defenses: Disable or Modify Tools | T1562.001 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml) · [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| Masquerading | T1036 | 🔍 | [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |

---

## TA0006 - Credential Access

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| OS Credential Dumping: LSASS Memory | T1003.001 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) · [PtH post]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/) |
| OS Credential Dumping: DCSync | T1003.006 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1003.006-dcsync-replication.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| AS-REP Roasting | T1558.004 | 🔍 | [Playbook]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| Brute Force / Password Spray | T1110 | 🔍 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| Steal Application Access Token (illicit consent) | T1528 | 🔍 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |

---

## TA0007 - Discovery

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Account Discovery: Domain Account | T1087.002 | 📝 | [Argon case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) · [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/) |
| Permission Groups Discovery: Domain Groups | T1069.002 | 📝 | [Argon case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) |
| Network Share Discovery | T1135 | 🔜 | - |

---

## TA0008 - Lateral Movement

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Pass the Hash | T1550.002 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml) · [Lateral movement post]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/) |
| Remote Services: SMB / Admin Shares | T1021.002 | 🔍 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) · [Sigma]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) |
| Remote Services: RDP | T1021.001 | 🔍 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| Remote Services: WinRM | T1021.006 | 🔍 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| Remote Services: SSH | T1021.004 | 🔍 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |

---

## TA0009 - Collection

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Data from Network Shared Drive | T1039 | 📝 | [Argon case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) |
| Archive Collected Data | T1560 | 🔍 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) · [Argon case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) |
| Email Collection: Forwarding Rule | T1114.003 | 🔍 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |

---

## TA0011 - Command and Control

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Application Layer Protocol: Web | T1071.001 | 🔍 | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) · [C2 beaconing post]({{ site.baseurl }}/blog/hunting-c2-beaconing/) |
| Application Layer Protocol: DNS | T1071.004 | 🔍 | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| Ingress Tool Transfer | T1105 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml) · [Sigma]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml) |
| Non-Application Layer Protocol | T1095 | 🔜 | - |

---

## TA0010 - Exfiltration

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Exfiltration Over C2 Channel | T1041 | 📝 | [Argon case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) · [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| Exfiltration Over Alternative Protocol | T1048 | 🔍 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| Exfiltration to Cloud Storage | T1567.002 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| Automated Exfiltration | T1020 | 🔜 | - |

---

## TA0040 - Impact

| Technique | ID | Status | Content |
|-----------|-----|--------|---------|
| Inhibit System Recovery | T1490 | ✅ | [Sigma]({{ site.baseurl }}/research/sigma/T1490-shadow-copy-deletion.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| Data Encrypted for Impact | T1486 | 🔍 | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| Service Stop | T1489 | 🔍 | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |

---

## Coverage summary

Counts are by row in the tables above (a technique may appear under several tactics).

| Status | Rows |
|---|---|
| ✅ Rule + playbook | 25 |
| 🔍 Playbook only | 20 |
| 📝 Write-up only | 6 |
| 🔜 Planned | 6 |

## Sigma rules index

All rules live in [`research/sigma/`]({{ site.baseurl }}/research/sigma/). See the [Sigma page]({{ site.baseurl }}/research/sigma/) for the full list with levels and false positives.

*[Suggest a technique or submit a rule →](https://github.com/iamjammie/hunt-sage/issues)*
