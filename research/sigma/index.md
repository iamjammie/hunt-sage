---
title: "Sigma Detection Rules"
permalink: /research/sigma/
layout: single
toc: true
toc_label: "Rules by Tactic"
excerpt: "20 Sigma detection rules authored by Hunt-Sage, each mapped to ATT&CK with documented false positives."
---

All rules follow the [Sigma specification](https://sigmahq.io/docs/basics/rules.html) and convert to your SIEM's query language with [pySigma](https://github.com/SigmaHQ/pySigma) backends. Rules are validated in CI on every pull request.

> **Status** follows the criteria in the [detection engineering notes]({{ site.baseurl }}/research/mitre-detection-engineering/#rule-status-criteria-used-in-this-repo): `experimental` (untested), `test` (lab-validated, FPs enumerated), `stable` (30+ days in production with measured precision). **Tune before alerting in production.**

## All rules

| Rule | Technique | Level | Status | Tactics |
|------|-----------|-------|--------|---------|
| [Suspicious LSASS Process Access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml) | T1003.001 | High | test | Credential Access |
| [DCSync - Directory Replication from Non-Domain-Controller Account]({{ site.baseurl }}/research/sigma/T1003.006-dcsync-replication.yml) | T1003.006 | High | test | Credential Access |
| [Scheduled Task Created from Suspicious Location or Interpreter]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) | T1053.005 | Medium | test | Persistence, Execution, Privilege Escalation |
| [PowerShell Encoded Command Execution]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) | T1059.001, T1027 | Medium | test | Execution, Defense Evasion |
| [Linux Reverse Shell Command Line]({{ site.baseurl }}/research/sigma/T1059.004-linux-reverse-shell.yml) | T1059.004 | High | test | Execution |
| [Windows Event Log Cleared]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml) | T1070.001 | High | test | Defense Evasion |
| [Service Account Interactive Logon]({{ site.baseurl }}/research/sigma/T1078.002-service-account-interactive-logon.yml) | T1078.002 | High | test | Persistence, Privilege Escalation, Lateral Movement |
| [Local Account Created via Command Line]({{ site.baseurl }}/research/sigma/T1136.001-local-account-created-cli.yml) | T1136.001, T1098 | Medium | test | Persistence, Privilege Escalation |
| [CertUtil LOLBin Encode/Decode Abuse]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml) | T1140, T1027, T1048 | High | test | Defense Evasion, Exfiltration |
| [BITSAdmin Download or Persistent Transfer Job]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml) | T1197 | Medium | test | Defense Evasion, Persistence |
| [Mshta Executing Remote or Inline Script Content]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml) | T1218.005 | High | test | Defense Evasion, Execution |
| [Shadow Copy Deletion or Recovery Inhibition]({{ site.baseurl }}/research/sigma/T1490-shadow-copy-deletion.yml) | T1490 | High | test | Impact |
| [Web Server Process Spawning Shell or Recon Tool]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml) | T1505.003, T1190 | High | test | Persistence, Initial Access |
| [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) | T1543.003, T1569.002 | High | test | Persistence, Privilege Escalation, Lateral Movement, Execution |
| [WMI Event Subscription Persistence]({{ site.baseurl }}/research/sigma/T1546.003-wmi-event-subscription.yml) | T1546.003 | High | test | Persistence, Privilege Escalation |
| [Run Key Persistence with Suspicious Value]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml) | T1547.001 | Medium | test | Persistence, Privilege Escalation |
| [Possible Pass-the-Hash Lateral Movement]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml) | T1550.002, T1003.001 | Medium | experimental | Lateral Movement, Credential Access |
| [Kerberoasting - RC4 Service Ticket Requests]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml) | T1558.003 | Medium | test | Credential Access |
| [Microsoft Defender Disabled or Excluded via PowerShell/Command Line]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml) | T1562.001 | High | test | Defense Evasion |
| [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml) | T1567.002 | High | test | Exfiltration |

## Rules by tactic

### Initial Access

- [Web Server Process Spawning Shell or Recon Tool]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml) (T1505.003, T1190, high)

### Execution

- [Scheduled Task Created from Suspicious Location or Interpreter]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) (T1053.005, medium)
- [PowerShell Encoded Command Execution]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) (T1059.001, T1027, medium)
- [Linux Reverse Shell Command Line]({{ site.baseurl }}/research/sigma/T1059.004-linux-reverse-shell.yml) (T1059.004, high)
- [Mshta Executing Remote or Inline Script Content]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml) (T1218.005, high)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) (T1543.003, T1569.002, high)

### Persistence

- [Scheduled Task Created from Suspicious Location or Interpreter]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) (T1053.005, medium)
- [Service Account Interactive Logon]({{ site.baseurl }}/research/sigma/T1078.002-service-account-interactive-logon.yml) (T1078.002, high)
- [Local Account Created via Command Line]({{ site.baseurl }}/research/sigma/T1136.001-local-account-created-cli.yml) (T1136.001, T1098, medium)
- [BITSAdmin Download or Persistent Transfer Job]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml) (T1197, medium)
- [Web Server Process Spawning Shell or Recon Tool]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml) (T1505.003, T1190, high)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) (T1543.003, T1569.002, high)
- [WMI Event Subscription Persistence]({{ site.baseurl }}/research/sigma/T1546.003-wmi-event-subscription.yml) (T1546.003, high)
- [Run Key Persistence with Suspicious Value]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml) (T1547.001, medium)

### Privilege Escalation

- [Scheduled Task Created from Suspicious Location or Interpreter]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) (T1053.005, medium)
- [Service Account Interactive Logon]({{ site.baseurl }}/research/sigma/T1078.002-service-account-interactive-logon.yml) (T1078.002, high)
- [Local Account Created via Command Line]({{ site.baseurl }}/research/sigma/T1136.001-local-account-created-cli.yml) (T1136.001, T1098, medium)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) (T1543.003, T1569.002, high)
- [WMI Event Subscription Persistence]({{ site.baseurl }}/research/sigma/T1546.003-wmi-event-subscription.yml) (T1546.003, high)
- [Run Key Persistence with Suspicious Value]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml) (T1547.001, medium)

### Defense Evasion

- [PowerShell Encoded Command Execution]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) (T1059.001, T1027, medium)
- [Windows Event Log Cleared]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml) (T1070.001, high)
- [CertUtil LOLBin Encode/Decode Abuse]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml) (T1140, T1027, T1048, high)
- [BITSAdmin Download or Persistent Transfer Job]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml) (T1197, medium)
- [Mshta Executing Remote or Inline Script Content]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml) (T1218.005, high)
- [Microsoft Defender Disabled or Excluded via PowerShell/Command Line]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml) (T1562.001, high)

### Credential Access

- [Suspicious LSASS Process Access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml) (T1003.001, high)
- [DCSync - Directory Replication from Non-Domain-Controller Account]({{ site.baseurl }}/research/sigma/T1003.006-dcsync-replication.yml) (T1003.006, high)
- [Possible Pass-the-Hash Lateral Movement]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml) (T1550.002, T1003.001, medium)
- [Kerberoasting - RC4 Service Ticket Requests]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml) (T1558.003, medium)

### Lateral Movement

- [Service Account Interactive Logon]({{ site.baseurl }}/research/sigma/T1078.002-service-account-interactive-logon.yml) (T1078.002, high)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) (T1543.003, T1569.002, high)
- [Possible Pass-the-Hash Lateral Movement]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml) (T1550.002, T1003.001, medium)

### Exfiltration

- [CertUtil LOLBin Encode/Decode Abuse]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml) (T1140, T1027, T1048, high)
- [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml) (T1567.002, high)

### Impact

- [Shadow Copy Deletion or Recovery Inhibition]({{ site.baseurl }}/research/sigma/T1490-shadow-copy-deletion.yml) (T1490, high)

## How to use these rules

Install pySigma and the backend for your platform:

```bash
pip install sigma-cli
sigma plugin install splunk
sigma plugin install kusto         # Microsoft Sentinel / Defender KQL
sigma plugin install elasticsearch
sigma plugin install sysmon        # Sysmon field-name pipeline
```

Convert a rule:

```bash
# Splunk
sigma convert -t splunk -p splunk_windows research/sigma/T1490-shadow-copy-deletion.yml

# Microsoft Sentinel / KQL
sigma convert -t kusto -p microsoft_xdr research/sigma/T1490-shadow-copy-deletion.yml

# Elastic (Lucene) with ECS-style pipeline
sigma convert -t lucene -p ecs_windows research/sigma/T1490-shadow-copy-deletion.yml
```

Pipelines map generic Sigma fields (`Image`, `CommandLine`) to your schema; choose the one that matches how your data is ingested. Always test the converted query on sample data. Run `sigma check research/sigma/` to lint locally.

### Notes on the older rules

The first five rules (`T1059.001`, `T1078.002`, `T1140`, `T1546.003`, `T1550.002`) also carry extra non-standard keys (`hunt_notes`, `kql_equivalent`, `spl_equivalent`). Converters ignore them; they remain for analyst reference. The newer rules keep the file standard and put hunt queries in the [playbooks]({{ site.baseurl }}/hunt/).

## Test every rule

1. **Positive:** emulate with [Atomic Red Team]({{ site.baseurl }}/labs/emulate-and-detect/) and confirm the alert.
2. **Negative:** replay representative benign logs and count hits.
3. **Tune** with narrow, documented exclusions.

---

*[Suggest a rule or submit your own →](https://github.com/iamjammie/hunt-sage/blob/main/CONTRIBUTING.md)*
