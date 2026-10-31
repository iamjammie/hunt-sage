---
title: "Playbook: Ransomware Precursors"
permalink: /hunt/playbooks/ransomware-precursors/
excerpt: "Catch backup destruction, security-tool disabling, mass staging and encryption behaviours before they scale."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1490 (Inhibit System Recovery), T1486 (Data Encrypted for Impact), T1489 (Service Stop), T1562.001, T1021.002, T1484.001 (GPO modification), T1569.002 |
| **Tactic** | Impact (and the preceding stages) |
| **Data** | Process creation; Defender/EDR; file telemetry; Security 4688/5136/5145; Sysmon 11 |
| **Time-box** | 3-5 hours |
| **Difficulty** | ★★☆ |

## Hypothesis

> *Human-operated ransomware actors delete backups and shadow copies, disable recovery and security tools, stop database/backup services and push the payload at scale (often via GPO, PsExec or management tooling). Each is observable before encryption begins.*

The window between "hands on keyboard" and "encryption" can be hours to days. Hunting the precursors is your last, best chance.

## Hunt steps

### 1. Shadow copy and recovery destruction

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("resize shadowstorage"))
   or (FileName in~ ("wmic.exe") and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
   or (FileName =~ "wbadmin.exe" and ProcessCommandLine has_any ("delete catalog","delete backup","delete systemstatebackup"))
   or ProcessCommandLine has_all ("Get-WmiObject","Win32_ShadowCopy","Delete")
   or ProcessCommandLine has_all ("diskshadow","delete shadows")
```

```spl
index=sysmon EventCode=1
  ((Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*")
   OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*" CommandLine="*delete*")
   OR (Image="*\\bcdedit.exe" CommandLine="*recoveryenabled*" CommandLine="*no*")
   OR (Image="*\\wbadmin.exe" CommandLine="*delete*"))
| table _time host User ParentImage CommandLine
```

### 2. Service stops and process kills (databases, backup, AV)

```kql
DeviceProcessEvents
| where (FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has " stop ")
   or (FileName =~ "sc.exe" and ProcessCommandLine has_any (" stop "," config ") and ProcessCommandLine has "disabled")
   or (FileName =~ "taskkill.exe" and ProcessCommandLine has_any ("sql","veeam","backup","vss","MsMpEng","sophos","defender","oracle","exchange"))
| summarize Cmds = count(), Distinct = dcount(ProcessCommandLine), Samples = make_set(ProcessCommandLine, 10) by DeviceName, AccountName, bin(Timestamp, 15m)
| where Distinct >= 5       // bulk stops in a short window
```

### 3. Mass file activity (pre-encryption)

```kql
DeviceFileEvents
| where Timestamp > ago(1d) and ActionType in ("FileRenamed","FileModified")
| summarize Files = dcount(FolderPath), Renamed = countif(ActionType == "FileRenamed"), Exts = make_set(tostring(split(FileName, ".")[-1]), 5)
          by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where Files > 500
| order by Files desc
```

Hunt for ransom notes: many `readme*.txt` / `*_DECRYPT*.html` / `HOW_TO_*` files created in many directories; new, uniform extensions appended across files; honeyfile triggers (canary documents in file shares).

### 4. Mass deployment channels

- **GPO modification** (5136 on `groupPolicyContainer`, new GPO with scheduled task/startup script), especially at odd hours
- **PsExec / remote services** pushing a binary to many hosts → [lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/)
- **Management tools** (SCCM/Intune/RMM) used by unfamiliar admins; **new RMM agents** (AnyDesk, Atera, ScreenConnect, Splashtop) on servers
- Writes to many `\\host\ADMIN$` / `C$` shares from one source (5145 fan-out)

```kql
SecurityEvent
| where EventID == 5145 and ShareName in (@"\\*\ADMIN$", @"\\*\C$") and RelativeTargetName endswith ".exe"
| summarize Targets = dcount(Computer) by IpAddress, SubjectUserName, bin(TimeGenerated, 30m)
| where Targets > 10
```

### 5. Earlier stages worth checking in the same hosts

Hunts for [discovery bursts]({{ site.baseurl }}/learn/hunting-techniques/#2-grouping--clustering), [LSASS access]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/), [exfiltration tools]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/), and [Defender tampering]({{ site.baseurl }}/hunt/playbooks/defense-evasion/). Double extortion means data theft usually precedes encryption.

## Triage

- Is it one admin script (change ticket) or an actor sweep across servers?
- Are backup servers/hypervisors and domain controllers touched first? (A strong sign.)
- Same source account/host driving every action?

## Escalate when

Shadow-copy deletion or recovery disabling outside change control: **immediately**. Isolate the source host(s), disable the account, protect backups (offline/immutable), and invoke the IR plan. Do not wait for encryption.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1490` (in a snapshot-restorable VM only)
- Detection: [Shadow copy deletion]({{ site.baseurl }}/research/sigma/T1490-shadow-copy-deletion.yml)
- Hardening: immutable/offline backups tested regularly; restrict `vssadmin`/`bcdedit` for non-admins; ASR rule *Use advanced protection against ransomware*; controlled folder access on file servers; segment backup network; canary files; patch internet-facing systems and MFA on remote access.
