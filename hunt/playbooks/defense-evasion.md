---
title: "Playbook: Defense Evasion"
permalink: /hunt/playbooks/defense-evasion/
excerpt: "Log clearing, security-tool tampering, masquerading, process injection and timestomping."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1070.001 (Clear Windows Event Logs), T1562.001 (Disable/Modify Tools), T1562.002 (Disable Event Logging), T1036 (Masquerading), T1055 (Process Injection), T1070.006 (Timestomp) |
| **Tactic** | Defense Evasion |
| **Data** | Security 1102, System 104, Sysmon 1/8/10/25/26, PowerShell 4104, Defender 5001/5007/5010, registry telemetry |
| **Time-box** | 3-4 hours |
| **Difficulty** | ★★☆ |

## Hypothesis

> *An adversary who is detected, or anticipates detection, will clear logs, disable or exclude security tooling, or run payloads under trusted-looking names and processes.*

Defense-evasion events are **high-value because legitimate causes are rare**. Even one hit deserves review.

## Hunt steps

### 1. Log clearing

```kql
// Security log cleared
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, SubjectUserName
```

```kql
// Any other log cleared (System, Application, Sysmon...)
Event
| where Source == "Microsoft-Windows-Eventlog" and EventID == 104
| project TimeGenerated, Computer, RenderedDescription
```

```spl
index=wineventlog (EventCode=1102 OR (source="WinEventLog:System" EventCode=104))
| table _time host user Message
```

Also: `wevtutil cl`, `Clear-EventLog`, `Remove-EventLog`, and the **Event Log service stopped** (System 7036), `auditpol /clear`, `auditpol /set ... /success:disable`.

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("wevtutil cl","wevtutil.exe cl","Clear-EventLog","auditpol /clear","auditpol /remove","Remove-EventLog")
```

**Absence is a signal.** A host that stops sending logs is a lead:

```kql
Heartbeat | summarize LastSeen = max(TimeGenerated) by Computer | where LastSeen < ago(2h)
```

### 2. Tampering with Defender and EDR

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference")
| where ProcessCommandLine has_any ("DisableRealtimeMonitoring","ExclusionPath","ExclusionProcess","ExclusionExtension",
                                    "DisableIOAVProtection","DisableBehaviorMonitoring","DisableScriptScanning","MAPSReporting 0")
   or ProcessCommandLine has_all ("sc","stop","WinDefend") or ProcessCommandLine has_all ("sc","config","Sense")
```

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" (EventCode=5001 OR EventCode=5007 OR EventCode=5010 OR EventCode=5012)
| table _time host EventCode Message
```

(5001 = real-time protection disabled, 5007 = configuration changed, 5010/5012 = scanning disabled.) Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`, `...\Windows Defender\Exclusions\*`.

Also watch for **BYOVD** (driver loaded to kill EDR): Sysmon 6 (driver load) with unsigned/rare/known-vulnerable drivers, then security processes terminating. Cross-check hashes against [LOLDrivers](https://www.loldrivers.io/).

### 3. Masquerading

System process names are well known; their paths, parents and users are rigid.

| Process | Expected |
|---|---|
| `svchost.exe` | `C:\Windows\System32\`, parent `services.exe`, usually with `-k <group>` |
| `lsass.exe` | `System32`, parent `wininit.exe`, one instance |
| `csrss.exe`, `smss.exe`, `wininit.exe` | `System32`, specific parents, session 0 |
| `explorer.exe` | `C:\Windows\`, parent `userinit.exe`, per-user |
| `taskhostw.exe`, `RuntimeBroker.exe` | `System32`, parent `svchost.exe` |

```kql
DeviceProcessEvents
| where FileName in~ ("svchost.exe","lsass.exe","csrss.exe","smss.exe","services.exe","winlogon.exe","wininit.exe","taskhostw.exe")
| where not(FolderPath startswith @"c:\windows\system32\" or FolderPath startswith @"c:\windows\syswow64\")
   or (FileName =~ "svchost.exe" and InitiatingProcessFileName !~ "services.exe")
   or (FileName =~ "lsass.exe" and InitiatingProcessFileName !~ "wininit.exe")
```

Also look for look-alike names (`svch0st.exe`, `scvhost.exe`, `lsasss.exe`), double extensions (`invoice.pdf.exe`), trailing spaces, and right-to-left override characters (U+202E).

### 4. Injection and in-memory execution

- Sysmon 8 (CreateRemoteThread) from non-debugger processes into other processes
- Sysmon 10 with `GrantedAccess` including `PROCESS_VM_WRITE` (0x20), `PROCESS_VM_OPERATION` (0x8) or `PROCESS_CREATE_THREAD` (0x2) from unexpected sources
- Sysmon 25 (ProcessTampering: hollowing/herpaderping)
- Unbacked/unsigned memory regions in EDR telemetry; `rundll32.exe`/`regsvr32.exe`/`svchost.exe` spawned with **no command line** and making network connections (typical Cobalt Strike spawn-to processes)

```kql
DeviceProcessEvents
| where FileName in~ ("rundll32.exe","dllhost.exe","regsvr32.exe")
| where ProcessCommandLine matches regex @'^"?[^\s"]+"?\s*$'     // bare image path, no arguments
| where InitiatingProcessFileName !in~ ("services.exe","explorer.exe")
```

### 5. Timestomping and file-system tricks

Sysmon 2 (file creation time changed) from non-installer processes; alternate data streams (Sysmon 15); executables with `$STANDARD_INFORMATION` times earlier than `$FILE_NAME` times (forensics).

## Triage

- Who/what cleared logs or changed Defender settings, and from where (local vs remote)?
- What happened in the 30 minutes **before** (logons, tooling) and **after** (new execution without telemetry)?
- Is another host showing the same? (Rapid, multi-host tampering suggests ransomware staging.)

## Common false positives

Imaging/decommissioning scripts clearing logs; IT exclusions for dev tools or databases (verify against change tickets); installers touching Defender settings.

## Escalate when

Log clearing or security-tool disabling occurs outside an approved change, especially with other suspicious activity on the host. Treat as hands-on-keyboard activity.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1070.001`, `T1562.001`, `T1036.003`
- Detection: [Security log cleared]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml), [Defender tampering]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml)
- Hardening: Defender **Tamper Protection**; forward logs off-host in near real time; restrict `SeSecurityPrivilege`/`SeDebugPrivilege`; WDAC driver block list.
