---
title: "Playbook: LSASS Credential Dumping"
permalink: /hunt/playbooks/lsass-credential-dumping/
excerpt: "Detect processes reading LSASS memory, MiniDump abuse, and dump files on disk."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1003.001 (LSASS Memory), T1003.002/.004 (SAM/LSA secrets), T1003.003 (NTDS) |
| **Tactic** | Credential Access |
| **Data** | Sysmon 10 (ProcessAccess) targeting `lsass.exe`; Sysmon 11 (FileCreate); Sysmon 1; EDR process-access telemetry; Security 4656/4663 if LSASS SACL set |
| **Time-box** | 3-4 hours |
| **Difficulty** | ★★☆ |

## Hypothesis

> *If an adversary dumps credentials from LSASS memory, a non-system process will open `lsass.exe` with memory-read rights (e.g. `GrantedAccess` 0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff), or a dump file will be created by a process like `rundll32`/`procdump`/Task Manager.*

## Data required

- Sysmon configured to log ProcessAccess to `lsass.exe` (Event 10), or EDR with equivalent
- Know your **baseline**: security agents, EDR sensors, and `MsMpEng.exe` legitimately touch LSASS.

## Hunt steps

### 1. Stack processes that open LSASS

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| stats count dc(host) as hosts values(GrantedAccess) as access by SourceImage
| sort hosts
```

```kql
// Sysmon via Sentinel custom table (adapt) or Defender
DeviceEvents
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| summarize Count = count(), Hosts = dcount(DeviceName) by InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Hosts asc
```

Everything left after you remove documented security tooling is a lead.

### 2. Suspicious access masks from user-writable or unsigned sources

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
  (GrantedAccess=0x1010 OR GrantedAccess=0x1410 OR GrantedAccess=0x1438 OR GrantedAccess=0x143a OR GrantedAccess=0x1fffff)
  NOT (SourceImage="*\\MsMpEng.exe" OR SourceImage="C:\\Windows\\System32\\wininit.exe" OR SourceImage="C:\\Windows\\System32\\csrss.exe"
       OR SourceImage="C:\\Windows\\System32\\services.exe" OR SourceImage="C:\\Windows\\System32\\svchost.exe" OR SourceImage="C:\\Windows\\System32\\WerFault.exe")
| table _time host User SourceImage GrantedAccess CallTrace
```

Do **not** blanket-exclude `System32`: `rundll32.exe` (comsvcs MiniDump) and `taskmgr.exe` run from there. Exclude specific, expected images only. `CallTrace` containing `dbghelp.dll` / `dbgcore.dll` means a process is using MiniDumpWriteDump. `UNKNOWN` frames in `CallTrace` suggest injected or reflectively loaded code.

### 3. Comsvcs MiniDump and ProcDump command lines

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "comsvcs" and ProcessCommandLine has_any ("MiniDump","#24"))
   or (FileName in~ ("procdump.exe","procdump64.exe") and ProcessCommandLine has "lsass")
   or ProcessCommandLine has_any ("sekurlsa","lsadump::","mimikatz")
   or (ProcessCommandLine has "Out-Minidump")
```

### 4. Dump files on disk

```kql
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType == "FileCreated"
| where FileName endswith ".dmp" or FileName matches regex @"(?i)lsass.*\.(dmp|bin|zip)"
| where not(FolderPath startswith @"C:\Windows\Minidump" or FolderPath startswith @"C:\ProgramData\Microsoft\Windows\WER")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName
```

### 5. Related credential access paths

- **SAM/SYSTEM/SECURITY hive export**: `reg save HKLM\SAM`, `reg save HKLM\SYSTEM` (T1003.002)
- **NTDS.dit** via `ntdsutil "ac i ntds" ifm`, `vssadmin create shadow`, or `diskshadow` (T1003.003)
- **LSA protection off**: registry `RunAsPPL` set to 0 (T1562)

```kql
DeviceProcessEvents
| where ProcessCommandLine matches regex @"(?i)reg(\.exe)?\s+save\s+hklm\\(sam|system|security)"
   or ProcessCommandLine has_all ("ntdsutil","ifm")
   or ProcessCommandLine has_all ("vssadmin","create","shadow")
```

## Triage

| Check | Interpretation |
|---|---|
| `SourceImage` signed and in a trusted path? | Unsigned or user path → high suspicion |
| `GrantedAccess` | `PROCESS_VM_READ`-bearing masks needed to read credentials |
| `CallTrace` | `dbghelp`/`dbgcore` = dump; `UNKNOWN` = injection |
| Account | SYSTEM may still be an attacker who escalated; compare with baseline |
| Follow-on activity | Dump file written then compressed/exfiltrated; new logons using stolen creds (4624 type 3/9 with NTLM from odd hosts) |

## Common false positives

EDR/AV agents, backup agents, performance monitors, vendor crash-dump tools. Document each by **path + signer + access mask**.

## Escalate when

An unrecognised or user-path process opens LSASS with read access, a dump file appears, or credential tool strings are seen. **Treat accounts logged on to that host as compromised.** Coordinate password/Kerberos ticket resets with IR.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1003.001` in the lab (disable or allowlist your lab EDR appropriately).
- Detection: [LSASS access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml)
- Hardening: enable **LSA protection (RunAsPPL)**, **Credential Guard**, ASR rule *Block credential stealing from LSASS*, remove local admin, limit WDigest (`UseLogonCredential=0`), reduce privileged logons to workstations (tiering).
