---
title: "Playbook: Process Injection"
permalink: /hunt/playbooks/process-injection/
excerpt: "Find code running inside processes that never loaded it: remote threads, suspicious handle access, hollowed binaries, reflective loaders and injected processes talking to the network."
tactic: "Defense Evasion"
attack: [T1055, T1055.001, T1055.002, T1055.012]
difficulty: 3
timebox: "1-2 days"
data: [sysmon, edr]
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1055 (Process Injection), T1055.001 (DLL Injection), T1055.002 (PE Injection), T1055.012 (Process Hollowing) |
| **Tactic** | Defense Evasion / Privilege Escalation |
| **Data** | Sysmon 8 (CreateRemoteThread), 10 (ProcessAccess), 1 (ProcessCreate), 3 (NetworkConnect), 7 (ImageLoad); Defender `DeviceEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`; PowerShell 4104; EDR memory-scan / unbacked-module telemetry |
| **Time-box** | 1-2 days |
| **Difficulty** | ★★★ |

## Background

Injection moves attacker code into a process that is already trusted: it inherits that process's identity, token, network reputation and allow-list status, and the on-disk image stays clean. Three families dominate:

- **Classic remote injection** (T1055.001/.002): `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` (or `NtCreateThreadEx`, `QueueUserAPC`). Sysmon 10 sees the handle, Sysmon 8 sees the thread.
- **Process hollowing** (T1055.012): start a benign binary **suspended**, unmap its image, write the payload, resume. No remote thread into a *foreign* process, so Sysmon 8 is quiet; the signals are the parent/child pair and a process whose behaviour does not match its name.
- **Reflective / in-memory loading**: PowerShell or a loader maps a PE/shellcode into its *own* process. No Sysmon 7 image load for the payload; EDRs flag it as an **unbacked** or **floating** module.

Favourite hosts: `explorer.exe`, `svchost.exe`, `RuntimeBroker.exe`, browsers (traffic looks normal), `lsass.exe`/`winlogon.exe` (SYSTEM and credentials), and throwaway GUI binaries (`notepad.exe`, `mspaint.exe`, `calc.exe`) as hollowing targets.

## Hypothesis

> *If an adversary has injected into a process on this estate, we will see a non-security-product source create a remote thread or open a handle with write/create-thread rights to a sensitive or long-lived process, a benign-looking binary behaving out of character (outbound connections, unusual children, mismatched image and command line), or EDR flagging executable memory with no backing file.*

## Data required

- Sysmon **event 8** (CreateRemoteThread) and **event 10** (ProcessAccess) for the targets above. Default configs often log 10 only for `lsass.exe`; extend it to `explorer.exe`, `svchost.exe`, `winlogon.exe` and browsers and filter `GrantedAccess` in the config to control volume. Sysmon **event 3** for the accessory binaries in step 5.
- Defender for Endpoint: `DeviceEvents` with `ActionType` in `CreateRemoteThreadApiCall`, `OpenProcessApiCall`, `ProcessPrimaryTokenModified`, `NtAllocateVirtualMemoryRemoteApiCall`, `NtProtectVirtualMemoryApiCall`, `QueueUserApcRemoteApiCall`, `SetThreadContextRemoteApiCall`. Defender **samples** some of these, so absence is not clearance; it also raises alerts for injection it blocks (`AlertEvidence`).
- PowerShell Script Block Logging (4104); a baseline of tooling that legitimately touches other processes (EDR, AV, DLP, accessibility software).

## Hunt steps

### 1. Remote threads into sensitive or favourite host processes (Sysmon 8)

```spl
index=sysmon EventCode=8
  (TargetImage="*\\lsass.exe" OR TargetImage="*\\winlogon.exe" OR TargetImage="*\\csrss.exe" OR TargetImage="*\\services.exe"
   OR TargetImage="*\\explorer.exe" OR TargetImage="*\\svchost.exe" OR TargetImage="*\\RuntimeBroker.exe"
   OR TargetImage="*\\chrome.exe" OR TargetImage="*\\msedge.exe" OR TargetImage="*\\firefox.exe")
  NOT (SourceImage="C:\\Windows\\System32\\csrss.exe" OR SourceImage="C:\\Windows\\System32\\svchost.exe"
       OR SourceImage="C:\\Windows\\System32\\wininit.exe" OR SourceImage="*\\MsMpEng.exe")
| stats count dc(host) as hosts values(StartModule) as start_module values(StartFunction) as start_function values(TargetImage) as targets by SourceImage
| sort hosts
```

```kql
DeviceEvents
| where Timestamp > ago(14d) and ActionType == "CreateRemoteThreadApiCall"
| where FileName in~ ("lsass.exe","winlogon.exe","csrss.exe","services.exe","explorer.exe","svchost.exe","RuntimeBroker.exe","chrome.exe","msedge.exe","firefox.exe")
| where InitiatingProcessFolderPath !startswith @"c:\programdata\microsoft\windows defender"
    and InitiatingProcessFileName !in~ ("csrss.exe","svchost.exe","wininit.exe","MsMpEng.exe")
| summarize Count = count(), Hosts = dcount(DeviceName), Targets = make_set(FileName, 10)
          by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessVersionInfoCompanyName
| order by Hosts asc
```

Read `StartModule`/`StartFunction`: a thread that starts at `kernel32.dll!LoadLibraryA/W` is textbook DLL injection; **an empty `StartModule`** means the thread starts in memory with no backing file (shellcode); a `StartAddress` ending in `0000` is page-aligned, which freshly allocated regions tend to be. In Defender the equivalent field set is in `AdditionalFields`.

### 2. Handle access with write/create-thread rights (Sysmon 10)

The LSASS playbook hunts *read* masks (`0x1010`, `0x1410`, `0x143a`). Injection needs **write** and **thread** rights: `0x1F0FFF` / `0x1FFFFF` (PROCESS_ALL_ACCESS), `0x1F3FFF`, or masks containing `0x0008` (VM_OPERATION), `0x0020` (VM_WRITE) and `0x0002` (CREATE_THREAD), e.g. `0x002A`, `0x043A`, `0x1F2FFF`.

```spl
index=sysmon EventCode=10
  (TargetImage="*\\explorer.exe" OR TargetImage="*\\svchost.exe" OR TargetImage="*\\lsass.exe" OR TargetImage="*\\winlogon.exe" OR TargetImage="*\\RuntimeBroker.exe")
  (GrantedAccess=0x1F0FFF OR GrantedAccess=0x1FFFFF OR GrantedAccess=0x1F3FFF OR GrantedAccess=0x1F2FFF OR GrantedAccess=0x002A OR GrantedAccess=0x043A)
  NOT (SourceImage="C:\\Windows\\System32\\*" OR SourceImage="*\\MsMpEng.exe")
| stats count values(GrantedAccess) as masks values(CallTrace) as calltrace by SourceImage TargetImage
```

```kql
DeviceEvents
| where Timestamp > ago(14d) and ActionType == "OpenProcessApiCall"
| where FileName in~ ("explorer.exe","svchost.exe","lsass.exe","winlogon.exe","RuntimeBroker.exe")
| extend Access = tostring(parse_json(AdditionalFields).DesiredAccess)
| where Access in~ ("0x1F0FFF","0x1FFFFF","0x1F3FFF","2035711","2097151")
| summarize Count = count(), Hosts = dcount(DeviceName) by InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, Access
```

`CallTrace` with `UNKNOWN` frames means the call came from unbacked memory: the *source* is probably already injected. The `System32` exclusion above is only acceptable because this step is not hunting `lsass.exe` read masks; drop it for LSASS.

### 3. Hollowing indicators: odd parents, missing arguments, mismatched identities

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("svchost.exe","notepad.exe","mspaint.exe","calc.exe","werfault.exe","dllhost.exe","RuntimeBroker.exe","explorer.exe")
| where (FileName =~ "svchost.exe" and ProcessCommandLine !contains "-k" and InitiatingProcessFileName !in~ ("services.exe","MsMpEng.exe"))
    or (FileName =~ "dllhost.exe" and ProcessCommandLine !contains "/Processid")
    or (FileName =~ "RuntimeBroker.exe" and ProcessCommandLine !contains "-Embedding")
    or (FileName in~ ("notepad.exe","mspaint.exe","calc.exe") and InitiatingProcessFileName !in~ ("explorer.exe","cmd.exe","powershell.exe"))
    or (FolderPath !startswith @"c:\windows\" and FileName in~ ("svchost.exe","explorer.exe","RuntimeBroker.exe"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine
```

```spl
index=sysmon EventCode=1
  ((Image="*\\svchost.exe" NOT CommandLine="*-k*" NOT ParentImage="*\\services.exe")
   OR (Image="*\\dllhost.exe" NOT CommandLine="*/Processid*")
   OR (Image="*\\RuntimeBroker.exe" NOT CommandLine="*-Embedding*")
   OR ((Image="*\\notepad.exe" OR Image="*\\mspaint.exe" OR Image="*\\calc.exe") NOT (ParentImage="*\\explorer.exe" OR ParentImage="*\\cmd.exe")))
| table _time host User ParentImage ParentCommandLine Image CommandLine
```

Other tells: `Image` path and `OriginalFileName` disagree; the command line names one program while the image path is another; `CREATE_SUSPENDED` (0x4) in EDR process-creation flags where exposed; the child has **no Sysmon 7 image loads** for DLLs its real counterpart always loads (notepad without `comdlg32.dll`).

### 4. Reflective loading hints in PowerShell (4104)

```kql
Event
| where TimeGenerated > ago(14d) and Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| extend Script = tostring(EventData)
| where Script has_any ("VirtualAlloc","VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtCreateThreadEx",
                        "QueueUserAPC","Invoke-ReflectivePEInjection","Invoke-Shellcode","Invoke-DllInjection",
                        "[System.Runtime.InteropServices.Marshal]::Copy","GetDelegateForFunctionPointer","OpenProcess(")
| summarize Hits = count(), Hosts = dcount(Computer), Sample = any(substring(Script, 0, 300)) by Computer, UserName
```

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*VirtualAlloc*" OR ScriptBlockText="*WriteProcessMemory*" OR ScriptBlockText="*CreateRemoteThread*"
   OR ScriptBlockText="*NtCreateThreadEx*" OR ScriptBlockText="*QueueUserAPC*" OR ScriptBlockText="*Invoke-ReflectivePEInjection*"
   OR ScriptBlockText="*GetDelegateForFunctionPointer*")
| stats count values(host) as hosts by UserID ScriptBlockId
```

Reassemble chunked script blocks (same `ScriptBlockId`) before judging. `Marshal::Copy` plus `GetDelegateForFunctionPointer` is the fingerprint of shellcode runners that avoid naming Win32 APIs. Logging prerequisites are in the [PowerShell abuse playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/).

### 5. Injected hosts making network connections

Accessory binaries should never talk to the internet; any outbound connection from them is a lead.

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d) and ActionType in ("ConnectionSuccess","ConnectionRequest")
| where InitiatingProcessFileName in~ ("notepad.exe","calc.exe","calculator.exe","mspaint.exe","write.exe","wordpad.exe","charmap.exe","magnify.exe","osk.exe","werfault.exe","SearchProtocolHost.exe")
| where not(ipv4_is_private(RemoteIP)) and RemoteIP !startswith "127." and RemoteIP !startswith "fe80"
| summarize Connections = count(), Destinations = make_set(RemoteIP, 10), Ports = make_set(RemotePort, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

```spl
index=sysmon EventCode=3 Initiated=true
  (Image="*\\notepad.exe" OR Image="*\\calc.exe" OR Image="*\\mspaint.exe" OR Image="*\\write.exe" OR Image="*\\charmap.exe" OR Image="*\\werfault.exe" OR Image="*\\SearchProtocolHost.exe")
  NOT (DestinationIp=10.* OR DestinationIp=192.168.* OR DestinationIp=172.16.* OR DestinationIp=172.17.* OR DestinationIp=172.2* OR DestinationIp=172.30.* OR DestinationIp=172.31.* OR DestinationIp=127.*)
| stats count dc(DestinationIp) as dests values(DestinationPort) as ports by host Image ParentImage
```

For injected `explorer.exe`/`svchost.exe`/browsers, run the [C2 beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) analysis per process rather than per host.

### 6. Unbacked or floating modules from EDR

Most EDRs record executable memory with no file backing (Defender `DeviceEvents` remote allocation/protection calls with RWX or RX protection and alerts such as "Behavior:Win32/InjectedCode"; CrowdStrike "injected thread" / "reflective DLL"; Elastic "Memory Threat"). Stack by process name and look for a benign image carrying them.

```kql
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("NtAllocateVirtualMemoryRemoteApiCall","NtProtectVirtualMemoryApiCall","QueueUserApcRemoteApiCall","SetThreadContextRemoteApiCall","ProcessPrimaryTokenModified")
| summarize Events = count(), Hosts = dcount(DeviceName), Types = make_set(ActionType) by InitiatingProcessFileName, FileName
| order by Hosts asc
```

`ProcessPrimaryTokenModified` on its own is token manipulation, but it frequently follows injection into a SYSTEM process; treat it as corroboration.

## Triage

| Check | Interpretation |
|---|---|
| Source image path and signer | Unsigned, user-writable path (`%TEMP%`, `%APPDATA%`, `Downloads`) = strong; signed security vendor = probably baseline |
| `StartModule` / `StartFunction` on Sysmon 8 | Empty module or `LoadLibrary*` = injection; `ntdll.dll!RtlUserThreadStart` with a known module = often benign |
| `CallTrace` frames | `UNKNOWN` frames = call originated from unbacked memory |
| Target behaviour after the event | New outbound connections, child processes, file writes from the *target* within minutes = payload is running |
| Target identity | `lsass`/`winlogon` = credential or SYSTEM intent; browser/explorer = C2 hosting |
| Image loads of the child (Sysmon 7) | Missing the DLLs the real program always loads = hollowed |
| Same source on many hosts | Enterprise tooling; one or two hosts = targeted |

## Common false positives

- EDR, AV, DLP, application-control and backup agents (exclude by exact path **and** signer, never by name alone)
- Accessibility software, input-method editors, macro tools, shell extensions and overlays hooking `explorer.exe` or browsers
- Debuggers and profilers (WinDbg, Visual Studio, `dotnet-dump`, Process Explorer) on developer machines
- Windows Error Reporting (`WerFault.exe`) opening crashed processes with full access; game anti-cheat

## Escalate when

A thread or write-access handle into `lsass.exe`/`winlogon.exe` from anything other than documented tooling; any accessory binary with external connections; a hollowing pattern (step 3) whose child then connects out or spawns children; or EDR unbacked-memory telemetry on a tier-0 host. Capture a memory image of the target process before killing it.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1055` (remote-thread shellcode and `mavinject` into a test process), `T1055.001` (DLL injection), `T1055.002` (PE injection), `T1055.012` (hollowing via suspended `svchost.exe`/`notepad.exe`). Record which of steps 1, 3 and 5 fired.
- Detection: [Remote thread into sensitive process]({{ site.baseurl }}/research/sigma/T1055-remote-thread-into-sensitive-process.yml), [Network connection from benign GUI binary]({{ site.baseurl }}/research/sigma/T1055-hollowed-process-network-connection.yml); pair with [Suspicious LSASS access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml) for the read-mask side.
- Hardening: ASR rules ("Block Office applications from injecting code into other processes", "Block credential stealing from LSASS"); LSASS as Protected Process Light (`RunAsPPL`) and Credential Guard; Arbitrary Code Guard for browsers and Office via Exploit Protection; Constrained Language Mode and AMSI for PowerShell; remove local admin so injection into other users' processes fails.

See also: [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) for read-access masks, [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) for 4104 collection, [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) for masquerading, and the [Sysmon cheat sheet]({{ site.baseurl }}/cheatsheets/sysmon.pdf).
