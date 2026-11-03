---
title: "Playbook: UAC Bypass"
permalink: /hunt/playbooks/uac-bypass/
excerpt: "Catch the silent Medium-to-High integrity jump: shell-handler registry writes, auto-elevated binaries with unexpected children, and UAC policy tampering."
tactic: "Privilege Escalation"
attack: [T1548.002, T1548, T1218.011, T1112]
difficulty: 2
timebox: "2-4 hours"
data: [edr, sysmon, windows-security]
---

{% include playbook-meta.html %}

**Data used:** EDR or Sysmon process creation **with integrity level** (Sysmon 1 `IntegrityLevel`, `DeviceProcessEvents.ProcessIntegrityLevel`); registry telemetry (Sysmon 12/13, `DeviceRegistryEvents`, or 4657 on the UAC policy keys)

## Background

Microsoft is explicit that UAC is a convenience feature, not a security boundary. For an attacker already running as a local administrator at Medium integrity, it is the one step between reading the user's files and acting with full administrative rights. The bypasses are well catalogued (the UACME project tracks dozens) and heavily scripted, but from a defender's seat almost all of them leave one of two traces, which is what this hunt looks for:

1. An **auto-elevated** Windows binary spawns a child **at High integrity** that it has no business spawning, while its own ancestry is a Medium-integrity user shell.
2. A **per-user registry value** is written moments before that binary runs, because the binary reads a handler path from `HKCU` where a normal system would read it from `HKLM`.

The signal is the combination: integrity transition plus an auto-elevated parent, or a short-lived write under `HKCU\Software\Classes\...` followed by one of a known set of binaries. The full list of auto-elevated binaries lives in the Windows manifest set; the ones abused most are `fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`, `eventvwr.exe`, `slui.exe`, `wsreset.exe`, `cmstp.exe` and the `SilentCleanup` scheduled task's `cleanmgr`/`DismHost` chain.

## Hypothesis

> *If a UAC bypass is being used, then we would see an auto-elevated Windows binary spawn a shell, script host or LOLBin at High integrity whose parent chain ran at Medium integrity, and/or a write to a shell-handler key under `HKCU\Software\Classes\` immediately before that binary runs.*

## Data required

- Process creation with **integrity level** recorded. Confirm your Sysmon config captures `IntegrityLevel` (it does by default for event 1) and that your EDR exposes `ProcessIntegrityLevel`. Without it, step 1 and 2 collapse into noisy parent/child rules.
- Registry **set-value** telemetry (Sysmon 12/13 or `DeviceRegistryEvents`). If you only have Security-log auditing, SACL the UAC policy keys for step 4.
- Parent-process fields (`ParentImage`/`InitiatingProcessFileName`) and command line.

## Hunt steps

### 1. Auto-elevated parent with an unexpected elevated child

The highest-fidelity single query. An auto-elevated binary launching an interpreter or LOLBin is rare in normal operation.

```kql
let autoElevated = dynamic(["fodhelper.exe","computerdefaults.exe","sdclt.exe","eventvwr.exe",
    "slui.exe","wsreset.exe","cmstp.exe","dismhost.exe","cleanmgr.exe"]);
let suspiciousChild = dynamic(["cmd.exe","powershell.exe","pwsh.exe","rundll32.exe",
    "regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","cmd.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where tolower(tostring(split(InitiatingProcessFolderPath, "\\")[-1])) in (autoElevated)
| where tolower(FileName) in (suspiciousChild)
| where ProcessIntegrityLevel in ("High","System")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, ProcessIntegrityLevel
| order by Timestamp desc
```

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage IN ("*\\fodhelper.exe","*\\computerdefaults.exe","*\\sdclt.exe","*\\eventvwr.exe",
                  "*\\slui.exe","*\\wsreset.exe","*\\cmstp.exe","*\\DismHost.exe","*\\cleanmgr.exe")
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe","*\\rundll32.exe","*\\regsvr32.exe",
            "*\\mshta.exe","*\\wscript.exe","*\\cscript.exe")
| search IntegrityLevel IN ("High","System")
| table _time host User ParentImage Image CommandLine IntegrityLevel
```

### 2. Integrity transition: Medium parent, High child

Broader than step 1: any process that runs at High integrity whose initiating process ran at Medium, excluding the legitimate consent path (`consent.exe`/`UAC` prompt) and known installers. Stack the parent/child pairs and read the long tail.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessIntegrityLevel == "High"
| where InitiatingProcessIntegrityLevel == "Medium"
| where InitiatingProcessFileName !in~ ("consent.exe","userinit.exe","explorer.exe")
| summarize Count = count(), Hosts = dcount(DeviceName), Sample = any(ProcessCommandLine)
          by InitiatingProcessFileName, FileName
| order by Count asc
```

Rare pairs (seen on one or two hosts, a handful of times) are the candidates. Common pairs are your installers and IT tooling, which you baseline out.

### 3. Shell-handler write under HKCU\Software\Classes

The registry half of the pattern. A write to a shell `open\command` or `DelegateExecute` value under the per-user `Classes` hive is abnormal for interactive users.

```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Software\Classes\"
| where RegistryKey has_any (@"ms-settings\shell\open\command", @"mscfile\shell\open\command",
        @"exefile\shell\runas\command\isolatedCommand", @"\shell\open\command", "DelegateExecute")
| where InitiatingProcessFileName !in~ ("explorer.exe","svchost.exe","msiexec.exe","setup.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (12,13)
  TargetObject="*\\Software\\Classes\\*"
  (TargetObject="*ms-settings\\shell\\open\\command*" OR TargetObject="*mscfile\\shell\\open\\command*"
   OR TargetObject="*\\shell\\runas\\command\\isolatedCommand*" OR TargetObject="*DelegateExecute*")
| table _time host User Image TargetObject Details
```

### 4. Correlate: handler write then auto-elevated binary (sequence/timing)

The write and the launch within a short window on one host is the bypass itself. Join step 3's writes to step 1's launches.

```kql
let writes = DeviceRegistryEvents
    | where Timestamp > ago(14d) and ActionType == "RegistryValueSet"
    | where RegistryKey has @"\Software\Classes\" and RegistryKey has @"\shell\open\command"
    | project WriteTime = Timestamp, DeviceName, Writer = InitiatingProcessFileName;
let launches = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where tolower(tostring(split(InitiatingProcessFolderPath, "\\")[-1]))
        in ("fodhelper.exe","computerdefaults.exe","sdclt.exe","eventvwr.exe","slui.exe","wsreset.exe")
    | where ProcessIntegrityLevel in ("High","System")
    | project LaunchTime = Timestamp, DeviceName, Elevated = InitiatingProcessFileName,
              Child = FileName, ProcessCommandLine;
writes
| join kind=inner launches on DeviceName
| where LaunchTime between (WriteTime .. WriteTime + 2m)
| project DeviceName, WriteTime, Writer, LaunchTime, Elevated, Child, ProcessCommandLine
```

### 5. UAC policy tampering

Disabling the prompt (or admin-approval mode) is a blunter route. Watch the policy values under `...\Policies\System`.

```kql
DeviceRegistryEvents
| where RegistryKey endswith @"\CurrentVersion\Policies\System"
| where RegistryValueName in ("ConsentPromptBehaviorAdmin","EnableLUA","PromptOnSecureDesktop",
        "FilterAdministratorToken","LocalAccountTokenFilterPolicy")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          RegistryValueName, RegistryValueData
```

`EnableLUA = 0` or `ConsentPromptBehaviorAdmin = 0` outside a known hardening/GPO change is a finding on its own. If you only have Security-log auditing, SACL these keys and read 4657.

### 6. COM elevation moniker reuse

Some bypasses drive an elevated COM object via `dllhost.exe` with a `/Processid:{GUID}` argument. Stack the GUIDs and investigate `dllhost` running at High integrity from a Medium parent.

```kql
DeviceProcessEvents
| where FileName =~ "dllhost.exe" and ProcessCommandLine has "/Processid:"
| where ProcessIntegrityLevel in ("High","System") and InitiatingProcessIntegrityLevel == "Medium"
| summarize Count = count(), Hosts = dcount(DeviceName) by ProcessCommandLine
| order by Count asc
```

## Triage

| Check | Interpretation |
|---|---|
| Parent is an auto-elevated binary with a shell/LOLBin child | Classic bypass; near-zero legitimate reason |
| Integrity jumped Medium → High without `consent.exe` in the chain | No UAC prompt was shown: strong signal |
| `HKCU` shell-handler write seconds before the launch, then the key is deleted | The clean-up is itself evidence; look for the deletion event too |
| Account is a standard admin doing hands-on work (installing software) | Could be benign elevation; confirm the child and command line |
| `EnableLUA`/`ConsentPromptBehaviorAdmin` changed | Config change: tie to a ticket or GPO, else treat as tampering |
| What ran next | A bypass is a means; pivot to what the elevated child did (LSASS access, service install, defender changes) |

## Common false positives

- Legitimate software installers and updaters that self-elevate (baseline the parent/child pairs in step 2).
- IT automation and management agents that run tasks at High integrity.
- Admins changing UAC settings during provisioning or hardening (should map to a change record).
- Developer tooling that registers shell handlers under `HKCU` (rare, but it exists).

## Escalate when

An auto-elevated binary spawned a shell or LOLBin at High integrity with no matching install activity, a shell-handler key was written then removed around an elevation, or UAC policy was disabled outside a change window. Capture the elevated child's full activity, isolate the host if the child touched credentials or security tooling, and reset the local admin credentials used.

## Validate and operationalise

- **Emulate** in an isolated lab: `Invoke-AtomicTest T1548.002` covers the fodhelper, computerdefaults, sdclt and eventvwr paths and the UAC policy changes; run only with authorisation.
- **Detection:** [UAC bypass via shell-handler registry hijack]({{ site.baseurl }}/research/sigma/T1548.002-uac-bypass-ms-settings-registry-hijack.yml) and [Auto-elevated binary spawns a shell or LOLBin]({{ site.baseurl }}/research/sigma/T1548.002-uac-bypass-auto-elevated-parent.yml).
- **Hardening:** set UAC to "Always notify"; run day-to-day admin work from separate, non-privileged accounts (tiering); remove local-admin rights from standard users so a bypass has nothing to elevate; deploy app control (WDAC/AppLocker) so unexpected children of auto-elevated binaries cannot run; alert on `EnableLUA`/`ConsentPromptBehaviorAdmin` changes.

See also: [Process injection]({{ site.baseurl }}/hunt/playbooks/process-injection/) and [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) for what follows a successful elevation, and the [LOLBins quick reference]({{ site.baseurl }}/cheatsheets/lolbins/).

{% include playbook-footer.html %}
