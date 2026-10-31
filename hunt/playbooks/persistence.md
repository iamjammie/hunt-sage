---
title: "Playbook: Persistence"
permalink: /hunt/playbooks/persistence/
excerpt: "Stack and diff autoruns, scheduled tasks, services and WMI subscriptions to find what survives a reboot."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1547.001 (Run keys/Startup), T1053.005 (Scheduled Task), T1543.003 (Windows Service), T1546.003 (WMI subscription), T1546.* (event-triggered execution), T1136 (Create Account), T1574 (hijack execution flow) |
| **Tactic** | Persistence (and Privilege Escalation) |
| **Data** | Sysmon 12/13/14 (registry), 11 (file create), 19/20/21 (WMI), 1; Security 4698/4699/4702, 4697/7045, 4720/4732; EDR autoruns inventory |
| **Time-box** | 3-6 hours |
| **Difficulty** | ★★☆ |

## Hypothesis

> *If an adversary has established persistence, one or more hosts will have autostart entries (registry, tasks, services, WMI) that point to unusual locations, are unique in the fleet, were created at suspicious times, or launch interpreters with network capability.*

Persistence is a *state*, so it is the best hunt for **stacking and diffing**. Deep dive: [Hunting persistence]({{ site.baseurl }}/blog/hunting-persistence/).

## Hunt steps

### 1. Registry Run / RunOnce / Winlogon / IFEO

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d) and ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\CurrentVersion\Policies\Explorer\Run",
                             @"\Winlogon\Shell", @"\Winlogon\Userinit", @"Image File Execution Options", @"\Windows\AppInit_DLLs")
| where RegistryValueData has_any ("\\AppData\\","\\Temp\\","\\Users\\Public\\","\\ProgramData\\","powershell","cmd.exe","wscript","mshta","rundll32","regsvr32","http")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
```

```spl
index=sysmon EventCode=13 (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Winlogon\\Shell" OR TargetObject="*\\Winlogon\\Userinit" OR TargetObject="*Image File Execution Options*")
| regex Details="(?i)(\\\\AppData\\\\|\\\\Temp\\\\|\\\\Users\\\\Public\\\\|powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32|https?:)"
| table _time host Image TargetObject Details
```

### 2. Scheduled tasks: stack and inspect

```kql
DeviceEvents
| where Timestamp > ago(30d) and ActionType == "ScheduledTaskCreated"
| extend Task = tostring(parse_json(AdditionalFields).TaskName)
| summarize Hosts = dcount(DeviceName), First = min(Timestamp) by Task
| order by Hosts asc
```

```spl
index=wineventlog EventCode=4698
| rex field=Message "(?s)<Command>(?<cmd>.*?)</Command>\s*(<Arguments>(?<args>.*?)</Arguments>)?"
| stats count dc(host) as hosts values(cmd) values(args) by Task_Name
| sort hosts
```

Flag: task names that mimic Microsoft (`\Microsoft\Windows\...` created by a non-SYSTEM process), commands in user-writable paths, interpreters with encoded args, and tasks created remotely (`schtasks /create /s <host>`, preceded by network logon).

On a host: `schtasks /query /fo LIST /v` and inspect `C:\Windows\System32\Tasks`. Hidden tasks (missing SD value in registry `TaskCache\Tree\<task>` – Tarrask-style) will not show in `schtasks` but will in the registry/Tasks folder.

### 3. New / unusual services

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4697
| where ServiceFileName !startswith @"C:\Windows\" and ServiceFileName !startswith @"C:\Program Files"
| summarize Count = count(), Hosts = dcount(Computer) by ServiceName, ServiceFileName
| order by Hosts asc
```

```spl
index=wineventlog source="WinEventLog:System" EventCode=7045
| stats count dc(host) as hosts values(Service_File_Name) as image values(Service_Account) as acct by Service_Name
| sort hosts
```

Look for: `LocalSystem` accounts running from `Temp`/`ProgramData`/user profiles, random-named services, `cmd.exe /c`/`powershell` ImagePath, and kernel drivers (`Type=1`) from odd paths (BYOVD).

### 4. WMI event subscriptions

Legitimate subscriptions are rare; any `CommandLineEventConsumer` or `ActiveScriptEventConsumer` outside management tools is a strong lead.

```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time host EventCode Operation User Name Query Destination Consumer Filter
```

On host:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### 5. Startup folders, Office add-ins, COM hijacks, and DLL search-order

```kql
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType == "FileCreated"
| where FolderPath has @"\Start Menu\Programs\Startup" or FolderPath has @"\Microsoft\Office\" and FileName endswith ".xll"
| where InitiatingProcessFileName !in~ ("explorer.exe","msiexec.exe","OneDrive.exe")
```

- **COM hijack**: `HKCU\Software\Classes\CLSID\*\InprocServer32` set to a user-writable path (Sysmon 13).
- **DLL hijacking**: unsigned DLL loaded by a signed binary from a user-writable path (Sysmon 7); stack `ImageLoaded` by rarity.

### 6. Accounts as persistence

```kql
SecurityEvent
| where EventID in (4720, 4722, 4728, 4732, 4756)  // create, enable, add to global/local/universal group
| project TimeGenerated, Computer, EventID, TargetUserName, SubjectUserName, MemberName, TargetSid
```

Alert on additions to **Administrators / Domain Admins / Remote Desktop Users** by non-IAM accounts and on new accounts created outside change windows.

## Triage

| Question | Why |
|---|---|
| Creation time vs. user/ admin activity? | Off-hours or just after a suspicious logon |
| Signed binary in trusted path? | Unsigned in `ProgramData`/`AppData` = priority |
| Unique to one host? | Fleet-unique + unusual path = high priority |
| What does it execute and does that process connect out? | Confirms purpose |
| Who created it (initiating process/user)? | Remote creation implies lateral movement |

## Common false positives

Software installers/updaters (Chrome, Zoom, Teams), management agents, GPO-pushed tasks, AV/EDR, SCCM WMI usage.

## Escalate when

Persistence points to an unsigned/unknown binary or interpreter script in a user-writable path, or was created by a process chain tied to other suspicious activity.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1547.001`, `T1053.005`, `T1543.003`, `T1546.003`
- Detection: [Run key]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml), [Scheduled task]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml), [Service install]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml), [WMI subscription]({{ site.baseurl }}/research/sigma/T1546.003-wmi-event-subscription.yml)
- Hardening: application control (WDAC/AppLocker); restrict who can create services/tasks remotely; scheduled autoruns baseline (Sysinternals `autorunsc -a * -c -h -s -m`) compared fleet-wide (Velociraptor `Windows.Sys.StartupItems`, osquery `startup_items`, `scheduled_tasks`, `services`).
