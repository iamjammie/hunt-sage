---
title: "Hunting Persistence: Every Place an Attacker Can Survive a Reboot"
date: 2025-06-29
categories:
  - blog
tags:
  - threat-hunting
  - persistence
  - windows
  - registry
  - scheduled-tasks
  - MITRE-ATT&CK
toc: true
toc_label: "Contents"
header:
  teaser: /assets/images/posts/persistence.png
excerpt: "Attackers don't want to re-exploit you every session. They plant persistence — and there are dozens of places to look."
---

## Why Persistence Matters

Most attacks don't end with a single session. Attackers establish persistence mechanisms so they survive reboots, password changes, and even partial incident response. If you remediate the initial access vector but miss the persistence, the attacker simply walks back in.

MITRE ATT&CK lists over 20 sub-techniques under the [Persistence](https://attack.mitre.org/tactics/TA0003/) tactic. This post covers the most commonly abused ones and gives you hunting queries for each.

---

## 1. Registry Run Keys

The classic. Entries under these keys execute at user logon or system startup:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**Hunt — New or unusual Run key entries**:
```kql
// Requires Sysmon Event ID 13 (Registry value set)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend TargetObject = tostring(EventData.TargetObject),
         Details = tostring(EventData.Details),
         Image = tostring(EventData.Image)
| where TargetObject has_any (
    "\\CurrentVersion\\Run",
    "\\CurrentVersion\\RunOnce"
)
| where Image !in~ (
    "C:\\Windows\\System32\\msiexec.exe",
    "C:\\Windows\\regedit.exe"
)
| project TimeGenerated, Computer, Image, TargetObject, Details
| order by TimeGenerated desc
```

**Sigma Rule**:
```yaml
title: Suspicious Registry Run Key Modification
id: c4d5e6f7-a8b9-0123-cdef-234567890123
status: stable
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
  filter_known_installers:
    Image|contains:
      - '\msiexec.exe'
      - '\setup.exe'
      - '\install.exe'
  condition: selection and not filter_known_installers
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
```

---

## 2. Scheduled Tasks

Scheduled tasks are one of the most abused persistence mechanisms because they're legitimate, numerous, and blended with thousands of real tasks in every Windows environment.

**Red flags in scheduled tasks**:
- Task created by an unusual process (not Task Scheduler UI or Group Policy)
- Task runs from a temp directory, AppData, or unusual path
- Task uses encoded PowerShell or LOLBins
- Task was created or modified outside business hours

**Hunt — Recently created scheduled tasks with suspicious commands**:
```kql
// Event ID 4698 = Scheduled Task Created
SecurityEvent
| where EventID == 4698
| extend TaskXML = tostring(EventData)
| where TaskXML has_any (
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "AppData", "Temp"
)
| where SubjectUserName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| project TimeGenerated, Computer, SubjectUserName, TaskName = tostring(EventData.TaskName), TaskXML
| order by TimeGenerated desc
```

**Splunk SPL**:
```spl
index=wineventlog EventCode=4698
| rex field=_raw "TaskName\">(?P<task_name>[^<]+)"
| rex field=_raw "Command\">(?P<command>[^<]+)"
| where match(command, "(?i)(powershell|cmd|wscript|cscript|mshta|appdata|temp)")
| table _time, host, user, task_name, command
| sort -_time
```

---

## 3. Services

Malicious services are harder to spot than run keys but grant higher privilege.

**What to look for**:
- New service with unusual binary path (temp dir, user profile dir)
- Service binary signed by unknown publisher
- Service that starts automatically but has never been observed before

**Hunt — New services with suspicious binary paths**:
```kql
// Event ID 7045 = New service installed
Event
| where Source == "Service Control Manager"
| where EventID == 7045
| extend ServiceName = tostring(EventData.ServiceName),
         ImagePath = tostring(EventData.ImagePath),
         AccountName = tostring(EventData.AccountName)
| where ImagePath has_any ("\\Temp\\", "\\AppData\\", "\\Users\\", "%TEMP%")
    or ImagePath matches regex @"[a-zA-Z0-9]{8,}\.exe"  // random-looking binary names
| project TimeGenerated, Computer, ServiceName, ImagePath, AccountName
| order by TimeGenerated desc
```

---

## 4. WMI Event Subscriptions

WMI persistence is stealthy because it leaves no obvious files or registry keys in the typical places. Instead, it lives in the WMI repository.

An attacker creates a WMI event subscription that fires when a condition is met (e.g., system startup, or every 60 seconds) and executes a payload.

**Hunt — WMI subscription creation**:
```kql
// Sysmon Event ID 19, 20, 21 = WMI activity
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID in (19, 20, 21)
| extend EventType = case(
    EventID == 19, "WMIEventFilter",
    EventID == 20, "WMIEventConsumer",
    EventID == 21, "WMIEventConsumerToFilter",
    "Unknown"
)
| extend Query = tostring(EventData.Query),
         Destination = tostring(EventData.Destination)
| project TimeGenerated, Computer, EventType, Query, Destination
| order by TimeGenerated desc
```

**Quick audit — check existing WMI subscriptions on a host** (PowerShell, run on the suspect machine):
```powershell
# List all permanent WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter | 
    Select Name, Query, QueryLanguage

Get-WMIObject -Namespace root\subscription -Class __EventConsumer | 
    Select Name, CommandLineTemplate, ScriptText

Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

Any result here that you can't account for is suspicious. Most environments have zero legitimate WMI subscriptions.

---

## 5. DLL Hijacking via PATH

Attackers drop malicious DLLs in directories that are searched before the legitimate DLL location. When a privileged process loads the DLL, the payload executes.

**Common targets**: Applications that load DLLs from the current working directory, or from user-writable directories that appear early in the DLL search order.

**Hunt — DLL loaded from unusual location by privileged process**:
```kql
// Sysmon Event ID 7 = Image Loaded
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 7
| extend Image = tostring(EventData.Image),
         ImageLoaded = tostring(EventData.ImageLoaded),
         Signed = tostring(EventData.Signed)
| where Signed == "false"
| where Image startswith "C:\\Windows\\System32\\"
    or Image startswith "C:\\Program Files\\"
| where ImageLoaded !startswith "C:\\Windows\\"
    and ImageLoaded !startswith "C:\\Program Files\\"
| project TimeGenerated, Computer, Image, ImageLoaded
| order by TimeGenerated desc
```

---

## Quick Persistence Audit Checklist

Run this on any host you suspect. Each command is a hunt in itself:

```powershell
# 1. Run keys
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# 2. Scheduled tasks (created in last 7 days)
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-7)} | 
    Select TaskName, TaskPath, State, Date

# 3. Services with non-standard binary paths
Get-WmiObject win32_service | 
    Where-Object {$_.PathName -notlike "*system32*" -and $_.PathName -notlike "*Program Files*"} | 
    Select Name, PathName, StartMode, State

# 4. WMI subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer

# 5. Startup folder
Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

---

## Building a Persistence Baseline

The key to detecting abnormal persistence is knowing what normal looks like. Before hunting, run the checklist above on 10 clean machines and document every legitimate entry. That becomes your allowlist. Anything not on it is worth investigating.

This is tedious. Do it anyway. The alternative is chasing false positives forever.

---

*View all Sigma rules from this post in [/research/sigma](/research/sigma/).*
