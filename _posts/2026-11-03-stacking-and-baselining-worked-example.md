---
title: "Stacking and Baselining: A Worked Example on Scheduled Tasks"
date: 2026-11-03
categories:
  - blog
tags:
  - threat-hunting
  - stacking
  - baselining
  - scheduled-tasks
  - persistence
  - KQL
  - SPL
  - sigma
toc: true
toc_label: "Contents"
attack: [T1053.005]
header:
  teaser: /assets/images/posts/stacking-baselining.png
excerpt: "1,200 Windows hosts, 31 days of scheduled-task creations, one afternoon. What the long tail looked like, what we found, and how the hunt became a Sigma rule."
---

[Chapter 5]({{ site.baseurl }}/learn/hunting-techniques/) describes stacking and baselining in the abstract. This post runs both on one fleet, one data type, with real-shaped numbers, so you can see where the time goes and where the findings come from.

## The setup

| Item | Detail |
|---|---|
| Fleet | 1,200 Windows hosts: 1,050 workstations, 150 servers (40 of them file/print, 22 SQL, 18 web, the rest mixed) |
| Telemetry | Security log 4698 (task created; requires *Audit Other Object Access Events*), Sysmon 1 for `schtasks.exe`, both in Sentinel. Splunk equivalents given alongside |
| Retention | 90 days hot |
| Hypothesis | *If an attacker has established persistence via scheduled tasks (T1053.005) on any host, then a task creation will exist whose action path, creating process or account is rare across the fleet and absent from the prior 30 days.* |
| Time-box | One analyst, four hours |
| Playbook | [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |

Two data sources on purpose. 4698 gives you the task XML (action, trigger, author) regardless of how the task was created (API, PowerShell cmdlet, GPO). Sysmon 1 for `schtasks.exe` gives you the parent process and the exact command line, but only when the attacker used that binary. Each sees things the other misses.

## Step 1: Raw volume

Before stacking, know what you are stacking.

```kql
SecurityEvent
| where TimeGenerated > ago(31d) and EventID == 4698
| summarize Events = count(), Hosts = dcount(Computer)
```

Result: **48,311 task creations across 1,187 hosts** in 31 days. About 40 per host per month, dominated by Windows Update, Defender, Office and Edge maintenance tasks that are recreated on every update. Thirteen hosts generated no 4698 at all; that is a visibility finding on its own (checked later: eight were offline the whole month, five had the audit subcategory missing from their GPO).

## Step 2: Stack on the action path

The field that matters is the executable the task runs, not the task name. Task names are free text; attackers copy legitimate ones. Parse the action out of the XML and normalise it so one task does not appear as 1,200 variants.

```kql
let tasks = SecurityEvent
| where TimeGenerated > ago(31d) and EventID == 4698
| extend TaskName = tostring(parse_xml(EventData).EventData.Data[3]["#text"]),
         TaskContent = tostring(EventData)
| extend Command = extract(@"<Command>([^<]+)</Command>", 1, TaskContent),
         Arguments = extract(@"<Arguments>([^<]+)</Arguments>", 1, TaskContent)
| extend CommandNorm = tolower(replace_regex(Command, @"C:\\Users\\[^\\]+\\", @"C:\Users\<user>\"))
| extend CommandNorm = replace_regex(CommandNorm, @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<guid>");
tasks
| summarize Creations = count(), Hosts = dcount(Computer), Accounts = dcount(SubjectUserName),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Sample = any(TaskName) by CommandNorm
| order by Hosts asc, Creations asc
```

The XML field position for `TaskName` varies by Windows build and log parser; check `EventData` on your tenant before trusting index `[3]`. On Splunk the same stack looks like this:

```spl
index=wineventlog EventCode=4698 earliest=-31d
| rex field=_raw "<Command>(?P<Command>[^<]+)</Command>"
| rex field=_raw "<Arguments>(?P<Arguments>[^<]+)</Arguments>"
| rex field=_raw "TaskName\">(?P<TaskName>[^<]+)"
| eval CommandNorm=lower(Command)
| eval CommandNorm=replace(CommandNorm, "c:\\\\users\\\\[^\\\\]+\\\\", "c:\\users\\<user>\\")
| eval CommandNorm=replace(CommandNorm, "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<guid>")
| stats count as Creations, dc(host) as Hosts, dc(user) as Accounts, min(_time) as FirstSeen, max(_time) as LastSeen, values(TaskName) as Sample by CommandNorm
| sort Hosts, Creations
```

Normalising user profile paths and GUIDs collapsed **2,214 distinct raw commands to 173 normalised ones**. Of those 173, **119 appeared on fewer than 5 hosts**. That is the long tail.

## Step 3: The long tail

The bottom of the stack, trimmed. Numbers are what a fleet this size produces; names are invented.

| CommandNorm | Hosts | Creations | Accounts | First seen | Sample task name |
|---|---|---|---|---|---|
| `c:\programdata\lenovo\imcontroller\...\imcontroller.exe` | 48 | 96 | 1 (SYSTEM) | 31d+ | ImControllerScheduledTask |
| `c:\program files\dell\supportassist\...` | 41 | 41 | 1 | 31d+ | Dell SupportAssist |
| `c:\windows\system32\wscript.exe` | 9 | 11 | 3 | 31d+ | FinanceExport-Nightly, HR-Sync, ... |
| `c:\program files (x86)\veeam\...\veeam.backup.manager.exe` | 6 | 6 | 1 | 31d+ | VeeamBackup |
| `c:\users\<user>\appdata\local\programs\python\python.exe` | 4 | 7 | 4 | 31d+ | pip-upgrade, jupyter, ... |
| `c:\windows\system32\windowspowershell\v1.0\powershell.exe` | 3 | 3 | 2 | 2d | ScheduledScan, SQLMaint, **MicrosoftEdgeUpdateTaskMachineUA** |
| `c:\sqlbackups\scripts\backup_rotate.bat` | 2 | 2 | 1 | 31d+ | SQL-BackupRotate |
| `c:\programdata\microsoft\windows\update\svchost.exe` | **1** | **1** | 1 | **19h** | **GoogleUpdateTaskMachineCore** |
| `c:\users\<user>\desktop\tools\autohotkey.exe` | 1 | 2 | 1 | 31d+ | AHK-Start |
| `c:\tools\ninite\niniteone.exe` | 1 | 1 | 1 | 31d+ | Ninite Weekly |

Three rows deserve a second look before any enrichment: the one-host `svchost.exe` under ProgramData (svchost does not live there), the `powershell.exe` row whose sample task name is an Edge updater (Edge does not use PowerShell), and nine hosts running `wscript.exe` tasks under three different accounts (scripts, user context, probably legitimate but unmanaged).

## Step 4: Build the baseline and diff the last 24 hours

Stacking tells you what is rare. Baselining tells you what is *new*. The difference matters: an attacker who planted a task three weeks ago is rare but not new; a task planted last night is both.

```kql
let history = SecurityEvent
| where TimeGenerated between (ago(31d) .. ago(1d)) and EventID == 4698
| extend Command = tolower(extract(@"<Command>([^<]+)</Command>", 1, tostring(EventData)))
| extend CommandNorm = replace_regex(Command, @"c:\\users\\[^\\]+\\", @"c:\users\<user>\")
| distinct CommandNorm;
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4698
| extend Command = tolower(extract(@"<Command>([^<]+)</Command>", 1, tostring(EventData))),
         TaskName = tostring(parse_xml(EventData).EventData.Data[3]["#text"])
| extend CommandNorm = replace_regex(Command, @"c:\\users\\[^\\]+\\", @"c:\users\<user>\")
| join kind=leftanti history on CommandNorm
| project TimeGenerated, Computer, SubjectUserName, TaskName, Command
```

```spl
index=wineventlog EventCode=4698 earliest=-31d latest=-1d
| rex field=_raw "<Command>(?P<Command>[^<]+)</Command>"
| eval CommandNorm=replace(lower(Command), "c:\\\\users\\\\[^\\\\]+\\\\", "c:\\users\\<user>\\")
| stats count by CommandNorm
| outputlookup task_command_baseline_30d.csv
```

```spl
index=wineventlog EventCode=4698 earliest=-24h
| rex field=_raw "<Command>(?P<Command>[^<]+)</Command>"
| rex field=_raw "TaskName\">(?P<TaskName>[^<]+)"
| eval CommandNorm=replace(lower(Command), "c:\\\\users\\\\[^\\\\]+\\\\", "c:\\users\\<user>\\")
| lookup task_command_baseline_30d.csv CommandNorm OUTPUT count as seen_before
| where isnull(seen_before)
| table _time host user TaskName Command
```

**Last 24 hours: 1,406 task creations, 4 commands not in the 30-day baseline.**

| Host | Account | Task name | Command |
|---|---|---|---|
| WKS-FIN-0412 | SYSTEM | GoogleUpdateTaskMachineCore | `C:\ProgramData\Microsoft\Windows\Update\svchost.exe` |
| SRV-SQL-03 | svc_sqlagent | SQLMaint | `powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\sqlmaint.ps1` |
| WKS-ENG-0917 | j.okafor | AHK-Start | `C:\Users\j.okafor\Desktop\tools\autohotkey.exe` (first seen in 24h window because the user reinstalled) |
| SRV-FILE-07 | SYSTEM | MicrosoftEdgeUpdateTaskMachineUA | `powershell.exe -w hidden -nop -c "iex (gc C:\ProgramData\edge\u.txt)"` |

Two baseline pitfalls showed up immediately. The AutoHotkey row is a false "new" caused by the user profile path changing after a reinstall; the normalisation handled the username but not the fact that `Desktop\tools` had previously been `Downloads\tools`. And `SQLMaint` was new because a DBA had created it yesterday; legitimate, but with `-ExecutionPolicy Bypass` and no change ticket. Baselines surface process problems as often as attackers.

## Step 5: Triage the three that mattered

### Finding A: benign rarity (AutoHotkey, Ninite, Python tasks)

Six one- or two-host tasks were power users automating their own machines. Every one had a plausible owner, a stable creation history and a signed or well-known binary. Documented as allow-list candidates with the host and user scoped, not the path. Time spent: 25 minutes. Value: these will not cost the next hunter 25 minutes.

### Finding B: misconfiguration (nine `wscript.exe` tasks, `SQLMaint`)

Nine hosts ran VBScript tasks under three named user accounts, including one domain admin, created over the past year by a departed sysadmin. Two of the scripts pulled files from a share using a password embedded in the script. Not an attacker, but exactly the material an attacker would harvest. The `SQLMaint` task was legitimate and untracked.

Outcome: ticket to the platform team to move the scripts to a gMSA and strip the embedded credentials; ticket to the DBA team for change control on scheduled tasks on Tier 1 servers. Hunt report section 8, actions.

### Finding C: a real one (`svchost.exe` in ProgramData)

The 19-hour-old task on WKS-FIN-0412 ran `C:\ProgramData\Microsoft\Windows\Update\svchost.exe` under a Google updater task name. Enrichment from Sysmon on that host:

| Check | Result |
|---|---|
| Sysmon 1 for the binary | `OriginalFileName` = `AdFind.exe`; unsigned; SHA-256 unknown to the fleet |
| Who created the task | Sysmon 1: `schtasks.exe /create /tn "GoogleUpdateTaskMachineCore" /sc minute /mo 30 /ru SYSTEM ...` with parent `powershell.exe`, grandparent `WINWORD.EXE` |
| File arrival | Sysmon 11: written by `powershell.exe` 6 minutes after a `.docm` opened from Outlook temp |
| Network | Sysmon 3: outbound 443 to a single IP in a hosting ASN every ~30 minutes since creation |
| Follow-on | Sysmon 1: `nltest /dclist`, `net group "Domain Admins" /domain`, AdFind queries dumping users and computers |

A renamed AD enumeration tool, dropped by a macro, persisted via a scheduled task with a stolen name, beaconing on a 30-minute cadence. Nineteen hours of dwell time. No alert had fired: the macro ran in a user context, the binary was unknown rather than known-bad, and the task name matched an allow-listed pattern in the EDR.

Hunting stopped here. Evidence preserved (queries, timestamps, event exports), IR engaged with the [hand-off package]({{ site.baseurl }}/templates/#handoff-package-to-ir), host isolated by IR within 40 minutes.

## Step 6: What the follow-up looked like

| Action | Owner | Done within |
|---|---|---|
| Isolate WKS-FIN-0412; collect memory and triage image | IR | Same day |
| Sweep fleet for the SHA-256, the C2 IP and the task name on non-Google hosts (`OriginalFileName == "AdFind.exe"` anywhere) | Hunt | Same day; 0 further hosts |
| Reset the user's credentials and review what AdFind returned (user and computer lists: assume enumerated) | IR + identity | Next day |
| Block macros from the internet zone where not already enforced; confirm MOTW handling | Endpoint team | 1 week |
| Fix audit policy on the five hosts missing 4698 | Platform | 1 week |
| Remove embedded credentials from the nine VBScript tasks | Platform | 2 weeks |

The dwell time (19 hours) versus the alert-found median for that quarter (3 hours) went into the metrics deck as the argument for keeping the hunt cadence.

## Step 7: Hunt to detection

The stacking query is a hunt, not a detection: it needs a human to read 119 rows. What *does* convert cleanly is the specific shape of finding C. The existing rule [T1053.005-schtasks-suspicious-create.yml]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) already fires on `schtasks /create` with an action under `\ProgramData\`, so the first question was why it had not: it was not deployed in this tenant. It is now, with two tenant-specific filters for the Lenovo and Dell paths, and precision measured over the first fortnight at 11 true positives (all red-team or admin-scripted) in 14 alerts.

Two detection candidates came out of the hunt as additions:

1. **Renamed binary as task action**: Sysmon 1 where `Image` ends in a Windows-system filename (`svchost.exe`, `lsass.exe`, `csrss.exe`, `services.exe`) but the path is not `\Windows\System32\` or `\Windows\SysWOW64\`, or where `OriginalFileName` is a known enumeration tool and `Image` does not match it. Low volume, high precision; shipped as a Sigma rule in the tenant and proposed upstream.
2. **First-seen task command per fleet**: the baseline diff from Step 4 as a daily scheduled query producing a review list, not an alert. Four to ten rows a day; owned by the hunt rotation, 15 minutes a morning.

And one **backlog item**: *"Stack 4698 task triggers (boot, logon, minute-cadence) rather than actions; a 30-minute SYSTEM task with a fake vendor name should be rare regardless of the binary."* Trigger-based stacking would have caught finding C from the XML alone. It is scheduled for next month's hunt sprint, with the data already known to be present.

## What to copy from this

- Count before you stack. 48,311 events and 173 normalised commands told us the hunt was feasible in four hours.
- Normalise paths and GUIDs or you will stack noise.
- Rare and new are different questions. Run both; the intersection is where you start.
- Rare things with a plausible owner go on an allow-list scoped to host and user. Rare things with a stolen name and a wrong path go to IR.
- Every hunt ends with something written down: a detection deployed, two proposed, six allow-list entries, two configuration tickets, one incident and one backlog item.

Templates for the report and the backlog are on the [templates page]({{ site.baseurl }}/templates/). The techniques are in [chapter 5]({{ site.baseurl }}/learn/hunting-techniques/); the persistence hunt steps are in the [playbook]({{ site.baseurl }}/hunt/playbooks/persistence/).
