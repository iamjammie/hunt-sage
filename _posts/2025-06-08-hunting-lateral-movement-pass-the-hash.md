---
title: "Hunting Lateral Movement: What Pass-the-Hash Looks Like in Your Logs"
date: 2025-06-08
categories:
  - blog
tags:
  - threat-hunting
  - lateral-movement
  - NTLM
  - windows
  - active-directory
toc: true
toc_label: "Contents"
header:
  teaser: /assets/images/posts/lateral-movement.png
excerpt: "Pass-the-Hash is one of the most common post-exploitation moves. It leaves specific, findable traces — if you know where to look."
---

## Why Lateral Movement Matters

Initial access is just the beginning. What attackers actually want is deeper in your network — the domain controller, the backup server, the database with customer data. To get there, they move laterally.

**Pass-the-Hash (PtH)** is one of the most common lateral movement techniques. The attacker steals an NTLM hash from memory (using tools like Mimikatz) and uses it to authenticate to other systems — without ever knowing the plaintext password.

The good news: it leaves traces. The bad news: most of those traces blend into normal Windows authentication noise if you don't know the difference.

---

## How Pass-the-Hash Works

Normal NTLM authentication flow:
```
User enters password → Client hashes it → Sends hash to server → Server validates
```

Pass-the-Hash:
```
Attacker steals hash from LSASS memory → Uses hash directly → Server can't tell the difference
```

The result is a valid authentication session using a stolen credential. The key forensic artifact: **the attacker authenticates with a hash, but the logon type and source will be unusual**.

---

## The Indicators to Hunt

### Windows Event Log Signatures

PtH attacks generate specific Windows Security event patterns:

| Event ID | Description | PtH Indicator |
|----------|-------------|---------------|
| 4624 | Successful Logon | Logon Type 3 (Network) with NTLM, blank workstation name |
| 4625 | Failed Logon | Multiple 4625s before success suggests hash spraying |
| 4776 | NTLM Auth attempt | Source workstation doesn't match originating host |
| 4648 | Logon with explicit credentials | Indicates RunAs-style lateral movement |

**The critical field for PtH detection in Event 4624**:
- `Authentication Package: NTLM`
- `Logon Type: 3`
- `WorkstationName: (blank or mismatched)`
- `SubjectLogonId: 0x0` (null session indicator)

---

## Hunting Queries

### Microsoft Sentinel / KQL

**Hunt 1: Network logons via NTLM with blank workstation (PtH fingerprint)**
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where WorkstationName == "" or WorkstationName == "-"
| where TargetUserName !endswith "$"  // exclude machine accounts
| summarize count(), 
            TargetSystems = make_set(Computer),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by TargetUserName, IpAddress
| where count_ > 3
| order by count_ desc
```

**Hunt 2: Logon source IP doesn't match known workstation**
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| extend ExpectedWorkstation = tostring(WorkstationName)
| where IpAddress != "" and ExpectedWorkstation != ""
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 2  // interactive logon = where they actually sit
    | summarize KnownIP = make_set(IpAddress) by TargetUserName
) on TargetUserName
| where not(IpAddress in (KnownIP))
| project TimeGenerated, TargetUserName, IpAddress, Computer, ExpectedWorkstation
```

**Hunt 3: Mimikatz Artifact — LSASS access from unexpected process**
```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe", "csrss.exe", "wininit.exe", 
    "lsass.exe", "services.exe", "svchost.exe"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

---

### Splunk SPL Equivalents

**Splunk Hunt — NTLM Network Logon Anomaly**:
```spl
index=wineventlog EventCode=4624 
    Logon_Type=3 
    Authentication_Package=NTLM
    Workstation_Name="-"
| where NOT like(user, "%$")
| stats count by user, src_ip, dest
| where count > 3
| sort -count
```

---

## Sigma Rule: Pass-the-Hash Detection

```yaml
title: Possible Pass-the-Hash Activity
id: a8b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: |
  Detects network logons (Type 3) using NTLM authentication with 
  blank workstation name — a common artifact of Pass-the-Hash attacks.
references:
  - https://attack.mitre.org/techniques/T1550/002/
  - https://www.eventid.net/display.asp?eventid=4624
author: hunt-sage
date: 2025/06/08
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
  filter_workstation:
    WorkstationName|contains:
      - ''
      - '-'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  filter_anonymous:
    TargetUserName: 'ANONYMOUS LOGON'
  condition: selection and filter_workstation and not filter_machine_accounts and not filter_anonymous
falsepositives:
  - Some legitimate software may use NTLM with blank workstation field
  - Scheduled tasks running under domain credentials
level: medium
tags:
  - attack.lateral_movement
  - attack.credential_access
  - attack.t1550.002
  - attack.t1003.001
```

---

## Pivoting After a Hit

If your query returns results that look suspicious, your next moves:

1. **Identify the source host** — What system did this lateral movement originate from? That's likely your beachhead.

2. **Check what the account did after authentication** — Look for Event ID 4688 (process creation) on the destination host within 5 minutes of the 4624.

3. **Look for credential dumping on the source** — Event 10 in Sysmon (process access to lsass.exe) or Security Event 4656/4663 on the LSASS process object.

4. **Check for persistence** — New scheduled tasks (Event 4698), new services (7045), registry run key modifications.

5. **Timeline it** — Build a full timeline: when did the attacker gain initial access, when did they dump credentials, when did they move laterally, what did they access?

---

## What Normal Looks Like

Before you escalate everything, know your baseline. In most environments, legitimate sources of NTLM Type 3 logons with blank workstation names include:

- Legacy applications (pre-Kerberos era software)
- Some backup agents
- Certain monitoring tools

The difference is **volume, timing, and source IP**. Attackers tend to move fast and hit multiple hosts in short windows. Your baseline won't do that.

---

## Turning This Into a Continuous Detection

Once you've validated this hunt, save it as a scheduled rule:
- **Frequency**: Every 1 hour
- **Lookback**: 2 hours
- **Alert threshold**: >5 NTLM Type 3 logons with blank workstation from same source IP within 30 minutes

That's a detection rule. You just automated your own hunt.

---

*Next post: Hunting Command & Control — Detecting Beaconing Behaviour in Network Logs.*
