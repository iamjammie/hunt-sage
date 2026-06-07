---
title: "CTF Challenge: Argon Nexus — The Internal Data Spill"
permalink: /ctf/argon-nexus/
layout: single
toc: true
toc_label: "Challenge Stages"
header:
  teaser: /assets/images/ctf/argon-nexus-banner.png
excerpt: "A regional manufacturing company detected suspicious file access. Your job: reconstruct what happened, who did it, and how they got in. All artifacts provided."
difficulty: Beginner–Intermediate
skills_tested:
  - Windows Event Log analysis
  - EDR log investigation
  - Timeline reconstruction
  - Sigma/KQL query writing
---

> **Difficulty**: Beginner–Intermediate  
> **Skills**: Windows Event Logs, EDR telemetry, Timeline reconstruction  
> **Artifacts**: Available in [argon_nexus repository](https://github.com/iamjammie/argon_nexus)  
> **Estimated time**: 2–4 hours

---

## Scenario Brief

You are a SOC analyst at a MSSP. Your client, **Argon Dynamics**, is a small regional manufacturing company with approximately 200 employees.

At **06:45 AM**, their DLP system generated an alert:

> *"Unusually high volume of file reads from Finance share by account `svc_reportgenerator`"*

The client's IT team confirmed: `svc_reportgenerator` is a service account used for automated report generation. It has never previously accessed the Finance share.

Your job is to determine:
1. Was this a true positive?
2. If so, how did the attacker get access?
3. What data was accessed?
4. What happened after the data was accessed?
5. What should have detected this sooner?

---

## Artifacts Provided

Download or clone [argon_nexus](https://github.com/iamjammie/argon_nexus) for the following files:

```
argon_nexus/
├── logs/
│   ├── security_events.evtx         # Windows Security Event Log
│   ├── sysmon_events.evtx           # Sysmon operational log
│   ├── powershell_events.evtx       # PowerShell operational log
│   └── dns_events.csv               # DNS query log export
├── network/
│   ├── proxy_logs.csv               # Web proxy logs
│   └── firewall_logs.csv            # Perimeter firewall logs
└── email/
    └── mail_headers.txt             # Email headers for investigation
```

---

## Challenge Questions

Answer each question before moving to the next. Hints are available below each question if you get stuck.

---

### Stage 1: Confirm the Anomaly

**Q1.1** — Look at `security_events.evtx`. What Event ID confirms the service account accessed the Finance share, and at what exact time did the first access occur?

**Q1.2** — How many files were accessed in total? What were the file types?

**Q1.3** — What access mask was used? Was the account reading, writing, or both?

<details>
<summary>💡 Hint for Stage 1</summary>

Filter for Event ID **4663** (An attempt was made to access an object). Look at the SubjectUserName field for `svc_reportgenerator` and ObjectName for paths containing "Finance".

To export and analyse in PowerShell:
```powershell
Get-WinEvent -Path ".\logs\security_events.evtx" |
  Where-Object {$_.Id -eq 4663} |
  Where-Object {$_.Message -match "svc_reportgenerator"} |
  Select-Object TimeCreated, Message |
  Format-List
```
</details>

---

### Stage 2: Find the Authentication Source

**Q2.1** — From which workstation or IP did `svc_reportgenerator` authenticate?

**Q2.2** — Is this authentication from a workstation associated with this service account's normal operation? How do you determine this?

**Q2.3** — Who normally logs into that workstation (hint: look for Type 2 logons on that machine)?

<details>
<summary>💡 Hint for Stage 2</summary>

Filter Event ID **4624** for `svc_reportgenerator`. Look at the `IpAddress` and `WorkstationName` fields.

Then filter for Event ID **4624** with LogonType **2** (Interactive) on that workstation to find its regular user.
</details>

---

### Stage 3: Trace the Compromise

**Q3.1** — Look at `sysmon_events.evtx`. What process activity occurred on the identified workstation between 01:30 and 03:00?

**Q3.2** — What tool was used to copy files from the Finance share?

**Q3.3** — Decode the PowerShell command that ran at 01:59. What did it do?

**Q3.4** — What tool was used to archive the copied files? Where was the archive saved?

<details>
<summary>💡 Hint for Stage 3</summary>

Filter Sysmon Event ID **1** (Process Create) for the workstation name in the timeframe. Look for:
- `cmd.exe`, `net.exe`, `xcopy.exe`, `robocopy.exe`, `WinRAR.exe`, `certutil.exe`, `curl.exe`

For the PowerShell decode, find the -EncodedCommand argument and decode it:
```powershell
$encoded = "PASTE_BASE64_HERE"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```
</details>

---

### Stage 4: Find the Exfiltration

**Q4.1** — Look at `proxy_logs.csv` and `firewall_logs.csv`. Where was data sent? What IP and port?

**Q4.2** — What was the approximate size of data exfiltrated?

**Q4.3** — Using DNS logs, when did this IP first appear in queries? What does this tell you?

<details>
<summary>💡 Hint for Stage 4</summary>

Look for outbound connections from the identified workstation to external IPs on port 443 at approximately 02:44.

Check DNS logs for any lookups resolving to that IP. First appearance of the IP in DNS tells you when the attacker's initial C2 connection may have established.
</details>

---

### Stage 5: Find Initial Access

**Q5.1** — Look at `mail_headers.txt`. When was the suspicious email received and from whom?

**Q5.2** — What was the attachment name? What file type?

**Q5.3** — Cross-reference with Sysmon logs — when was the C2 connection first established after the email was opened? How long did the attacker wait before taking action?

<details>
<summary>💡 Hint for Stage 5</summary>

Look at the mail headers for the timestamp, sender domain, and attachment filename. 

In Sysmon Event ID **3** (Network Connection), filter for connections to the attacker C2 IP. The first occurrence is when initial access was established.

Compare that timestamp to the bulk file access — the difference is the attacker's "dwell time" before acting.
</details>

---

### Stage 6: Improve Defences

**Q6.1** — List at least 5 detection opportunities that were missed. For each, name the log source that would have caught it.

**Q6.2** — Write a Sigma rule or KQL query to detect at least one of those gaps.

**Q6.3** — Write a 3-sentence incident summary suitable for an executive briefing.

---

## Scoring Rubric

| Stage | Points | Bonus |
|-------|--------|-------|
| Stage 1 — Confirm anomaly | 10 | +5 for exact file count |
| Stage 2 — Auth source | 15 | +5 for identifying regular user |
| Stage 3 — Trace compromise | 25 | +10 for decoded PowerShell |
| Stage 4 — Exfiltration | 20 | +5 for data size estimate |
| Stage 5 — Initial access | 20 | +5 for dwell time calculation |
| Stage 6 — Improve defences | 10 | +10 for working Sigma/KQL |
| **Total** | **100** | **+40 bonus** |

---

## Solution Walkthrough

The full solution walkthrough is available in the blog post: [**The Argon Dynamics Case Study**](/blog/argon-dynamics-case-study/)

Try to complete the challenge before reading it.

---

## What You'll Learn

By completing this challenge, you'll have practised:
- Navigating Windows Event Logs with PowerShell and EVTX parsers
- Correlating events across multiple log sources
- Decoding obfuscated commands
- Reconstructing an attacker timeline
- Writing detection rules from real incident data

These are the core skills for Tier 1 and Tier 2 SOC analyst roles.

---

*More CTF challenges coming soon. [Suggest a scenario →](https://github.com/iamjammie/hunt-sage/issues)*
