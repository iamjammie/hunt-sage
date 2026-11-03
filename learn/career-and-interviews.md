---
title: "Threat Hunting Careers & Interview Prep"
permalink: /learn/career-and-interviews/
excerpt: "Roles and ladders, a skills matrix, a 90-day self-study plan built from this site, portfolio ideas, certifications and 40 interview questions with model-answer notes."
toc: true
toc_sticky: true
sidebar:
  nav: "learn"
---

This page is for two readers: the analyst who wants to move into hunting, and the hiring manager who needs to tell a hunter from someone who has memorised event IDs. Both benefit from the same thing: a clear picture of what a hunter is expected to *produce*.

## Roles and ladders

| Level | Typical title | Expected to produce |
|---|---|---|
| **Entry** | SOC analyst (Tier 1/2) | Triaged alerts with evidence; escalations that contain host, user, process, time and a hypothesis; tuning suggestions |
| **Hunter** | Threat hunter, Tier 3 analyst, detection analyst | Completed hunts from a backlog, each ending in a documented outcome (detection, gap, hardening, incident or a negative result); peer-reviewable queries |
| **Senior** | Senior hunter, hunt lead | Original hypotheses from intel and anomalies; statistical/baseline hunts; mentoring; the hunt backlog and its prioritisation; metrics for leadership |
| **Lead / principal** | Hunt program lead, principal detection engineer | The program itself: cadence, hand-offs, data-source roadmap, coverage mapping, budget justification; cross-team influence |

**Detection engineer adjacency.** Hunting and detection engineering are two halves of one loop ([chapter 7]({{ site.baseurl }}/learn/detection-engineering/)). Hunters discover; detection engineers productionise, test and maintain. Many teams rotate people between the two, and most job adverts for "threat hunter" expect you to write and test rules. If you can only do one, learn the other.

**MSSP vs in-house.**

| | MSSP / MDR | In-house |
|---|---|---|
| Environments | Many, shallow context, varied telemetry | One, deep context, your own baselines |
| Volume | High; repeatable playbooks and automation matter | Lower; original hypotheses and long baselines matter |
| Growth | Breadth fast; see many intrusion types | Depth; influence logging, hardening and architecture |
| Risk | Burnout, templated work | Complacency, "we've never seen that here" |

Early career, an MSSP or MDR gives you incident exposure that an in-house team may never see. Later, an in-house role lets you build the program described in [chapter 8]({{ site.baseurl }}/learn/building-a-hunt-program/).

## Skills matrix

| Skill | Why it matters | How to prove it |
|---|---|---|
| Hunting method (hypothesis, loop, time-box) | Separates hunting from browsing logs | Written hunt reports using the [templates]({{ site.baseurl }}/templates/); explain [frameworks]({{ site.baseurl }}/learn/hunting-process-and-frameworks/) in your own words |
| Windows telemetry (Security log, Sysmon, PowerShell, ETW) | Most intrusions touch Windows endpoints and AD | Reproduce a technique in a [lab]({{ site.baseurl }}/labs/) and show the exact events it generates; the [Windows event ID]({{ site.baseurl }}/cheatsheets/) and Sysmon cheat sheets |
| Query languages (KQL, SPL, SQL-ish) | You cannot hunt what you cannot ask | Public query repo; every [playbook]({{ site.baseurl }}/hunt/) on this site has KQL and SPL to adapt |
| Analytical techniques (stacking, baselining, first-seen, timing) | Finds unknowns, not just IOCs | A write-up applying [chapter 5]({{ site.baseurl }}/learn/hunting-techniques/) to a public dataset ([datasets]({{ site.baseurl }}/labs/datasets/)) |
| Adversary tradecraft (ATT&CK, kill chain, LOTL) | Hypotheses come from knowing what attackers do | Map a DFIR report to ATT&CK and to the data sources that would see each step ([chapter 6]({{ site.baseurl }}/learn/adversary-tradecraft/)) |
| Active Directory and identity | Credential and Kerberos abuse is in almost every ransomware case | Run the [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/), [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) and [LSASS]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) playbooks in a lab |
| Network analysis (Zeek, DNS, proxy) | C2 and exfiltration leave network traces | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) and [exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) playbooks on a PCAP dataset |
| Detection engineering (Sigma, testing, tuning) | Hunts must leave something behind | Merged Sigma PRs; a rule with documented false positives and a test ([research/sigma]({{ site.baseurl }}/research/sigma/)) |
| Cloud and identity platforms | Entra ID, AWS and SaaS are where the data went | [Cloud identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) playbook; a lab tenant |
| Communication | Findings that nobody acts on are wasted | A one-page report and a three-sentence executive summary for the same hunt |
| Scripting (Python/PowerShell) | Glue, parsing, statistics the SIEM cannot do | A notebook that stacks or baselines a dataset |

## 90-day self-study plan

Built from this site. Each block assumes roughly 8–10 hours a week.

| Days | Read | Do |
|---|---|---|
| 1–10 | Chapters [1]({{ site.baseurl }}/learn/what-is-threat-hunting/)–[3]({{ site.baseurl }}/learn/hypotheses-and-intelligence/) | Write three hypothesis cards from one public DFIR report |
| 11–25 | Chapter [4]({{ site.baseurl }}/learn/data-and-telemetry/); [lab guide]({{ site.baseurl }}/labs/) | Build the minimal AD lab; deploy Sysmon with a maintained config; forward logs to a free-tier SIEM |
| 26–40 | Chapter [5]({{ site.baseurl }}/learn/hunting-techniques/) | Run the [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) and [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) playbooks; stack process images and scheduled tasks across your lab hosts |
| 41–55 | Chapter [6]({{ site.baseurl }}/learn/adversary-tradecraft/) | [Emulate and detect]({{ site.baseurl }}/labs/emulate-and-detect/) exercises 1–5; write up what each test produced in the logs |
| 56–70 | Chapter [7]({{ site.baseurl }}/learn/detection-engineering/) | Convert two of your hunts into Sigma rules; test with Atomic Red Team; document false positives |
| 71–80 | Network and cloud playbooks | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) on a public PCAP; [cloud identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) in a trial tenant |
| 81–90 | Chapter [8]({{ site.baseurl }}/learn/building-a-hunt-program/) | Complete the [Argon Nexus CTF]({{ site.baseurl }}/ctf/argon-nexus/); write one public hunt report; answer the interview questions below out loud |

If you only have 30 days: days 1–10, then the lab, then two playbooks and one write-up.

## Portfolio ideas

Hiring managers can verify a portfolio in ten minutes; they cannot verify "experienced with SIEM".

- **Public hunt reports.** One page each, using the [hunt report template]({{ site.baseurl }}/templates/#hunt-report), against public datasets. Include negative results; they show discipline.
- **Sigma pull requests.** A merged rule in SigmaHQ (or a well-argued rejected one) demonstrates you understand field names, false positives and review.
- **Lab write-ups.** "I ran Atomic test T1053.005-2; here are the 4698, Sysmon 1 and Sysmon 11 events it generated, and here is the query that catches it with 0 hits on a clean baseline."
- **CTF solutions.** Defensive CTFs ([ours]({{ site.baseurl }}/ctf/), CyberDefenders, Sherlocks). Write the reasoning, not just the flags.
- **Query repository.** Versioned KQL/SPL with comments stating the hypothesis, data assumptions and known noise.
- **A talk or blog post** that teaches one technique end to end. Teaching exposes gaps faster than reading.

## Certifications

Vendor-neutral view. Certifications get you past HR filters and structure your study; they do not replace a portfolio.

| Certification | What it covers | Value for hunting roles |
|---|---|---|
| **GCIH** (SANS SEC504) | Attack techniques and incident handling | Strong foundation; widely requested. Expensive. |
| **GCFA** (SANS FOR508) | Advanced IR, memory and disk forensics, hunting across the enterprise | The closest SANS cert to day-to-day hunting; highly regarded |
| **GCTI** (SANS FOR578) | Threat intelligence analysis | Useful for intel-driven hunting and senior roles |
| **GCDA** (SANS SEC555) | SIEM tactical analytics | Directly relevant to query and baseline work |
| **CySA+** (CompTIA) | Analyst fundamentals | Entry-level filter; cheap; not deep |
| **BTL1 / BTL2** (Security Blue Team) | Hands-on blue-team practicals | Good practical signal at entry (BTL1) and mid (BTL2) level; well priced |
| **Splunk Core/Power User, Microsoft SC-200** | Platform skills | Worth it if the employer runs that platform; SC-200 covers Sentinel and Defender hunting |
| **Elastic Certified Analyst** | Elastic Security | Same logic: platform-specific |
| **OSCP** (OffSec) | Offensive practical | Optional. Teaches attacker thinking but costs months; a red-team lab and Atomic tests give most of the benefit for defenders |

Honest ranking for a hunting career on a budget: BTL1 → platform cert for your SIEM → GCFA (employer-funded if possible). Skip collecting certificates past that; publish work instead.

## 40 interview questions with model-answer notes

Answers are bullet notes, not scripts. Interviewers want to hear *how* you think and where you would check your own claims.

### Fundamentals

**1. Hunting vs detection vs incident response?**
- Detection: automated, alert-driven, known patterns, measured by precision/recall.
- Hunting: human-led, hypothesis-driven, looks for what detections miss, measured by outcomes (new detections, gaps closed, incidents).
- IR: scoped response to a confirmed incident; hunting hands off to IR and receives lessons learned back.

**2. What is a hunt hypothesis and what makes a good one?**
- Testable statement: "If an attacker is X, we would see Y in Z data."
- Scoped to data you have, time-boxed, with success and failure criteria defined up front.
- Bad: "look for bad PowerShell". Good: "encoded PowerShell launched by Office or by a service account on servers in the last 30 days".

**3. Explain the Pyramid of Pain.**
- Hashes, IPs, domains at the bottom: trivial for attackers to change.
- Network/host artefacts, tools, then TTPs at the top: costly to change.
- Hunting and detection should aim as high as the data allows; hashes are for sweeping, behaviours are for lasting detections.

**4. What is a hunting maturity model and where would you place a team that only sweeps for IOCs from reports?**
- HMM0–4 (Bianco). IOC sweeping with centralised data is HMM1.
- Moving up: written procedures (HMM2), original analytics (HMM3), automation of successful hunts (HMM4).

**5. How do you decide what to hunt next?**
- Backlog ranked by threat relevance (intel, recent incidents), business impact (crown jewels), data availability and detection gaps (ATT&CK coverage).
- Mix: some intel-driven, some baseline/anomaly, some gap-driven.

**6. What does a finished hunt look like when nothing malicious is found?**
- A documented negative result with scope, queries, data coverage and dates.
- Benign explanations recorded as allow-list candidates; gaps logged; often a detection anyway.

**7. IOC vs IOA?**
- IOC: static artefact (hash, IP). IOA: behaviour pattern (Office spawning a script host that connects out).
- IOAs survive tool changes; IOCs decay in hours to days.

**8. How does threat intelligence feed hunting?**
- Reports → ATT&CK mapping → hypotheses about *behaviour*, not just indicators.
- Prioritise by actors relevant to your sector; use intel to pick techniques, then hunt your own data.

### Windows internals and logs

**9. Walk through 4624 logon types.**
- 2 interactive (console), 3 network (SMB, WinRM, shares), 4 batch (scheduled task), 5 service, 7 unlock, 8 network cleartext (IIS basic), 9 new credentials (`runas /netonly`), 10 RemoteInteractive (RDP), 11 cached interactive.
- Hunt angles: type 3 from workstation to workstation; type 10 from unusual source; type 9 from non-admins.

**10. 4688 vs Sysmon event 1: what is the difference?**
- 4688 needs the audit policy and a separate GPO for command-line logging; gives parent PID, user, path.
- Sysmon 1 adds hashes, OriginalFileName, parent command line, ProcessGuid, signature info, and is filterable at source.
- Prefer Sysmon or EDR; keep 4688 as a fallback where you cannot deploy agents.

**11. How would you spot LSASS credential dumping?**
- Sysmon 10 (ProcessAccess) with TargetImage `lsass.exe`; look at GrantedAccess masks: `0x1010`, `0x1410`, `0x1FFFFF` are classic, but legitimate AV and some agents also touch LSASS.
- Combine with source image path, signature status and rarity; also 4663 on LSASS if SACL set, and EDR LSASS-read telemetry.
- Playbook: [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/).

**12. Kerberos events 4768, 4769, 4771: what are they and how do you hunt with them?**
- 4768 TGT requested (AS-REQ). 4769 service ticket requested (TGS-REQ). 4771 pre-authentication failed.
- Kerberoasting: 4769 with RC4 (encryption type 0x17) from a user account for many SPNs in a short window.
- AS-REP roasting: 4768 for accounts without pre-auth required, RC4 encryption.
- Password spraying over Kerberos: many 4771 (failure code 0x18) from one source.

**13. What is an access token and why do hunters care about SIDs?**
- Token carries user SID, group SIDs, privileges and integrity level; processes inherit tokens.
- SIDs are stable identifiers; usernames are not. Well-known SIDs (S-1-5-18 SYSTEM) and RID 500 (built-in admin) matter.
- Token theft/impersonation lets attackers act as another user without their password; look for SeDebugPrivilege use and unusual parent/child user mismatches.

**14. What generates 4698 and what else fires when a scheduled task is created?**
- 4698 (Security log, requires Object Access: Other Object Access Events auditing). Also Sysmon 1 for `schtasks.exe`, Sysmon 11 for the task XML under `C:\Windows\System32\Tasks`, registry writes under `TaskCache`, and TaskScheduler operational log 106.
- Remote creation via `schtasks /s` appears on the *target*.

**15. How do you tell a renamed binary from the real one?**
- Compare `OriginalFileName` (PE version info) with `Image`; hash against known-good; signature status.
- Example from the [defence evasion playbook]({{ site.baseurl }}/hunt/playbooks/defense-evasion/): `OriginalFileName == "rundll32.exe"` and `Image` not ending in `\rundll32.exe`.

**16. Which PowerShell logs would you turn on and why?**
- Module logging (4103), script block logging (4104), transcription. 4104 shows de-obfuscated code as executed.
- Hunt for `-enc`, `FromBase64String`, `IEX`, `DownloadString`, AMSI bypass strings, and long command lines.

**17. What is WEF/WEC and why does it matter for hunting?**
- Windows Event Forwarding to a collector: agentless, filterable by subscription, cheap way to centralise Security and Sysmon logs.
- Hunting needs central data; a well-designed subscription set is the difference between HMM0 and HMM1.

### Network

**18. How do you find C2 beaconing without signatures?**
- Per (source, destination) pair: connection count, interval mean and standard deviation, bytes in/out ratio, duration of relationship.
- Low coefficient of variation in intervals, small consistent payloads, long-lived relationship with a rare destination.
- Playbook: [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/).

**19. What does JA3/JA3S tell you and what does it not?**
- Fingerprint of the TLS client/server hello; groups traffic by client stack.
- Does not identify malware alone: common libraries collide. Use as a pivot and rarity feature.

**20. How would you hunt DNS tunnelling or DGA?**
- Query length, label entropy, subdomain count per domain, NXDOMAIN rate per host, TXT record volume, rare TLDs.
- Baseline per host class; servers rarely need thousands of unique subdomains.

**21. A server makes its first-ever outbound connection to a public IP on 443. Interesting or not?**
- Depends on server role and destination. Enrich: ASN, domain, certificate, who else talks to it, process that made it (Sysmon 3 / EDR), timing relative to logons.
- Servers have tight baselines, so "first-seen" is a strong signal there and weak on workstations.

**22. How do you detect data exfiltration?**
- Volume outliers per host vs its own and peer history; rare destinations; cloud storage domains; archive creation (7z/rar/rclone) before the transfer; off-hours.
- Playbook: [data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/).

### Query and data

**23. Explain stacking (frequency analysis) and when it fails.**
- Count a field across a homogeneous population, sort ascending, examine the rare tail.
- Fails when the population is heterogeneous (developers' laptops), when the attacker uses the most common tool, or when the field is high-cardinality by nature (command lines with GUIDs). Normalise first.

**24. How do you build a baseline and what are the pitfalls?**
- Choose entity and window (30 days is a common starting point), compute distinct values or statistics, compare the latest window against it.
- Pitfalls: baselining a compromised period, seasonality (month-end), too-short history, drift after a software rollout. Rebuild on a schedule and version it.

**25. Explain a query you have written to someone non-technical.**
- Structure: what question it answers, what data it reads, what it filters out and why, what the output row means, how often it is wrong.
- Interviewers are listening for whether you know your false positives.

**26. False-positive rate vs precision: why does the distinction matter?**
- FP rate = FP / (FP + TN): depends on the size of benign traffic; looks tiny for anything.
- Precision = TP / (TP + FP): what the analyst experiences. A 0.01% FP rate on 10 million events is 1,000 false alerts.
- Report precision and alert volume per day when proposing a detection.

**27. What is first-seen analysis?**
- Flag entity-attribute pairs not seen in the history window: first time user X logged on to host Y, first time host Z ran binary W.
- Cheap and effective on servers and service accounts; noisy on new joiners and new builds, so pair with age of account/host.

**28. How would you handle a query that takes an hour to run over 30 days?**
- Narrow early (time, event type) before parsing; use summary tables or scheduled aggregations; sample to develop then run full once; pre-filter on indexed fields; move statistics to a notebook if the SIEM is the bottleneck.

**29. What is the difference between a hunt query and a detection rule?**
- Hunt query: broad, exploratory, run once, output read by a human.
- Detection: narrow, scheduled, must have known precision, documented false positives, owner, tests, and a response procedure. [Chapter 7]({{ site.baseurl }}/learn/detection-engineering/) lists what changes.

### Scenarios: "you see X — what next?"

**30. You see `svchost.exe` running from `C:\Users\Public`.**
- Not the real one; svchost lives in System32. Capture hash, parent, command line, user, network connections, signer.
- Pivot: other hosts with the same hash or path; how it got there (Sysmon 11 file create, browser or Office parent); escalate to IR with containment recommendation.

**31. 4769 with RC4 from one workstation requesting tickets for 40 SPNs in two minutes.**
- Textbook Kerberoasting. Confirm the account and host, check whether the SPN accounts are weak (old passwords, no gMSA), look for subsequent logons using those accounts.
- Escalate; rotate affected service account passwords; move to AES; consider honeytoken SPNs.

**32. A domain controller shows 4662 with replication GUIDs from a non-DC account.**
- DCSync. Check for `DS-Replication-Get-Changes` and `-All` GUIDs (1131f6aa / 1131f6ad), source IP, whether the account is a known sync tool (Entra Connect) or legitimate DC.
- If unexplained: critical incident, assume krbtgt compromise, plan a double krbtgt reset. Playbook: [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/).

**33. An admin says the alert for `certutil -urlcache -f http://...` is "just how we install things".**
- Verify: who ran it, from which script or deployment tool, what URL, is that pattern repeatable? If true, document it as an allow-list with narrow conditions (source host, URL prefix), not a blanket exclusion.
- If the admin cannot show the deployment job, treat as unverified.

**34. Your stacking hunt returns 300 rare scheduled tasks across 1,200 hosts. How do you triage?**
- Enrich with path (user-writable?), signature, creator process, account, creation time, hosts affected; rank by combinations (unsigned + ProgramData + created by non-installer + one host).
- Explain the top 20; document the categories; the rest become baseline.

**35. EDR shows `w3wp.exe` spawning `cmd.exe` on a web server at 03:12.**
- Likely web shell. Capture the command line and child tree, recent file writes to web roots (`.aspx`, `.php`), web logs for the POST that triggered it, outbound connections.
- Isolate if confirmed; preserve the shell file for IR. Playbook: [web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/).

**36. A user signs in from two countries 20 minutes apart in Entra ID.**
- "Impossible travel" is often VPN or mobile carrier egress. Check device, app, user agent, whether MFA satisfied and how, token refresh vs new sign-in, consent grants or mailbox rules shortly after.
- Treat MFA fatigue patterns (many pushes then approval) and new inbox rules as the escalation signals. Playbook: [cloud identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/).

**37. You find something that looks like an active intrusion halfway through a hunt. What do you do?**
- Stop hunting, preserve evidence, note timestamps and queries, escalate to IR following the hand-off procedure. Do not touch the host or tip off the attacker (no pings, no password resets without IR).
- Afterwards: why did detections miss it, and which hunt step found it.

### Behavioural

**38. Tell me about a hunt that found nothing.**
- Good answer covers: hypothesis, what data was and was not available, what was ruled out and how, what you left behind (detection, gap ticket, allow-list), and what you would change.

**39. Describe a time you were wrong about a finding.**
- Interviewers want to hear how you verified, how quickly you corrected it, and how you communicated the correction. Blaming the data is a red flag.

**40. How do you keep up and how do you decide what to ignore?**
- A small number of high-signal sources (DFIR reports, vendor threat reports, Sigma merges), each converted into backlog items or discarded. Volume is not the goal; the backlog is.

## How to run a hunt take-home exercise (for hiring managers)

A take-home shows how a candidate thinks far better than live quizzing. Keep it fair.

| Element | Recommendation |
|---|---|
| **Time** | State 3–4 hours; design for 2. Candidates have jobs. |
| **Data** | Public, synthetic or anonymised: an EVTX bundle, a Zeek log set, or a CSV export of process events for 50 hosts over 7 days. Our [datasets page]({{ site.baseurl }}/labs/datasets/) lists sources. Include some noise and at least one benign rarity. |
| **Task** | "Here is a hypothesis card. Hunt it. Deliver a one-page report using this template." Supply the [report template]({{ site.baseurl }}/templates/#hunt-report). |
| **What you are scoring** | Method (did they scope and time-box?), correctness (did they find the planted activity and *not* over-claim the benign rarity?), evidence (do claims cite events?), outputs (did they propose a detection with false positives listed and a gap?), and communication (could a manager read the summary?). |
| **Rubric** | Agree it before sending. Weight method and evidence over "found the flag". A candidate who misses the planted item but writes a rigorous negative report with a sound detection may be the stronger hire. |
| **Debrief** | 30 minutes walking through their report. Ask what they would do with another day and what data they wished they had. |
| **Avoid** | Vendor-specific query syntax requirements (accept pseudo-queries), trick artefacts, unpaid multi-day work, and exercises that require offensive tooling. |

Compare notes across interviewers using the same rubric, and tell every candidate the planted answer afterwards. They put hours in; closing the loop is the least you owe them.

## See also

- [8. Building a Hunt Program]({{ site.baseurl }}/learn/building-a-hunt-program/)
- [Glossary]({{ site.baseurl }}/learn/glossary/)
- [Tools, Books, Courses & Communities]({{ site.baseurl }}/resources/)
