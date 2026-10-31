---
title: "Hunter's Cheat Sheets"
permalink: /cheatsheets/
excerpt: "One-page references for the logs, query languages and artefacts you reach for mid-hunt."
toc: false
---

Fast lookups. Print them, pin them, or keep them in a second tab.

| Sheet | Use it for |
|---|---|
| [Windows Security event IDs]({{ site.baseurl }}/cheatsheets/windows-event-ids/) | Logon, Kerberos, process, share, service, task and policy events; logon types; status codes |
| [Sysmon event IDs]({{ site.baseurl }}/cheatsheets/sysmon/) | What each Sysmon event tells you and which technique it exposes |
| [Linux logs & auditd]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/) | Where evidence lives; auditd rules; triage one-liners |
| [KQL for hunters]({{ site.baseurl }}/cheatsheets/kql/) | Operators and patterns for Sentinel and Defender Advanced Hunting |
| [Splunk SPL for hunters]({{ site.baseurl }}/cheatsheets/splunk-spl/) | `stats`, `tstats`, `streamstats`, `eventstats`, regex and rarity patterns |
| [Network & DNS (Zeek)]({{ site.baseurl }}/cheatsheets/network-zeek/) | Zeek logs, fields and one-liners; ports of interest; DNS anomalies |
| [LOLBins quick reference]({{ site.baseurl }}/cheatsheets/lolbins/) | Which signed binaries are abused for what, and the telltale arguments |
| [Active Directory attacks]({{ site.baseurl }}/cheatsheets/active-directory-attacks/) | Attack → artefact → event table for AD and Kerberos |

Other quick references: [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) · [Glossary]({{ site.baseurl }}/learn/glossary/) · [Sigma rules]({{ site.baseurl }}/research/sigma/)
