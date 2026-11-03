---
title: "Hunter's Cheat Sheets"
permalink: /cheatsheets/
excerpt: "Compact references for the logs, query languages and artefacts you reach for mid-hunt. Read them online with a live filter, or download the printable PDFs."
toc: false
---

Eight compact references, each available two ways: as a **web page** with a live row filter (type an event id or keyword and everything else disappears) and as a watermarked **A4 PDF** (2-3 pages) for your desk or the SOC wall. Links inside the PDFs stay clickable and point back to the site.

| Cheat sheet | Use it for | Read | Download |
|---|---|---|---|
| **Windows Security event IDs** | Logon, Kerberos, process, share, service, task and policy events; logon types; failure and encryption codes | [🔎 Online]({{ site.baseurl }}/cheatsheets/windows-event-ids/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/windows-event-ids.pdf) |
| **Sysmon event IDs** | What each Sysmon event tells you and which technique it exposes; key fields | [🔎 Online]({{ site.baseurl }}/cheatsheets/sysmon/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/sysmon.pdf) |
| **Linux logs & auditd** | Where evidence lives; starter auditd rules; triage one-liners | [🔎 Online]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/linux-logs-auditd.pdf) |
| **KQL for hunters** | Operators and hunting patterns for Sentinel and Defender Advanced Hunting | [🔎 Online]({{ site.baseurl }}/cheatsheets/kql/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/kql.pdf) |
| **Splunk SPL for hunters** | `stats`, `tstats`, `streamstats`, regex and rarity patterns | [🔎 Online]({{ site.baseurl }}/cheatsheets/splunk-spl/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/splunk-spl.pdf) |
| **Network & DNS (Zeek)** | Zeek logs and fields, one-liners, ports of interest, DNS anomaly checklist | [🔎 Online]({{ site.baseurl }}/cheatsheets/network-zeek/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/network-zeek.pdf) |
| **LOLBins quick reference** | Abused signed binaries and the telltale arguments | [🔎 Online]({{ site.baseurl }}/cheatsheets/lolbins/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/lolbins.pdf) |
| **Active Directory attacks** | Attack → artefact → event table for AD and Kerberos | [🔎 Online]({{ site.baseurl }}/cheatsheets/active-directory-attacks/) | [📄 PDF]({{ site.baseurl }}/cheatsheets/active-directory-attacks.pdf) |

> The sheets are a starting point: field names and event availability depend on your audit policy, agent and schema. See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) for what must be enabled.

Other quick references: [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) · [Glossary]({{ site.baseurl }}/learn/glossary/) · [Sigma rules]({{ site.baseurl }}/research/sigma/)

*Licence: © 2025 iamjammie. Educational use permitted with attribution (keep the watermark and footer intact when sharing).*
