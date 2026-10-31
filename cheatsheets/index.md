---
title: "Hunter's Cheat Sheets (PDF)"
permalink: /cheatsheets/
excerpt: "One-page-style references for the logs, query languages and artefacts you reach for mid-hunt. Download, print or pin them."
toc: false
---

Eight compact **A4 PDFs** (2-3 pages each) for use at your desk or in the SOC. Every page carries the Hunt-Sage watermark and a footer with the repository link, and links inside the PDFs stay clickable and point back to the site.

| Cheat sheet | Use it for | Download |
|---|---|---|
| **Windows Security event IDs** | Logon, Kerberos, process, share, service, task and policy events; logon types; failure and encryption codes | [📄 PDF]({{ site.baseurl }}/cheatsheets/windows-event-ids.pdf) |
| **Sysmon event IDs** | What each Sysmon event tells you and which technique it exposes; key fields | [📄 PDF]({{ site.baseurl }}/cheatsheets/sysmon.pdf) |
| **Linux logs & auditd** | Where evidence lives; starter auditd rules; triage one-liners | [📄 PDF]({{ site.baseurl }}/cheatsheets/linux-logs-auditd.pdf) |
| **KQL for hunters** | Operators and hunting patterns for Sentinel and Defender Advanced Hunting | [📄 PDF]({{ site.baseurl }}/cheatsheets/kql.pdf) |
| **Splunk SPL for hunters** | `stats`, `tstats`, `streamstats`, regex and rarity patterns | [📄 PDF]({{ site.baseurl }}/cheatsheets/splunk-spl.pdf) |
| **Network & DNS (Zeek)** | Zeek logs and fields, one-liners, ports of interest, DNS anomaly checklist | [📄 PDF]({{ site.baseurl }}/cheatsheets/network-zeek.pdf) |
| **LOLBins quick reference** | Abused signed binaries and the telltale arguments | [📄 PDF]({{ site.baseurl }}/cheatsheets/lolbins.pdf) |
| **Active Directory attacks** | Attack → artefact → event table for AD and Kerberos | [📄 PDF]({{ site.baseurl }}/cheatsheets/active-directory-attacks.pdf) |

> The sheets are a starting point: field names and event availability depend on your audit policy, agent and schema. See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) for what must be enabled.

Other quick references: [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) · [Glossary]({{ site.baseurl }}/learn/glossary/) · [Sigma rules]({{ site.baseurl }}/research/sigma/)

*Licence: © 2025 iamjammie. Educational use permitted with attribution (keep the watermark and footer intact when sharing).*
