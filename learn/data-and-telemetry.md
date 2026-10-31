---
title: "4. Data & Telemetry"
permalink: /learn/data-and-telemetry/
excerpt: "You can only hunt what you can see. Map techniques to data sources, assess quality and close blind spots."
---

Data is the single biggest determinant of hunting success. Before hunting any technique, answer: **which log would show this, do we collect it, and can we trust it?**

## Core data source categories

| Category | Typical sources | Best for |
|---|---|---|
| **Endpoint process/telemetry** | EDR, Sysmon, Windows 4688, Linux auditd/eBPF | Execution, persistence, credential access, discovery |
| **Authentication / identity** | Windows 4624/4625/4768/4769/4776, Entra ID sign-in logs, Okta, VPN | Lateral movement, valid accounts, Kerberos attacks |
| **Directory services** | AD change auditing (5136, 4728, 4662), Entra audit logs | Privilege escalation, persistence, DCSync |
| **Network flow & metadata** | NetFlow/IPFIX, Zeek, firewall logs, cloud flow logs | C2, lateral movement, exfiltration |
| **DNS** | Resolver logs, Zeek `dns.log`, Sysmon 22, passive DNS | C2, tunneling, DGA, phishing |
| **Web / proxy** | Proxy, WAF, web server access logs | Initial access, C2, exfil, web shells |
| **Email** | Gateway and mailbox audit logs | Phishing, BEC, mail-rule persistence |
| **Cloud control plane** | AWS CloudTrail, Azure Activity, GCP Audit, M365 Unified Audit | Cloud persistence, privilege escalation, data access |
| **Cloud workload/SaaS** | Container runtime, Kubernetes audit, SaaS audit logs | Container escape, token abuse |
| **File / object** | File-integrity monitoring, SMB audit, object-store access logs | Staging, exfil, ransomware |
| **Vulnerability / asset inventory** | CMDB, scanners | Context: "should this host exist?" |

## The "minimum viable hunting dataset"

If you can only collect a little, collect this first:

1. **Process creation with full command line** (Sysmon 1 / EDR / 4688+command line)
2. **Authentication events** from DCs and servers (4624/4625/4768/4769/4776)
3. **DNS queries** with the querying host
4. **Outbound network connections** with process attribution (Sysmon 3 / EDR) or firewall/proxy logs
5. **PowerShell Script Block Logging** (4104)
6. **Persistence-relevant changes**: services (7045/4697), scheduled tasks (4698), registry run keys (Sysmon 12/13), WMI (Sysmon 19-21)
7. **Cloud control-plane audit logs** and identity provider sign-ins

See [Windows event IDs]({{ site.baseurl }}/cheatsheets/windows-event-ids/), [Sysmon]({{ site.baseurl }}/cheatsheets/sysmon/) and [Linux logs]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/).

## Mapping technique → telemetry

This is the core data-engineering skill for hunters. For each technique ask: *what must the attacker do on the system, and what does the OS/service record when they do it?*

| Technique | Required attacker action | Observable | Log source |
|---|---|---|---|
| LSASS dumping (T1003.001) | Open LSASS with read-memory access | Process access to `lsass.exe` with `GrantedAccess` like `0x1010`/`0x1FFFFF` | Sysmon 10, EDR |
| Kerberoasting (T1558.003) | Request service tickets for SPN accounts | 4769 with RC4 (`0x17`) for user-owned SPNs, bursts per source | DC Security |
| Scheduled task (T1053.005) | Register task | 4698; `schtasks.exe /create`; task XML in `System32\Tasks` | Security, Sysmon 1/11 |
| DNS C2 (T1071.004) | Many queries with high-entropy labels | High query rate/length to one domain | DNS logs, Zeek |
| Cloud role abuse (T1098.003) | Assign privileged role | `Add member to role` / `AttachRolePolicy` | Entra audit, CloudTrail |

The ATT&CK "Data Sources" and "Detection" sections for each technique, and the [Sigma `logsource`](https://sigmahq.io/docs/basics/log-sources.html) taxonomy, are the starting points.

## Data quality checklist

Before trusting a negative result, verify:

- [ ] **Coverage**: what % of in-scope hosts send this log? (Count distinct hosts per day.)
- [ ] **Completeness**: are there gaps (agent crashed, license limits, ingestion errors)? Plot events/hour.
- [ ] **Timeliness**: ingestion lag; does `_time` reflect event time or index time?
- [ ] **Time sync**: NTP drift ruins timelines. Normalise to UTC.
- [ ] **Parsing**: are fields extracted (CommandLine, ParentImage, LogonType)? Sample 20 raw events.
- [ ] **Retention**: can you look back 30/90/180 days? Many intrusions are older than your hot storage.
- [ ] **Filtering**: has someone dropped "noisy" event IDs upstream? Ask.
- [ ] **Audit policy**: advanced audit policy and GPOs actually enabled (see below).

Quick coverage query examples:

```kql
// KQL: which hosts sent process creation events in the last day?
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4688
| summarize Events = count() by Computer
| order by Events asc   // low or absent = coverage gap
```

```spl
| tstats count where index=sysmon earliest=-24h by host
| sort count
```

## Windows logging that must be enabled (it is not by default)

| Setting | Why | Where |
|---|---|---|
| **Audit Process Creation** + *Include command line in process creation events* | 4688 with command line | Advanced Audit Policy › Detailed Tracking; Admin Templates › System › Audit Process Creation |
| **PowerShell Script Block Logging** (4104) and Module Logging | See deobfuscated script content | Admin Templates › Windows Components › Windows PowerShell |
| **Audit Directory Service Changes / Access** | 5136, 4662 | Advanced Audit Policy › DS Access |
| **Audit Kerberos Service Ticket Operations** / **Authentication Service** | 4769 / 4768 | Account Logon |
| **Audit Logon / Special Logon** | 4624/4625/4672 | Logon/Logoff |
| **Audit Other Object Access Events** | 4698 scheduled tasks | Object Access |
| **Sysmon** with a maintained config | Rich endpoint telemetry | See [lab guide]({{ site.baseurl }}/labs/) |
| **Larger event log sizes** | Security log default (20 MB) rolls in hours on a DC | Event Log policy |

## Normalisation and schemas

Hunts are far more portable when data is mapped to a common model:

- **Sigma** abstracts rules over log sources and field names.
- **OCSF**, **ECS** (Elastic Common Schema), **ASIM** (Microsoft Sentinel), **CIM** (Splunk): choose one and map to it.

Write your hunts against the normalised fields where you can, and keep a field cheat sheet for the raw ones.

## Retention and cost strategy

You cannot keep everything hot. Tier it:

| Tier | Data | Retention (typical) |
|---|---|---|
| Hot, indexed | Auth, EDR process/network, DNS, cloud audit | 30-90 days |
| Warm, searchable | Same + proxy/firewall | 6-12 months |
| Cold, archive | Raw logs for IR/compliance | 1-7 years |

Summarised "metadata" (e.g. daily per-host-per-domain DNS counts) can extend useful hunt windows cheaply for baselining.

## Next

→ [5. Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/)
