---
title: "5. Hunting Techniques"
permalink: /learn/hunting-techniques/
excerpt: "Searching, grouping, stacking, baselining, outlier and timing analysis, pivoting, and where machine learning helps."
---

Hunting techniques are the reusable analytical moves you apply to data, regardless of the specific attack. Learn these and you can build a hunt for a technique you have never seen.

## 1. Searching (known-pattern matching)

Query for specific artefacts: command-line strings, file names, registry paths, event IDs, IOCs.

- **Strength:** fast, precise, easy to explain.
- **Weakness:** only finds what you already know to look for; attackers rename and obfuscate.
- **Tip:** search on *what cannot easily change*: e.g. PE `OriginalFileName`, parent-child process relationships, API access masks, rather than file names.

```kql
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "certutil.exe" and FileName !~ "certutil.exe"   // renamed copy
```

## 2. Grouping / clustering

Take a set of items that share an attribute and look for the set as a whole to be suspicious: *a user who runs `whoami`, `net group "domain admins"`, `nltest`, and `ipconfig /all` within five minutes* is a discovery cluster even if each command is benign alone.

```kql
DeviceProcessEvents
| where FileName in~ ("whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe","arp.exe","tasklist.exe")
| summarize Cmds = make_set(FileName), Count = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 5m)
| where Count >= 4
```

## 3. Stack counting (frequency analysis / "long-tail")

Count occurrences of an attribute across your fleet and **sort ascending**. Most legitimate software is common; malware, tools and one-off scripts live in the tail.

Good stacking fields:

| Field | What the tail reveals |
|---|---|
| Process image path + hash | Unusual binaries, renamed tools |
| Parent → child pairs | `winword.exe → cmd.exe`, `w3wp.exe → powershell.exe` |
| Scheduled task / service names + paths | Rogue persistence |
| Autorun entries | Anything unique to one host |
| User-Agent strings | Scripted clients, C2 frameworks |
| Destination domains / ASNs | Rare destinations from servers |
| Logon source → destination pairs | Unexpected admin paths |

```spl
index=sysmon EventCode=1
| stats dc(host) as hosts, count by Image
| where hosts < 3
| sort hosts
```

**Rules of thumb**

- Stack *per scope that should be homogeneous* (servers of one role, one OU, one image).
- Combine with attributes such as signature status and path: unsigned + user-writable path + rare = priority.
- Rare ≠ bad, so always ask "why does this exist?". Document benign explanations; they become the allow-list.

## 4. Baselining and anomaly detection

Establish "normal" for an entity (host, user, service account, subnet) over a window, then flag deviations.

- **Peer-group baselines** are often better than per-entity: "this server does something no other file server does".
- **Time-of-day / day-of-week** baselines catch off-hours activity.
- **New-behaviour (first-seen) detection**: first time this account logged on to this host; first time this host contacted this domain.

```kql
// First-seen outbound domains per host in the last day vs prior 30 days
let history = DnsEvents | where TimeGenerated between (ago(31d) .. ago(1d)) | distinct Computer, Name;
DnsEvents
| where TimeGenerated > ago(1d)
| distinct Computer, Name
| join kind=leftanti history on Computer, Name
```

Pitfalls: baselining a *compromised* window (you bake the attacker in), too-short windows, and seasonality (month-end jobs).

## 5. Outlier and statistical analysis

| Method | Use | Example |
|---|---|---|
| **Z-score / MAD** | Spike detection on counts | Failed logons per account per hour |
| **Percentiles** | Define "unusually large" | Outbound bytes > P99 for that host class |
| **Entropy** | Randomness in strings | DGA domains, base64/encrypted DNS labels, random service names |
| **String length** | Tunneling, encoded commands | DNS query length, command-line length |
| **Beacon scoring** | Regular intervals | Low standard deviation / coefficient of variation of connection gaps |
| **Rarity (IDF)** | Weighted rare events | Rare parent/child pair |

**Beacon timing in one query:**

```kql
// Connection regularity per (host, destination): low coefficient of variation = metronomic
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| extend Prev = prev(Timestamp), PrevHost = prev(DeviceName), PrevIP = prev(RemoteIP)
| where PrevHost == DeviceName and PrevIP == RemoteIP
| extend DeltaSec = datetime_diff('second', Timestamp, Prev)
| summarize N = count(), Avg = avg(DeltaSec), Std = stdev(DeltaSec) by DeviceName, RemoteIP
| where N > 30 and Avg > 5
| extend CoV = Std / Avg
| where CoV < 0.3          // jitter-tolerant
| order by CoV asc
```

Full treatment in the [C2 beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/).

## 6. Sequence and correlation (chain) analysis

Individually benign events become suspicious in order and proximity:

> Office app spawns script host → script host writes executable to user-writable path → that file makes a first-seen outbound connection → creates a run key.

Hunt the *chain*, not the node. Techniques: join on host + time window, process-tree reconstruction (ProcessGuid / process IDs), session IDs (LogonId), and "A followed by B within N minutes by same entity" patterns.

## 7. Pivoting

After any lead, expand along relationships:

```text
              ┌─────────── account ───────────┐
 host ──── process tree ──── network dest ──── other hosts
              └─────────── file hash ─────────┘
```

Keep a pivot table in your notes: *indicator → where else seen → first seen → last seen → verdict*. Pivoting on infrastructure (IP/JA3/JARM/cert) and on malware attributes (imphash, signing cert, pipe names, mutexes) extends beyond what the first alert showed.

## 8. Graph analysis

Model entities as nodes (user, host, process, IP) and events as edges (logon, spawn, connect). Useful for:

- **Lateral movement paths** (BloodHound: attack paths in AD; also useful defensively to find shortest paths to Domain Admin)
- **Account-to-host fan-out** (one account touching hundreds of hosts)
- **Campaign linking** (many hosts → one rare domain)

## 9. Machine learning (use deliberately)

ML is good at ranking leads in high-dimensional data and bad at explaining why. Reasonable uses:

| Use | Technique |
|---|---|
| DGA / random-looking domain scoring | Character n-gram model, entropy features |
| Rare behaviour scoring | Isolation Forest, one-class SVM on aggregated features |
| User/entity behaviour analytics (UEBA) | Per-entity statistical profiles |
| Clustering command lines | TF-IDF + clustering to find "families" of similar commands |

Guidelines: start with the simple statistics above; ML output is a *lead generator* needing human triage; version your models and features; measure analyst time per useful lead.

## 10. Hunting with tools you already have

| Tool | Hunting use |
|---|---|
| SIEM (Splunk/Sentinel/Elastic) | Cross-source correlation, long retention |
| EDR query consoles (Defender Advanced Hunting, CrowdStrike Event Search, etc.) | Process/network/file/registry telemetry at scale |
| Velociraptor / osquery | Live endpoint queries and artefact collection |
| Zeek / Suricata | Network metadata and signatures |
| Jupyter + pandas | Anything the SIEM cannot do (statistics, joins, plotting) |
| Chainsaw / Hayabusa | Fast Sigma-based triage of Windows event logs (EVTX) |

## Technique selection cheat sheet

| You have... | Use |
|---|---|
| A specific indicator or command pattern | Searching |
| A technique with a set of noisy, individually benign steps | Grouping / chain analysis |
| Lots of homogeneous hosts | Stack counting |
| A long retention window and a stable environment | Baselining / first-seen |
| Periodic or high-volume network behaviour | Statistical timing / volume analysis |
| A confirmed bad host/IOC | Pivoting and graph |

## Next

→ [6. Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/)
