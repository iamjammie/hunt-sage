---
title: "Splunk SPL for Hunters"
excerpt: "Search patterns for stacking, rarity, time analysis and joins in Splunk."
---

## Anatomy

```spl
index=wineventlog EventCode=4624 Logon_Type=3 earliest=-24h
| search NOT Account_Name="*$"
| stats count dc(ComputerName) as hosts values(Source_Network_Address) as src by Account_Name
| where hosts>5
| sort - hosts
```

Order of operations: **filter in the base search** (index, sourcetype, keywords) → `where`/`search` → transform with `stats`. Field names depend on your Windows add-on and CIM mapping, so always check with `| table *` on a sample first.

## Core commands

| Command | Use |
|---|---|
| `stats` / `eventstats` / `streamstats` | Aggregate / aggregate keeping events / running window computations |
| `tstats` | Very fast counts over indexed fields / data models |
| `rex field=_raw "(?<name>regex)"` | Extract fields |
| `regex field=pattern` | Filter by regex |
| `eval` | Compute: `if`, `case`, `match`, `like`, `len`, `lower`, `split`, `mvindex` |
| `rare` / `top` | Frequency (rare = long-tail stacking) |
| `bin _time span=1h` | Bucket time |
| `timechart` | Time series |
| `transaction` | Group related events (costly; prefer `stats`) |
| `lookup` / `inputlookup` | Enrich / allow-lists and watchlists |
| `join` | Subsearch join (limited; prefer `stats` with `by`) |
| `append` / `appendcols` | Combine searches |
| `fillnull`, `dedup`, `sort`, `head`, `table`, `fields` | Housekeeping |

## Hunting patterns

**Stack / long-tail**

```spl
index=sysmon EventCode=1
| stats dc(host) as hosts count by Image
| where hosts<=2
| sort hosts
```

```spl
index=sysmon EventCode=1 | rare limit=30 Image
```

**First-seen / new behaviour**

```spl
index=proxy earliest=-30d
| stats earliest(_time) as first_seen by src_ip dest_domain
| where first_seen > relative_time(now(), "-1d")
```

**Beacon timing**

```spl
index=proxy src_ip=* dest_domain=*
| sort 0 src_ip dest_domain _time
| streamstats current=f last(_time) as prev by src_ip dest_domain
| eval gap=_time-prev
| stats count avg(gap) as avg stdev(gap) as sd by src_ip dest_domain
| eval cov=sd/avg
| where count>30 AND avg>10 AND cov<0.35
```

**Outliers (z-score) per entity**

```spl
index=firewall action=allowed | bin _time span=1h
| stats sum(bytes_out) as b by src_ip _time
| eventstats avg(b) as mu stdev(b) as sd by src_ip
| eval z=(b-mu)/sd | where z>3
```

**Sequence (A then B)**

```spl
index=sysmon (EventCode=1 Image="*\\winword.exe") OR (EventCode=1 ParentImage="*\\winword.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe"))
| transaction host maxspan=5m startswith=(Image="*\\winword.exe") endswith=(ParentImage="*\\winword.exe")
```

**Fast counts with tstats**

```spl
| tstats count where index=wineventlog earliest=-24h by host, sourcetype | sort count
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="rundll32.exe" by Processes.dest Processes.process
```

**Regex extraction & decode**

```spl
| rex field=CommandLine "(?i)-enc(odedcommand)?\s+(?<b64>[A-Za-z0-9+/=]{20,})"
| eval decoded=base64decode(b64)    /* use the Base64 app/CyberChef for UTF-16LE */
```

**Allow-list via lookup**

```spl
index=sysmon EventCode=1 | lookup approved_parents parent_image AS ParentImage OUTPUT approved
| where isnull(approved)
```

**Entropy (URL Toolbox)**

```spl
| `ut_parse_extended(query, ut)` | `ut_shannon(ut_domain)` | where ut_shannon>3.8
```

## Performance tips

- Always specify `index=` and a **time range**; use `sourcetype` and indexed fields.
- `tstats` and data-model acceleration for fleet-wide counts.
- Avoid leading wildcards (`*foo`) and `transaction` over long spans.
- Use `| fields` early to drop unneeded fields on big searches.
- Use summary indexing for baselines you reuse.

## Common Windows field names (Splunk Add-on for Microsoft Windows)

`EventCode`, `Logon_Type`, `Account_Name`, `Source_Network_Address`, `Authentication_Package`, `Key_Length`, `Workstation_Name`, `Service_Name`, `Ticket_Encryption_Type`, `Task_Name`, `New_Process_Name`, `Process_Command_Line`. Sysmon app: `Image`, `ParentImage`, `CommandLine`, `TargetImage`, `GrantedAccess`, `DestinationIp`.
