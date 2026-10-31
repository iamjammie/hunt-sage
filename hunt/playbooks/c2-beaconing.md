---
title: "Playbook: C2 Beaconing & DNS Tunneling"
permalink: /hunt/playbooks/c2-beaconing/
excerpt: "Find regular check-ins, rare destinations, odd TLS/HTTP fingerprints and DNS abuse using timing and frequency analysis."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1071.001 (Web), T1071.004 (DNS), T1573 (Encrypted Channel), T1568 (Dynamic Resolution/DGA), T1572 (Protocol Tunneling), T1090 (Proxy), T1102 (Web Service) |
| **Tactic** | Command & Control |
| **Data** | Proxy / firewall / NetFlow; DNS logs; Zeek `conn`, `dns`, `http`, `ssl`; EDR network events |
| **Time-box** | 1-2 days |
| **Difficulty** | ★★★ |

## Hypothesis

> *If a host is compromised with a C2 implant, it will connect to attacker infrastructure at regular intervals (with jitter), with small consistent request/response sizes, to destinations that are rare in our environment, often with distinctive TLS or HTTP client characteristics.*

Background and a worked example: [Hunting C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/).

## Hunt steps

### 1. Frequency and regularity (time-delta analysis)

```kql
// Per source/destination, compute inter-connection gaps; low variance == metronome
let lookback = 1d;
DeviceNetworkEvents
| where Timestamp > ago(lookback) and RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| extend PrevT = prev(Timestamp), PrevDev = prev(DeviceName), PrevIP = prev(RemoteIP)
| where PrevDev == DeviceName and PrevIP == RemoteIP
| extend Gap = datetime_diff('second', Timestamp, PrevT)
| summarize Conns = count(), AvgGap = avg(Gap), StdGap = stdev(Gap), Procs = make_set(InitiatingProcessFileName, 5), Url = any(RemoteUrl)
          by DeviceName, RemoteIP, RemotePort
| where Conns >= 30 and AvgGap between (10 .. 3600)
| extend CoV = StdGap / AvgGap
| where CoV < 0.35
| order by CoV asc
```

```spl
index=firewall action=allowed direction=outbound
| sort 0 src_ip dest_ip _time
| streamstats current=f last(_time) as prev by src_ip dest_ip
| eval gap=_time-prev
| stats count avg(gap) as avg_gap stdev(gap) as sd by src_ip dest_ip dest_port
| eval cov=sd/avg_gap
| where count>=30 AND avg_gap>=10 AND cov<0.35
| sort cov
```

Jitter (±10-50%) raises CoV; widen the threshold and rank by `count` too. Exclude known periodic traffic (NTP, update checks, monitoring, telemetry) with a documented allow-list. Real-world C2 sleeps from seconds to hours, so also run a **daily-bucket** version (connections per hour per destination).

### 2. Rare / new destinations from servers and sensitive hosts

```kql
let seen = DeviceNetworkEvents | where Timestamp between (ago(30d) .. ago(1d)) | distinct RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public" and isnotempty(RemoteUrl)
| where DeviceName in (ServerList)        // define a watchlist/let of servers
| where RemoteUrl !in (seen)
| summarize Conns = count(), Hosts = dcount(DeviceName) by RemoteUrl
| where Hosts == 1
```

### 3. HTTP(S) fingerprints

- **User-Agent stacking** (proxy/Zeek `http.log`): rare UAs, outdated browsers, default library UAs (`python-requests`, `Go-http-client`, `curl`), or UA vs. process mismatch
- **JA3/JA3S/JARM** (Zeek `ssl.log` with ja3 package): rare client fingerprints and server fingerprints shared with known C2
- **Certificates**: self-signed, default Cobalt Strike/Metasploit certificate subjects, `Let's Encrypt` on bare IPs
- **URI patterns**: short random paths, consistent sizes, `GET` with cookie/header carrying encoded data
- **Direct-to-IP HTTPS** on non-standard ports from servers

```spl
index=zeek sourcetype=zeek_ssl 
| stats count dc(id.orig_h) as clients by ja3
| where clients<3
| sort - count
```

### 4. Process/network pairing (EDR)

Processes that should not talk to the internet but do: `rundll32`, `regsvr32`, `svchost.exe` (unusual), `notepad.exe`, `werfault.exe`, `dllhost.exe`, `msiexec`, `wmic`. Stack by `InitiatingProcessFileName` and destination.

### 5. DNS: tunneling, DGA and C2

Indicators: long labels, high entropy, many unique subdomains under one parent, TXT/NULL/CNAME-heavy, high query volume per host, NXDOMAIN spikes (DGA).

```kql
DnsEvents
| where TimeGenerated > ago(1d) and QueryType in ("TXT","NULL","CNAME","A","AAAA")
| extend Parent = strcat_array(array_slice(split(Name, "."), -2, -1), "."), LabelLen = strlen(tostring(split(Name, ".")[0]))
| summarize Queries = count(), UniqueNames = dcount(Name), AvgLabel = avg(LabelLen), MaxLen = max(strlen(Name)) by ClientIP, Parent
| where UniqueNames > 200 and AvgLabel > 20
| order by UniqueNames desc
```

```spl
index=zeek sourcetype=zeek_dns
| eval parent=replace(query,"^.*?([^.]+\.[^.]+)$","\1"), qlen=len(query)
| stats count dc(query) as uniq avg(qlen) as avglen by id.orig_h parent
| where uniq>200 AND avglen>30
| sort - uniq
```

Use the effective second-level domain (public suffix list) in production; `co.uk`-style suffixes break the 2-label split.

**Entropy** (Splunk URL Toolbox `ut_shannon`, or Python) helps flag DGAs; combine with *newly observed domain* age/registration data.

### 6. Volume asymmetry and long sessions

Interactive C2 (SOCKS, tunnels) shows long-lived connections and balanced bytes in/out; beacons show tiny constant requests. Rank by `duration`, `orig_bytes`/`resp_bytes` in Zeek `conn.log`.

## Triage

1. Destination: domain age, hosting ASN, certificate, reputation, passive DNS history, other internal hosts contacting it.
2. Process responsible (EDR) and its path/signature/parent.
3. Interval and size pattern: confirm in a time series chart.
4. Anything else on the host: persistence, discovery commands, dump tools.
5. Memory/disk triage (Velociraptor, EDR live response): look for in-memory implants (beacon config extraction with e.g. `CobaltStrikeParser`).

## Common false positives

Software update checkers, telemetry, SaaS sync clients, monitoring agents, chat/collab apps, browser extensions, CDN heartbeats. Document by **process + destination + interval**.

## Escalate when

A non-browser or injected process beacons to a rare external destination, especially coupled with discovery/credential activity, or DNS tunneling to a domain you don't own.

## Validate and operationalise

- Emulate in the lab with a **benign beacon**: a scheduled `curl` loop with jitter; or Atomic Red Team `T1071.001` / `T1071.004`, or frameworks such as Sliver/Mythic/Havoc on isolated infrastructure.
- Detection: scheduled analytic producing top-N beacon candidates per day, enriched with threat intel and an allow-list.
- Hardening: egress filtering/default-deny for servers, force proxy use with TLS inspection where lawful, DNS filtering (RPZ) and logging, block DoH to unapproved resolvers.
