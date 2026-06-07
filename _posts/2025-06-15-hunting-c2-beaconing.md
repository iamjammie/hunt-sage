---
title: "Hunting C2 Beaconing: Finding the Heartbeat in Your Network Traffic"
date: 2025-06-15
categories:
  - blog
tags:
  - threat-hunting
  - C2
  - network
  - beaconing
  - DNS
toc: true
toc_label: "Contents"
header:
  teaser: /assets/images/posts/c2-beaconing.png
excerpt: "C2 beaconing is how attackers maintain persistence and receive commands. It has a rhythm. If you know how to look, you can hear it."
---

## The C2 Problem

Once an attacker has a foothold in your environment, they need a way to issue commands and receive data back. That communication channel is Command & Control (C2).

Modern C2 frameworks (Cobalt Strike, Sliver, Havoc, Metasploit) are designed to hide in plain sight — they use HTTPS, blend into normal browser traffic, and jitter their timing to avoid obvious patterns. But they all share one unavoidable property: **they have to check in regularly**.

That regular check-in is called **beaconing**. And beaconing leaves a rhythm in your network logs.

---

## What Beaconing Looks Like

A C2 beacon makes outbound connections to the attacker's server at regular intervals — typically every 30 seconds to 5 minutes, depending on the operator's configuration. They often add **jitter** (random timing variance of ±10-30%) to avoid exact-interval detection.

Even with jitter, a beacon still produces:
- **High frequency** of connections to the same destination
- **Small, consistent payload sizes** (check-ins with no active tasking are tiny)
- **Low data volume per connection** (unlike legitimate browsing)
- **Connections at unusual hours** (including 3am when users are asleep)

---

## Data Sources

To hunt beaconing, you need network telemetry. In order of preference:

| Source | What It Gives You | Gaps |
|--------|------------------|------|
| Full packet capture (PCAP) | Everything | Storage cost, encryption |
| NetFlow / IPFIX | Connection metadata (IPs, ports, bytes, duration) | No payload content |
| DNS logs | All domain lookups (great for DNS C2) | Doesn't show HTTP C2 |
| Proxy logs | HTTP/HTTPS with URL, user-agent, bytes | Misses direct IP connections |
| EDR network events | Process-attributed connections | Varies by product |

---

## Hunting Beaconing in Proxy Logs (KQL)

**Hunt: High-frequency connections to a single domain from same host**
```kql
// Requires proxy or network connection logs in Sentinel
CommonSecurityLog
| where DeviceVendor == "Zscaler" or DeviceVendor == "Palo Alto Networks"
| where RequestURL != ""
| extend Domain = tostring(parse_url(RequestURL).Host)
| where Domain !endswith "microsoft.com" 
    and Domain !endswith "windows.com"
    and Domain !endswith "office.com"
    and Domain !endswith "google.com"
// Remove your known-good domains
| summarize 
    ConnectionCount = count(),
    UniqueHours = dcount(bin(TimeGenerated, 1h)),
    TotalBytesSent = sum(SentBytes),
    TotalBytesReceived = sum(ReceivedBytes),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, Domain
| where ConnectionCount > 20
| where UniqueHours > 3  // consistent over multiple hours
| extend AvgBytesPerConn = TotalBytesSent / ConnectionCount
| where AvgBytesPerConn < 5000  // small payloads per connection
| order by ConnectionCount desc
```

**Hunt: Beaconing with timing regularity (statistical approach)**
```kql
// Measure variance in connection intervals — low variance = regular beacon
let suspicious_hosts = 
DeviceNetworkEvents
| where RemotePort in (80, 443, 8080, 8443)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ (
    "chrome.exe","firefox.exe","msedge.exe","outlook.exe","teams.exe"
)
| summarize 
    ConnectionTimes = make_list(Timestamp),
    TotalConnections = count()
    by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where TotalConnections > 10
| extend 
    TimeDiffs = array_sort_asc(ConnectionTimes),
    ConnectionCount = array_length(ConnectionTimes);
suspicious_hosts
| mv-expand TimeDiffs
| summarize 
    AvgInterval = avg(totimespan(TimeDiffs)),
    StdDevInterval = stdev(todouble(TimeDiffs))
    by DeviceName, RemoteIP, InitiatingProcessFileName
| where StdDevInterval < 60  // low variance = regular timing
| order by StdDevInterval asc
```

---

## Hunting DNS-Based C2

DNS C2 is particularly sneaky — it tunnels commands through DNS TXT or subdomain queries. Tools like `dnscat2` and `iodine` use this technique.

**Indicators of DNS C2**:
- Unusually long subdomain names (base64-encoded data)
- High query frequency to same domain
- DNS TXT record queries (rare in normal traffic)
- Queries to recently registered domains

**KQL Hunt for DNS C2 via subdomain length**:
```kql
DnsEvents
| where QueryType == "A" or QueryType == "TXT"
| extend Domain = Name
| extend SubdomainPart = tostring(split(Domain, ".")[0])
| extend SubdomainLength = strlen(SubdomainPart)
| where SubdomainLength > 30  // encoded data in subdomains is long
| summarize 
    QueryCount = count(),
    UniqueDomains = dcount(Domain),
    SampleQueries = make_set(Domain, 10)
    by Computer, SubdomainLength
| where QueryCount > 5
| order by SubdomainLength desc
```

**Splunk SPL — DNS Beaconing Detection**:
```spl
index=dns 
| eval domain=lower(query)
| rex field=domain "(?:[^.]+\.)*(?P<tld>[^.]+\.[^.]+)$"
| stats 
    count as query_count,
    dc(query) as unique_subdomains,
    values(src) as sources
    by tld
| where query_count > 50 and unique_subdomains > 20
| sort -unique_subdomains
```

---

## Sigma Rule: High-Frequency Outbound Connections

```yaml
title: Potential C2 Beaconing - High Frequency Connection to Single Host
id: b3c4d5e6-f7a8-9012-bcde-f12345678901
status: experimental
description: |
  Detects repeated outbound connections from a single process to the same 
  external IP, characteristic of C2 beaconing behaviour.
references:
  - https://attack.mitre.org/techniques/T1071/001/
  - https://attack.mitre.org/techniques/T1071/004/
author: hunt-sage
date: 2025/06/15
logsource:
  category: network_connection
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 3
    Initiated: 'true'
    DestinationIsIpv6: 'false'
  filter_known_good:
    Image|contains:
      - '\chrome.exe'
      - '\firefox.exe'
      - '\msedge.exe'
      - '\MicrosoftEdgeUpdate.exe'
      - '\svchost.exe'
      - '\SearchIndexer.exe'
  condition: selection and not filter_known_good
falsepositives:
  - Monitoring agents with regular check-in intervals
  - Backup software
  - Telemetry and diagnostic tools
level: low
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1071.004
  - attack.t1132
```

> **Note**: This Sigma rule is meant to feed into a threshold-based detection — a single match isn't meaningful, but 20+ matches from the same process within an hour is.

---

## Profiling What's Normal First

Before this hunt produces useful results, you need a baseline. Spend one week collecting:

- Which processes make regular outbound connections in your environment?
- What are their typical connection intervals and byte sizes?
- Which domains do they connect to?

Document this. Every exclusion you add to your hunt query should be justified and written down. An unjustified exclusion is just an attacker's escape hatch.

---

## Enrichment: Is the Destination Suspicious?

When you find a candidate host with beacon-like behaviour, enrich the destination:

1. **WHOIS**: When was the domain registered? Attacker infrastructure tends to be recently registered.
2. **Passive DNS**: Has this IP hosted other domains? How many?
3. **VirusTotal / Shodan**: Is it already flagged?
4. **Certificate Transparency**: What certificates has it used? C2 servers often have self-signed or unusual certs.
5. **ASN**: Is it hosted on a residential ISP or cloud hosting common for C2?

Free tools: [VirusTotal](https://virustotal.com), [Shodan](https://shodan.io), [Censys](https://censys.io), [URLScan](https://urlscan.io)

---

*Next post: The Argon Dynamics Data Spill — A Full Incident Hunt Walkthrough.*
