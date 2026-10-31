---
title: "Network & DNS Hunting (Zeek)"
excerpt: "Zeek logs and fields, command-line one-liners, ports of interest and DNS anomaly patterns."
---

## Zeek logs that matter

| Log | Contents | Hunt uses |
|---|---|---|
| `conn.log` | Every connection: 5-tuple, duration, bytes, `conn_state`, `history` | Beaconing, scanning, exfil volume, long sessions |
| `dns.log` | Queries, answers, rcode, qtype | Tunneling, DGA, rare domains |
| `http.log` | Method, host, URI, user agent, status, sizes | Rare UAs, downloads, C2 over HTTP |
| `ssl.log` | SNI, certificate chain, JA3/JA3S (with package), validation | C2 over TLS, self-signed certs |
| `x509.log` | Certificate details | Cert pivots |
| `files.log` | File hashes, MIME types, extracted files | Payload delivery |
| `smb_files.log`, `smb_mapping.log` | SMB file ops, share mounts | Lateral movement, ADMIN$ writes |
| `dce_rpc.log` | RPC calls | DCSync (`drsuapi`), remote service/task creation (`svcctl`, `atsvc`, `ITaskSchedulerService`) |
| `kerberos.log` | AS/TGS requests, cipher, success | Kerberoasting, AS-REP roasting |
| `ntlm.log` | NTLM auth details | PtH, spray, relay |
| `rdp.log` | RDP cookies, security protocol | RDP from odd places |
| `ssh.log` | Auth success/fail, client/server strings, direction | Brute force, tunnels |
| `notice.log`, `weird.log` | Zeek detections, protocol anomalies | Leads |

## `conn_state` quick guide

| State | Meaning |
|---|---|
| `S0` | SYN seen, no reply (scan, blocked) |
| `S1` | Established, not closed |
| `SF` | Normal establish and close |
| `REJ` | Rejected |
| `RSTO / RSTR` | Reset by originator / responder |
| `OTH` | No SYN seen; mid-stream (long-lived / capture started late) |

## `zeek-cut` one-liners

```bash
# Top talkers by bytes out
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | awk '{b[$1" "$2]+=$3} END{for(k in b)print b[k],k}' | sort -rn | head
# Long connections (> 1 hour)
cat conn.log | zeek-cut -d ts id.orig_h id.resp_h id.resp_p duration | awk '$5>3600' | sort -k5 -rn | head
# Rare user agents
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -30
# DNS: longest queries
cat dns.log | zeek-cut query | awk '{print length($0), $0}' | sort -rn | head
# NXDOMAIN storms per client
cat dns.log | zeek-cut id.orig_h rcode_name | grep NXDOMAIN | cut -f1 | sort | uniq -c | sort -rn | head
# Self-signed / odd certs
cat ssl.log | zeek-cut server_name validation_status | grep -v ok | sort | uniq -c | sort -rn | head
# JA3 stacking (with ja3 package)
cat ssl.log | zeek-cut ja3 | sort | uniq -c | sort -n | head -30
```

## Beacon detection tools

- **RITA / AC-Hunter (Active Countermeasures)**: scores beaconing, long connections, DNS tunneling from Zeek logs
- **Custom**: see the timing queries in [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/)

## Ports of interest (internal east-west)

| Port | Service | Why hunt it |
|---|---|---|
| 22 | SSH | Server-to-server pivoting; tunnels |
| 135, 49152-65535 | RPC / DCOM | Remote WMI, scheduled tasks, service creation |
| 139, 445 | SMB | PsExec, `ADMIN$`, ransomware spread |
| 3389 | RDP | Lateral movement; tunnelled RDP |
| 5985, 5986 | WinRM | PowerShell remoting |
| 88 | Kerberos | Roasting, ticket abuse |
| 389, 636, 3268, 3269 | LDAP / GC | AD recon (BloodHound), LDAP relay |
| 1433, 3306, 5432 | Databases | Bulk access, `xp_cmdshell` |
| 53, 853, 443 (DoH) | DNS | Tunneling, resolver bypass |
| 4444, 8080, 8443, 1337, 31337 | Common implant defaults | Lead only; C2 uses any port |
| 21, 69, 20 | FTP/TFTP | Exfil on legacy protocols |

## DNS anomaly checklist

- Query length > 50 chars, labels > 30 chars, many unique subdomains of one parent
- High entropy labels (DGA/tunnel); many `TXT`/`NULL`/`CNAME` queries
- High NXDOMAIN ratio per client (DGA)
- Newly registered domains (age < 30 days), rare TLDs (`.top`, `.xyz`, `.click` are overrepresented, but lead only)
- Direct-to-IP DNS to external resolvers; DoH/DoT to non-approved providers
- Queries to dynamic DNS and tunneling services (`ngrok`, `duckdns`, `no-ip`, `trycloudflare`)

## PCAP quick triage

```bash
tcpdump -nn -r cap.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' | head
tshark -r cap.pcap -q -z conv,tcp | head -30            # conversations by bytes
tshark -r cap.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri -e http.user_agent
tshark -r cap.pcap -Y 'dns.qry.name' -T fields -e ip.src -e dns.qry.name -e dns.qry.type | sort | uniq -c | sort -rn | head
zeek -r cap.pcap                                         # produce Zeek logs from a pcap
```
