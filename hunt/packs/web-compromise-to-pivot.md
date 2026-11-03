---
title: "Hunt Pack: Web-Facing Compromise to Internal Pivot"
permalink: /hunt/packs/web-compromise-to-pivot/
excerpt: "Follow an edge compromise from a web shell on a DMZ server to credential theft and lateral movement into the internal network."
classes: wide
toc: true
toc_sticky: true
pack: true
playbooks: [web-shells, lolbin-proxy-execution, powershell-abuse, network-share-discovery, lsass-credential-dumping, lateral-movement, c2-beaconing, data-exfiltration, persistence, linux-hunting]
attack: [T1190, T1505.003, T1059, T1083, T1552.001, T1135, T1003.001, T1021.002, T1090, T1572, T1048, T1133, T1136.001]
duration: "4-5 days, 1-2 analysts"
---

{% include pack-meta.html %}

An internet-facing application is exploited and a web shell is written under the web root. The first commands run as the web server's own account: `whoami`, `net`, `nltest`, directory listings looking for configuration files and connection strings. Stored credentials in `web.config`, `appsettings.json` or an `.env` file open a database or a file share. The operator sets up a tunnel or SOCKS proxy out of the DMZ so the rest of the activity looks like it originates from the edge server, then reuses the harvested credentials to move inward: an SMB admin share here, a WinRM session there, until an internal host with a privileged session is reached. Persistence is planted on an internal server so the access survives a rebuild of the edge box.

The defining signal of this pack is lineage: a web worker process (`w3wp.exe`, `httpd`, `tomcat`, an `nginx` worker) is the parent of a shell, and from there the activity walks from a segment that should be nearly silent into one that should be busy. Network telemetry between the DMZ and the internal VLANs is as important here as endpoint data.

**Run it when:** a vulnerability in an edge product is disclosed and you run an internet-facing estate, a WAF or IDS alert fires on an exposed app, intel describes exploitation of software you run, after any edge-server incident, or on a schedule for the crown-jewel public applications. The edge may be Windows or Linux, so the pack uses both.

## Kill chain at a glance

| Phase | What the adversary is doing | ATT&CK | What you would see (telemetry) | Hypotheses | Playbook |
|---|---|---|---|---|---|
| 1. Exploitation | Abusing a vulnerability in the public application | T1190 | WAF/IDS alerts; anomalous POSTs; the worker process spawning a shell or recon tool | H-003 | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) (step 4) |
| 2. Web shell | A script file is written under the web root and served | T1505.003 | New `.aspx`/`.jsp`/`.php`/`.ashx` files no pipeline wrote (Sysmon 11, FIM); access-log hits on an odd path | H-004, H-021 | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) |
| 3. On-host recon | Enumeration as the web-server account | T1059, T1083, T1082 | `cmd`/`powershell`/`sh` children of the worker; `whoami`/`net`/`nltest` clusters; reads of config files | H-011, H-052 | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) (step 1), [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) |
| 4. Credential harvesting | Reading stored secrets from files and the registry | T1552.001, T1003.001 | Non-admin reads of `web.config`/`appsettings`/`.env`/`id_rsa`; LSASS access on a Windows edge | H-048, H-040 | [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/), [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| 5. Tunnelling out of the DMZ | A proxy or tunnel so later activity appears to come from the edge | T1090, T1572, T1071.001 | Long balanced-byte sessions from a server that normally only serves inbound; new outbound from the DMZ; `chisel`/`ligolo`/`ssh -R` style processes | H-073, H-074 | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| 6. Share and file discovery | Looking for internal file servers and sensitive shares | T1135, T1039 | 5140/5145 fan-out from the edge account; `net view`/`Get-SmbShare`; access to shares the edge never touches | H-054, H-065 | [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |
| 7. Internal pivot | Reusing credentials to move from the DMZ inward | T1021.002, T1021.006, T1550.002 | Logons from the DMZ host or its account to internal servers; new (user, host) pairs crossing the segment boundary | H-057, H-058, H-060 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| 8. Persistence and exfil | Footholds on internal hosts; data staged and sent out | T1136.001, T1543.003, T1048, T1567.002 | New local accounts/services on internal hosts; archives in staging paths; outbound volume anomalies | H-019, H-064, H-078 | [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/), [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |

## Telemetry you need before you start

Check each source against [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/). The segment boundary is the thing this pack cannot do without.

**Must-have**

- `edr` or `sysmon` on every internet-facing server (Windows and Linux): process creation with command line, file creation under web roots (Sysmon 11 / `DeviceFileEvents`), network connections
- `iis` / web-server access logs (IIS, Apache, nginx) with URI, status, method, user agent and client IP
- `windows-security` on internal servers: 4624, 4648, 4688, 7045; and `linux-auditd` on Linux edge and internal hosts
- Network flow or firewall logs **across the DMZ-to-internal boundary** with source, destination, port and bytes, so a pivot across the boundary is visible even when host logs are missing
- File-integrity monitoring on web roots, or a known-good manifest of deployed files

**Nice-to-have**

- `zeek` `conn.log`, `http.log` and `ssl.log` at the perimeter and on the internal uplink (long-session and tunnelling detection, H-073)
- `proxy` egress logs if the DMZ is allowed outbound at all (it often should not be)
- Database audit logs for the systems the edge app connects to
- Secrets-management telemetry (which identities read which secrets)

## Five-day hunt plan

| Day | Focus | Steps | Output |
|---|---|---|---|
| 1 | Web-server lineage and new files: the core signal | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) steps 1 and 2 on every edge server (worker spawning shells; new/modified script files vs a known-good manifest); access-log analytics (step 3) for the files found | Confirmed clean, or a web shell found and an incident opened; manifest of legitimate web-root files |
| 2 | On-host recon and credential harvesting at the edge | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) recon pivots; [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) steps 1-2 on Windows edge; [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) reverse-shell and web-account `sudo` steps on Linux edge; search for reads of config/secret files by the web account | Edge-account activity baselined; any credential read escalated |
| 3 | The segment boundary: tunnelling and inbound pivots | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) steps 1 and 6 on DMZ egress (regular intervals, long balanced sessions); flow analysis of DMZ-to-internal connections that are new in the last 14 days; [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) fan-out from edge accounts | List of every connection that crossed the boundary from the edge, each attributed or escalated |
| 4 | Internal movement and persistence | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) steps 1 and 3 focused on the edge host and its account; [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) steps 3 and 6 on the internal servers the edge reached; [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) steps 1 and 4 | Internal footholds found or ruled out; staging activity reviewed |
| 5 | Reporting, detections, backlog | [Hunt report]({{ site.baseurl }}/templates/#hunt-report); confirm the rules below are live; log the segmentation and logging gaps the hunt exposed; backlog | Report, detection hand-off, backlog, updated [coverage map]({{ site.baseurl }}/research/mitre-mapping/) |

## Pivot map

- If you find **a web worker spawning a shell** → that is the incident. Capture the command lines, the files written under the web root around that time, and every outbound connection the host made afterwards ([Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) steps 1-2, then [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) step 6).
- If you find **a new script file under a web root** → check the access log for requests to it (who called it, from which IPs, with what parameters) and for the worker executing commands shortly after each request ([Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) step 3).
- If you find **the web account reading config or secret files** → identify which credentials those files hold and search for those credentials authenticating anywhere (database, share, internal host) after the read (H-048).
- If you find **a long, balanced-byte outbound session from a DMZ server** → map where that tunnel could reach internally and hunt for logons from the edge host or account to internal servers in the same window ([Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) step 1).
- If you find **a connection from the DMZ to an internal server that is new in 30 days** → treat the segment boundary as crossed; pull host logs on both ends and determine the account and protocol used.
- If you find **share enumeration from an edge account** → the operator is looking for internal file servers; check which shares were then accessed and whether any held credentials or backups (H-054, H-065).
- If you find **a new local account or service on an internal host reached from the DMZ** → this is the durable foothold; scope every host that account or service touched ([Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) steps 3 and 6).
- If you find **archives in staging paths on an internal host** → look for the outbound transfer, remembering it may egress through the DMZ tunnel rather than directly ([Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) steps 2-5).

## Detections to confirm are live

**Edge and execution**

- [Web Server Process Spawning Shell or Recon Tool]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml)
- [PowerShell Encoded Command Execution]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml)
- [Linux Reverse Shell Command Line]({{ site.baseurl }}/research/sigma/T1059.004-linux-reverse-shell.yml)
- [CertUtil LOLBin Encode/Decode Abuse]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml)

**Credential access and movement**

- [Suspicious LSASS Process Access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml)
- [SMB Session and Local Group Enumeration via IPC$ Named Pipes]({{ site.baseurl }}/research/sigma/T1018-session-enumeration-burst-smb.yml)
- [Possible Pass-the-Hash Lateral Movement]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml)
- [WinRM Host Process Spawning Shell or LOLBin]({{ site.baseurl }}/research/sigma/T1021.006-wsmprovhost-spawns-shell.yml)

**Persistence and exfiltration**

- [Local Account Created via Command Line]({{ site.baseurl }}/research/sigma/T1136.001-local-account-created-cli.yml)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml)
- [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml)

## What good looks like

- Every internet-facing server has process-with-command-line telemetry and web-root file monitoring, and a known-good manifest exists for each web root
- The DMZ-to-internal boundary is logged at the network layer, and a list of legitimate cross-boundary flows exists to baseline against
- Web-server service accounts have a documented behavioural baseline (they should almost never spawn shells or read credentials)
- Any outbound connectivity from the DMZ is enumerated and justified; tunnelling-shaped sessions are explained
- The rules above are deployed and have fired in the lab ([Emulate → detect]({{ site.baseurl }}/labs/emulate-and-detect/)) with false-positive notes recorded
- Segmentation and logging gaps the hunt exposed are written up with owners, not just noted
- Backlog items exist for any phase the data did not support

## Tabletop prompts

1. If our public app were exploited today, which log would first show the web worker running a command, and who would see it?
2. What credentials sit in the config files on our edge servers, and what can each of them reach inside?
3. Should any of our DMZ servers be able to open connections inward or outward, and would we notice if one did?
4. How would an operator get from the edge to a file server, and which of those hops do we log on both ends?
5. If the edge box were rebuilt tomorrow, where else might the access still live?

## Hardening that shortens the next hunt

1. Strict egress control from the DMZ (ideally none outbound), and tight, logged inbound rules from the DMZ to internal services
2. Web-server service accounts with least privilege, no interactive logon, and no reuse of their credentials elsewhere
3. Secrets out of config files and into a managed vault with per-identity audit; rotate anything found in plaintext
4. Application-allowlisting on edge servers so a worker process cannot launch shells or LOLBins
5. File-integrity monitoring on web roots with alerting on any file the deployment pipeline did not write
6. Rapid patching and virtual patching (WAF rules) for internet-facing products, with the exposure inventory kept current
7. Separate credentials and separate administration for DMZ and internal tiers

## Related

- Learn: [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/), [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/), [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/)
- Templates: [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card), [hunt report]({{ site.baseurl }}/templates/#hunt-report)
- Blog: [Threat hunting fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/), [Hunting C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/)
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) and the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/)
