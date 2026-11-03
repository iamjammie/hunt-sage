---
title: "6. Adversary Tradecraft"
permalink: /learn/adversary-tradecraft/
excerpt: "What intruders actually do at each ATT&CK tactic, what it looks like in your data, and the common patterns of modern intrusions."
---

Hunters must think like adversaries. This chapter is a defender's tour of the intrusion lifecycle with a **hunting lens** at each stage.

## The modern intrusion in one picture

```text
Initial access → Execution → Persistence → Priv-esc → Defense evasion → Credential access
      → Discovery → Lateral movement → Collection → C2 / Exfiltration → Impact
```

Real intrusions are not linear. Adversaries loop through discovery → credential access → lateral movement many times. The more loops, the more chances to catch them.

## Tactic-by-tactic hunting lens

| Tactic | What adversaries do | Typical artefacts | Where to look | Playbook |
|---|---|---|---|---|
| **Initial access** | Phishing, exploit public-facing apps, valid accounts, supply chain | Office/browser spawning scripts; web server spawning shells; sign-ins from new geos or ASNs | Email, web, EDR, IdP | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/), [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| **Execution** | PowerShell, cmd, WMI, scripting hosts, LOLBins | Encoded/obfuscated command lines; script hosts with network access | Process creation, 4104 | [PowerShell]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/), [LOLBins]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) |
| **Persistence** | Run keys, services, scheduled tasks, WMI subs, startup folder, web shells, new accounts, cloud app registrations | New autoruns in unusual paths; new local admins | Registry, 4698/7045, Sysmon | [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| **Privilege escalation** | Token theft, UAC bypass, vulnerable drivers, misconfigured services, role assignment in cloud | 4672 special logon for new accounts; driver loads; role assignments | Security log, Sysmon 6/7 | |
| **Defense evasion** | Log clearing, disabling AV, masquerading, injection, signed-binary proxy execution, timestomping | 1102/104; Defender tampering; svchost from wrong path | Security/System logs, EDR | [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| **Credential access** | LSASS dumping, Kerberoasting, DCSync, NTDS.dit, browser/keychain theft, token theft | LSASS access; 4769 RC4 bursts; 4662 replication | Sysmon 10, DC logs | [LSASS]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/), [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/), [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| **Discovery** | `whoami`, `net`, `nltest`, BloodHound/SharpHound, port scans | Burst of recon commands; LDAP query spikes | Process, DC LDAP logs, network | |
| **Lateral movement** | RDP, SMB/PsExec, WMI, WinRM, DCOM, pass-the-hash/ticket | 4624 type 3/10 fan-out; 7045 `PSEXESVC`; admin share writes | Security, network | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| **Collection** | Archive staging (7-Zip, rar), email/SharePoint harvesting | Large archives in temp paths; mass file reads | EDR, file audit | [Exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| **C2** | HTTPS beacons, DNS tunneling, legitimate-service C2 (cloud storage, chat, tunnelling tools) | Regular intervals; rare domains; odd JA3/User-Agent | Proxy, DNS, NetFlow | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| **Exfiltration** | Over C2, cloud sync tools, FTP/SFTP, web services | Large outbound transfers; rclone/MEGA/WinSCP | Proxy, flow, EDR | [Exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| **Impact** | Ransomware, wipers, backup deletion, defacement | `vssadmin delete shadows`; mass file modifications | EDR, file server | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |

## Living off the land (LotL)

Adversaries increasingly use **tools already on the system** (PowerShell, WMI, `certutil`, `rundll32`, `mshta`, `schtasks`, `bitsadmin`, `net`, `nltest`, cloud CLIs) because they are signed, trusted and hard to block. Detection therefore hinges on **context**, not on the binary:

- *Who* ran it (service account? user who never uses a shell?)
- *What launched it* (parent process)
- *What arguments* (download, encode, remote target)
- *Where from* (user-writable paths) and *where to* (rare network destinations)

Reference: [LOLBAS](https://lolbas-project.github.io/) (Windows), [GTFOBins](https://gtfobins.github.io/) (Linux), [LOLDrivers](https://www.loldrivers.io/). See our [LOLBin cheat sheet]({{ site.baseurl }}/cheatsheets/lolbins/).

## Hands-on-keyboard vs automated

| | Automated / commodity | Hands-on-keyboard (human-operated) |
|---|---|---|
| Speed | Seconds to minutes | Minutes to days |
| Signals | Same chain every time; matches signatures | Discovery commands typed with typos; time-of-day patterns; varying tools |
| Hunting angle | Detect chain / IOCs | Detect *behavioural clusters* and anomalous admin use |

Human-operated ransomware is often preceded by days of hands-on activity. That window is where hunting pays off.

## Typical post-exploitation sequence (illustrative)

1. Initial foothold on a workstation (phishing payload, stolen VPN credential)
2. Quick discovery: `whoami /all`, `nltest /dclist:`, `net group "Domain Admins" /domain`
3. Credential access: LSASS dump or Kerberoast
4. Lateral movement to a server with admin rights (SMB/WinRM/RDP)
5. Domain-wide recon (BloodHound), find backup and file servers
6. DCSync or `ntds.dit` copy; persistence on multiple hosts
7. Stage and exfiltrate data; delete backups; deploy ransomware

Each numbered step maps to a playbook in this repo. Our [Argon Dynamics case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/) walks an example.

## Using intelligence on groups

ATT&CK "Groups" and "Software" pages list techniques tied to named actors/tools. Use them to:

- Build a **sector-relevant technique list** for prioritisation
- Understand *tool families* (Cobalt Strike, Sliver, Impacket, Mimikatz, Rubeus, BloodHound) and their artefacts
- **Avoid over-fitting** to attribution: adversaries share tooling; hunt techniques, not names

## Know your tools' fingerprints

| Tool | Common fingerprints to hunt |
|---|---|
| **Mimikatz** | LSASS access; `sekurlsa`, `lsadump` in command line or memory; driver `mimidrv.sys` |
| **Impacket** (`psexec.py`, `wmiexec.py`, `secretsdump.py`) | Service named randomly (psexec); `cmd.exe /Q /c ... \\127.0.0.1\ADMIN$\__<timestamp>` (wmiexec); 4662 DCSync from non-DC (secretsdump) |
| **Rubeus** | Bursts of 4768/4769 with RC4, `asktgt`, `kerberoast` args |
| **BloodHound / SharpHound** | Massive LDAP queries and SMB session enumeration from one host |
| **Cobalt Strike** | Named pipes (`\\.\pipe\msagent_*`, `postex_*`), rundll32/svchost spawned with no args, sleep-masked regular beacons, `jump psexec` services |
| **PsExec / PsExec-likes** | `PSEXESVC` service, 7045 with `\\ADMIN$` image paths |

Treat these as **leads** — defaults change. Use [behaviour](#living-off-the-land-lotl), not only strings.

## Next

→ [7. Detection engineering]({{ site.baseurl }}/learn/detection-engineering/)
