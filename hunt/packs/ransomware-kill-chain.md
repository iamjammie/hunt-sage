---
title: "Hunt Pack: Ransomware Kill Chain"
permalink: /hunt/packs/ransomware-kill-chain/
excerpt: "A one-week campaign that chains ten playbooks to catch a ransomware affiliate in the days between foothold and encryption."
classes: wide
toc: true
toc_sticky: true
pack: true
playbooks: [initial-access-phishing, rdp-winrm-anomalies, powershell-abuse, lolbin-proxy-execution, c2-beaconing, ad-discovery-bloodhound, network-share-discovery, lsass-credential-dumping, kerberoasting, lateral-movement, defense-evasion, data-exfiltration, ransomware-precursors]
attack: [T1566.001, T1133, T1059.001, T1218, T1071.001, T1087.002, T1135, T1003.001, T1558.003, T1021.001, T1021.002, T1562.001, T1070.001, T1567.002, T1490, T1486]
duration: "1 week, 2 analysts"
---

{% include pack-meta.html %}

A user opens an invoice-themed attachment, or an affiliate buys a VPN credential from a broker and signs in through the gateway at 02:00. A PowerShell loader runs through a LOLBin, pulls a second stage, and a beacon starts calling home every few minutes. Over the next three to seven days the operator enumerates the domain with SharpHound, lists shares to find backups and file servers, dumps LSASS on the first host, roasts a few service accounts and moves to a server with RDP. Defender is excluded or disabled on the hosts that matter, logs are cleared on the way out, and a few hundred gigabytes of finance and HR data leave through `rclone` to a cloud bucket. On the last night, shadow copies are deleted, backup services are stopped, and the encryptor is pushed through GPO or PsExec to everything the stolen domain-admin account can reach.

Every one of those phases produces telemetry. This pack strings together the playbooks that look for each one, in the order that gives the earliest warning. The aim is not to detect encryption (that is the last and loudest event) but to find the dwell-time activity that precedes it.

**Run it when:** sector intel reports an active affiliate campaign, a peer organisation is hit, a quarterly assurance hunt is due, or after any confirmed commodity-malware infection that was "cleaned" without a full scope. It suits two analysts for a working week; one analyst can run the must-have phases (days 1-3) in the same time.

## Kill chain at a glance

| Phase | Adversary action | ATT&CK | What you would see (telemetry) | Hypotheses | Playbook |
|---|---|---|---|---|---|
| 1. Initial access | Phishing attachment, ISO/LNK lure, or stolen VPN/RDP credentials | T1566.001, T1566.002, T1133 | Office spawning script hosts; execution from mounted images; gateway logons from new countries or ASNs | H-001, H-002, H-005 | [Phishing & initial execution]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/), [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| 2. Execution | PowerShell loader, encoded commands, LOLBin download cradle | T1059.001, T1218, T1105 | 4104 script blocks with `-enc`/`IEX`; `mshta`/`rundll32`/`certutil` with URLs; rare parent/child pairs | H-008, H-009, H-075 | [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/), [LOLBin proxy execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) |
| 3. Command and control | Beacon over HTTPS, often through a rented VPS or a legitimate web service | T1071.001, T1573, T1102 | Low-jitter connection intervals; destinations new to the estate; library user agents | H-069, H-070, H-072 | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| 4. Discovery | SharpHound, `net`/`nltest` recon, share enumeration for backups and file servers | T1087.002, T1018, T1135, T1482 | LDAP bursts; SMB session enumeration against many hosts; 5140/5145 fan-out; recon command clusters | H-051, H-052, H-054 | [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/), [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |
| 5. Credential access | LSASS dump, Kerberoasting, cached local-admin reuse | T1003.001, T1558.003, T1110.003 | Sysmon 10 with suspicious masks; `comsvcs MiniDump`; 4769 RC4 bursts; 4625 spray patterns | H-040, H-041, H-043, H-047 | [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/), [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| 6. Lateral movement | RDP to servers, PsExec/SMB, WinRM, pass-the-hash | T1021.001, T1021.002, T1021.006, T1550.002 | New (user, host) logon pairs; type-10 logons workstation-to-server; 7045 random service names; type-9 `seclogo` | H-057, H-058, H-059, H-061 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/), [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| 7. Defense evasion | Defender exclusions or disablement, EDR service stops, event-log clearing | T1562.001, T1070.001, T1036 | Defender 5001/5010/5012; `Set-MpPreference -Disable*`; 1102/104; renamed tools | H-031, H-032, H-033 | [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| 8. Collection and exfiltration | Archive to staging folders, `rclone`/MEGA upload of hundreds of GB | T1560, T1074, T1567.002 | 7z/rar writing large archives in `C:\PerfLogs` or `%TEMP%`; `rclone` with `--config`; upload volume far above the host's 30-day median | H-064, H-076, H-077 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| 9. Impact preparation | Shadow-copy deletion, backup and database service stops, GPO/PsExec deployment | T1490, T1489, T1484.001 | `vssadmin delete shadows`; `net stop` of backup/SQL services; new GPO linked at domain root; backup console logons from new hosts | H-080, H-081, H-083 | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| 10. Impact | Encryption and ransom notes | T1486 | One process renaming hundreds of files per minute with a new extension | H-082 | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) (step 3) |

## Telemetry you need before you start

Verify each source with the checklist in [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/). A phase with no data becomes a visibility finding in the report, not a hunt step.

**Must-have**

- `edr` or `sysmon`: process creation with command line (Sysmon 1 / 4688 with command-line auditing), process access (Sysmon 10), network connections (Sysmon 3), file creation (Sysmon 11), registry (Sysmon 12/13) on workstations *and* servers, including domain controllers and backup servers
- `windows-security` on all domain controllers: 4624, 4625, 4648, 4662, 4768, 4769, 4771, 4776, 5136, 5140, 5145; on member servers: 4624, 4688, 7045, 4698, 1102
- `powershell`: Script Block Logging (4104) and Module Logging (4103) fleet-wide
- `proxy` or `firewall` egress logs with bytes in/out, user agent and destination, retained for at least 30 days so beacon and volume baselines are possible
- VPN / RDP gateway authentication logs with source IP and geolocation

**Nice-to-have**

- `dns` resolver logs (for DGA, tunnelling and first-seen domains)
- `zeek` `conn.log`, `ssl.log` and `http.log` at the internet edge and between user and server VLANs
- Backup application audit logs (job deletions, retention changes, console logons) and the backup-server Security log
- Defender for Endpoint `DeviceEvents` tamper-protection and AV configuration events, or the equivalent from your EDR
- Email gateway logs that can be joined to endpoint execution by recipient and time (phishing playbook step 5)

## Five-day hunt plan

| Day | Focus | Steps | Output |
|---|---|---|---|
| 1 | Precursors and evasion: the loudest, highest-fidelity signals first | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) steps 1, 2 and 4 across the whole fleet, 90 days; [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) steps 1 and 2; [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 2 (exfil tools by `OriginalFileName`). Stack by host and account; triage every hit the same day | Confirmed clean or an incident declared. Allow-list of scheduled shadow-copy maintenance and backup admins |
| 2 | Credential access and discovery on and against the DCs | [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) steps 1-3 (stack LSASS openers fleet-wide, then suspicious masks); [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) step 1; [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) steps 1, 3 and 4; [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) 5140/5145 fan-out | Documented list of legitimate LSASS accessors, scanners and admin recon hosts; any unexplained burst escalated |
| 3 | Lateral movement and remote access baselines | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) steps 1, 3 and 6 (fan-out, PsExec-style, PtH); [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) steps 1, 2 and 5; gateway logons by new country/ASN per account (H-005). Baseline 30 days, compare the last 7 | New (user, host) pairs explained or escalated; list of jump hosts and admin workstations for the allow-list |
| 4 | Execution and C2: the quieter early stages | [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) steps 1-3; [LOLBin proxy execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) steps 1, 2 and 4; [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) steps 1 and 2 on proxy/firewall data; [Phishing & initial execution]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) steps 1 and 2 for the last 14 days | Beacon candidates triaged; long tail of rare parent/child pairs reviewed; download cradles explained |
| 5 | Reporting, detections, backlog | Fill the [hunt report]({{ site.baseurl }}/templates/#hunt-report); confirm the rules in the next section are deployed and firing in the lab; log every missing source as a visibility gap; file backlog items for phases you could not cover | Report, detection hand-off, backlog, updated coverage on the [ATT&CK map]({{ site.baseurl }}/research/mitre-mapping/) |

If you only have one analyst, run days 1-3 and record days 4-5 as backlog. Those three days cover the phases where ransomware operators are most consistent and least able to vary their tradecraft.

## Pivot map

- If you find **shadow-copy deletion or `bcdedit` recovery changes** on any host → treat it as an incident, not a hunt. Check the host's last 72 hours of logons (4624 type 3/10), look for `rclone`/archive activity on the same host, and query which account ran it and where else that account has logged on ([Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) step 1).
- If you find **Defender exclusions or disablement** → pivot to process creations on that host in the following hour (the payload lands right after), and to the same command on other hosts ([Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) step 2, then [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) step 4 for the deployment channel).
- If you find **a suspicious LSASS access** → pull the accessing process's parent chain and network connections (is it the beacon?), then search for that host's user accounts authenticating to new hosts after the access time ([LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) triage, [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) step 2).
- If you find **a Kerberoast burst** → list the SPNs requested; check 4624 for those service accounts from new sources since the burst ([Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) triage), and check whether the requesting host also ran SharpHound ([AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) step 4).
- If you find **SharpHound-style SMB session enumeration** → the operator now knows the path to domain admin. Hunt for logons by the enumerated privileged accounts from the enumerating host and its neighbours; check backup and file servers for new share access (H-054, H-065).
- If you find **a beacon** → identify the process, its parent and its first appearance; search for the loader command line fleet-wide ([C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) step 4, [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) step 1), and check whether the same destination was contacted by any other host.
- If you find **large archives in staging paths** → look for the upload (proxy bytes out, `rclone`, SSH/FTP to public IPs) in the next 48 hours ([Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) steps 2-5), and assume impact is hours to days away.
- If you find **a gateway logon from a new country for a VPN account** → check the same account's internal activity in the following session: RDP destinations, share access, PowerShell. One phase of confirmation turns an anomaly into a case.
- If you find **a new GPO linked at the domain root or a new SCCM package by a non-admin** → open an incident; this is the deployment mechanism and encryption is typically scheduled within hours.

## Detections to confirm are live

Deploy or verify these Sigma rules while the hunt runs; several are the alert that would have fired earlier in a real intrusion.

**Initial access and execution**

- [Office or Document Reader Application Spawns Script Interpreter or LOLBin]({{ site.baseurl }}/research/sigma/T1566.001-office-application-spawns-interpreter.yml)
- [Execution from Extracted Archive, Disk Image Contents or Outlook Attachment Cache]({{ site.baseurl }}/research/sigma/T1204.002-execution-from-mounted-image-or-archive.yml)
- [PowerShell Encoded Command Execution]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml)
- [Mshta Executing Remote or Inline Script Content]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml)
- [Rundll32 Suspicious Invocation]({{ site.baseurl }}/research/sigma/T1218.011-rundll32-suspicious-invocation.yml)
- [CertUtil LOLBin Encode/Decode Abuse]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml)
- [BITSAdmin Download or Persistent Transfer Job]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml)

**Discovery and credential access**

- [Active Directory Enumeration Tooling on the Command Line]({{ site.baseurl }}/research/sigma/T1087.002-ad-enumeration-tooling-command-line.yml)
- [SMB Session and Local Group Enumeration via IPC$ Named Pipes]({{ site.baseurl }}/research/sigma/T1018-session-enumeration-burst-smb.yml)
- [Suspicious LSASS Process Access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml)
- [Kerberoasting - RC4 Service Ticket Requests]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml)

**Lateral movement and evasion**

- [Possible Pass-the-Hash Lateral Movement]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml)
- [Remote Desktop Enabled via Command Line or PowerShell]({{ site.baseurl }}/research/sigma/T1021.001-rdp-enabled-via-command-line.yml)
- [WinRM Host Process Spawning Shell or LOLBin]({{ site.baseurl }}/research/sigma/T1021.006-wsmprovhost-spawns-shell.yml)
- [Microsoft Defender Disabled or Excluded via PowerShell/Command Line]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml)
- [Windows Event Log Cleared]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml)

**Exfiltration and impact**

- [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml)
- [Shadow Copy Deletion or Recovery Inhibition]({{ site.baseurl }}/research/sigma/T1490-shadow-copy-deletion.yml)

## What good looks like

- Every phase in the table has either a completed hunt step with a documented result or a visibility gap logged against a named data source
- The precursor queries (shadow copies, service stops, Defender tampering, `rclone`) returned only explained activity, and that activity is written up as allow-list candidates with owner and expiry
- Legitimate LSASS accessors, vulnerability scanners and admin recon hosts are documented so the next hunt starts from a baseline rather than from zero
- New (user, host) logon pairs for privileged accounts over the last 30 days are all attributable to a ticket, a person or a job
- The rules listed above are deployed, have fired at least once in the lab ([Emulate → detect]({{ site.baseurl }}/labs/emulate-and-detect/)), and their false-positive notes are in the rule files
- Egress baselines (bytes out per host per day, beacon candidates) exist as saved searches so day 4 takes an hour next quarter
- Backlog items exist for the phases not covered, with the hypothesis id and the data needed

## Tabletop prompts

1. If the first beacon started on a Tuesday, which of our data sources would have shown it by Wednesday, and who would have looked?
2. Which five accounts could deploy to every endpoint today, and when did each last log on from somewhere new?
3. How many hosts can run `vssadmin` without an alert firing within five minutes? How do we know?
4. Where would an operator stage 300 GB before upload, and what would our proxy logs show while it left?
5. If our backup server was encrypted tonight, which log would tell us when the attacker first touched it?

## Hardening that shortens the next hunt

1. Tamper protection on for EDR and Defender; exclusions managed centrally and alerted on change
2. Tiered administration: domain admins never log on to workstations; separate admin workstations; LAPS for local administrator passwords
3. MFA on every remote-access path, and conditional access that blocks legacy authentication and unknown countries for VPN and RDP gateways
4. Immutable or offline backups with a separate identity plane; alert on backup console logons from non-backup hosts
5. Block or audit `vssadmin`, `wbadmin`, `bcdedit` and `wmic shadowcopy` for non-backup accounts via AppLocker/WDAC, and alert on them everywhere
6. Egress filtering by category with cloud-storage destinations limited to sanctioned tenants; TLS inspection or at least SNI logging
7. SMB signing, disabled SMBv1, and host firewalls that block workstation-to-workstation 445/3389/5985
8. Long random passwords or gMSA for every account with an SPN; remove unnecessary SPNs

## Related

- Learn: [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/), [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/), [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/), [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/)
- Templates: [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card), [hunt report]({{ site.baseurl }}/templates/#hunt-report)
- Blog: [Hunting persistence]({{ site.baseurl }}/blog/hunting-persistence/), [Hunting C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/), [Pass-the-hash]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/), [Argon Dynamics case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/)
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) and the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/)
