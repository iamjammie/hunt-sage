---
title: "Hunt Pack: Active Directory Domain Dominance"
permalink: /hunt/packs/ad-domain-dominance/
excerpt: "Chain the AD playbooks to find the enumeration, credential theft, tier-0 movement and certificate abuse that lead to Domain Admin, and the persistence that follows."
classes: wide
toc: true
toc_sticky: true
pack: true
playbooks: [ad-discovery-bloodhound, kerberoasting, lsass-credential-dumping, lateral-movement, rdp-winrm-anomalies, uac-bypass, adcs-abuse, dcsync, persistence, defense-evasion]
attack: [T1087.002, T1069.002, T1482, T1018, T1558.003, T1558.004, T1003.001, T1550.002, T1021.001, T1021.002, T1548.002, T1649, T1003.006, T1136.002, T1484.001, T1098]
duration: "1 week, 2 analysts (one with AD administration knowledge)"
---

{% include pack-meta.html %}

Most serious intrusions pass through the same choke point: control of Active Directory. The defender's view of that journey is a sequence of observable events on a small number of hosts. First, directory enumeration: a workstation reads every user, group, session, ACL and trust over LDAP and SMB in a short window. Then weak service and pre-authentication accounts are targeted for offline cracking. A privilege-escalation technique yields local administrator, after which credential material is harvested and reused to reach a server where a privileged administrator recently logged on. From there the path tends to fork toward either certificate-services abuse or directory replication, both of which hand the operator credentials that outlast a password reset. New accounts, group memberships, GPO edits and ACL changes follow, so that the access survives an incident.

The telemetry for this whole chain concentrates on the domain controllers, the certificate authority, and the tier-0 administration path. This pack puts the hunt where the evidence is and runs the AD playbooks in the order that gives the earliest, highest-fidelity warning.

**Run it when:** a red-team or penetration-test report shows a path to Domain Admin, intel describes AD-centric tradecraft against your sector, a new AD CS deployment or forest trust is added, after any incident where a domain account was confirmed stolen, or every quarter as a standing assurance hunt. One of the two analysts should be comfortable reading `msDS-*` attributes and certificate templates.

## Kill chain at a glance

| Phase | What the adversary is doing | ATT&CK | What you would see (telemetry) | Hypotheses | Playbook |
|---|---|---|---|---|---|
| 1. Foothold and local recon | Hands-on activity begins on a user workstation | T1059.001, T1082, T1033 | Rare parent/child process pairs; clusters of `whoami`/`net`/`nltest` within two minutes | H-011, H-012, H-052 | [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) (step 2) |
| 2. Directory enumeration | Bulk collection of users, groups, sessions, ACLs and trusts | T1087.002, T1069.002, T1482, T1018 | LDAP query bursts (1644); SMB session enumeration to many hosts in minutes; collection-tool command lines; honey-account touches | H-051, H-055, H-053 | [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) |
| 3. Offline credential attacks | Service-ticket and pre-auth requests aimed at offline cracking | T1558.003, T1558.004 | 4769 RC4 (`0x17`) for many SPNs from one account; 4768 `PreAuthType 0`; honey-SPN requests | H-043, H-044, H-046 | [Kerberoasting & AS-REP roasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| 4. Local privilege escalation | Elevation to administrator on the foothold host | T1548.002, T1134.001 | Auto-elevated binaries with high-integrity children; `ms-settings`/`mscfile` registry hijacks; SYSTEM children of user-context processes | H-025, H-027 | [UAC bypass]({{ site.baseurl }}/hunt/playbooks/uac-bypass/) |
| 5. Credential access | Harvesting credential material from memory and the registry | T1003.001, T1003.002 | Sysmon 10 access to LSASS with suspicious masks; `comsvcs MiniDump`; `reg save hklm\sam`; `.dmp` files on disk | H-040, H-041, H-042 | [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) |
| 6. Tier-0 movement | Reuse of stolen material to reach servers and the DCs | T1550.002, T1021.001, T1021.002, T1021.006 | New (user, host) logon pairs; type-10 logons to servers; type-9 `seclogo`; random-named 7045 services | H-057, H-058, H-059 | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/), [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| 7. Certificate-services abuse | Obtaining a certificate that authenticates as a privileged principal | T1649 | 4886/4887 requests with a requester-supplied SAN; template ACL changes (ESC4); NTLM relay to web enrolment (ESC8); first-time PKINIT logons | H-026, H-049 | [AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) |
| 8. Directory replication | Pulling secrets directly from a DC | T1003.006 | 4662 with replication GUIDs from an account that is not a DC or a sanctioned sync service | H-045 | [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| 9. Domain persistence | Access designed to survive incident response | T1136.002, T1098, T1484.001 | 4720 then 4732; `AdminSDHolder` and ACL edits (5136); `SIDHistory` additions; new GPOs linked at the domain root | H-019, H-023, H-083 | [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) (step 6), [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |

## Telemetry you need before you start

Verify every source against [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/). On the DCs and the CA, confirm the advanced audit subcategories are actually enabled; several of these events are off by default.

**Must-have**

- `windows-security` on **all** domain controllers: 4662 (with SACL on the domain object for replication GUIDs), 4768, 4769, 4771, 4776, 5136 (directory service changes), 4720/4722/4738, 4728/4732/4756 (group membership), 4624/4625/4648
- `windows-security` on member servers and the tier-0 administration hosts: 4624, 4648, 4688 with command line, 7045, 4698
- `edr` or `sysmon` on workstations and servers: process creation with command line, process access (Sysmon 10), registry (Sysmon 12/13), image load (Sysmon 7)
- `powershell` Script Block Logging (4104) fleet-wide
- `adcs`: certificate-authority audit events 4886/4887/4888 and the CA's own `CertificateServicesClient` logs, if AD CS is deployed

**Nice-to-have**

- LDAP query telemetry (1644 with field engineering enabled, or an LDAP-aware sensor) for enumeration volume
- Directory-change monitoring that resolves `msDS-AllowedToDelegateTo`, `msDS-KeyCredentialLink`, `AdminSDHolder` ACLs and `SIDHistory`
- A small set of honey objects: a honey SPN account and a honey user in a privileged-looking group, so any touch is high-fidelity (H-046)
- GPO change auditing (5136 on `gPLink` and SYSVOL file writes)

## Five-day hunt plan

| Day | Focus | Steps | Output |
|---|---|---|---|
| 1 | Directory replication and persistence: the highest-impact, lowest-volume signals | [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) steps 1-2 (4662 replication from non-DC accounts, plus an exposure review of who *can* replicate); [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) step 6 and the AD-ACL checks in [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/); honey-object review | Any replication by a non-DC account escalated immediately; documented list of accounts and groups with replication or `AdminSDHolder` rights |
| 2 | Certificate services and roasting | [AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) steps 1, 2 and 4 (SAN requests, template changes, first-time PKINIT logons); [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) steps 1 and 2 | Certificate requests with supplied SANs explained or escalated; list of SPN accounts still on RC4 or weak passwords |
| 3 | Enumeration and the honey tripwires | [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) steps 1, 3, 4 and 6 (tooling, LDAP volume, SMB session fan-out, honey accounts) | Enumeration bursts attributed to a scanner, an admin or an incident; tripwire accounts confirmed in place |
| 4 | Credential access and tier-0 movement | [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) steps 1-3; [UAC bypass]({{ site.baseurl }}/hunt/playbooks/uac-bypass/) steps on integrity-level transitions; [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) steps 1, 3 and 6; [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) steps 1 and 2, focused on logons *to* tier-0 | Documented LSASS accessors; every privileged logon to a DC or tier-0 host in 30 days attributed |
| 5 | Reporting, detections, backlog | [Hunt report]({{ site.baseurl }}/templates/#hunt-report); confirm the rules below are live and firing in the lab; log visibility gaps; file backlog items | Report, detection hand-off, backlog, updated [coverage map]({{ site.baseurl }}/research/mitre-mapping/) |

## Pivot map

- If you find **4662 replication from a non-DC account** → open an incident. Identify the account, where it logged on from in the preceding hours, and whether a certificate was issued to it or a new privileged account was created afterwards ([DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) triage, then [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) step 6).
- If you find **a certificate request with a requester-supplied SAN for a different principal** → check for a 4768 PKINIT logon as that principal from a new host shortly after ([AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) step 4), and review who modified the template.
- If you find **a Kerberoast burst** → list the SPNs; look for those service accounts authenticating from new sources since the burst, and check whether the requesting host also enumerated the directory ([AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) step 4).
- If you find **SharpHound-style SMB session enumeration** → the adversary now has the path to a privileged account. Hunt for logons by the accounts on that path from the enumerating host and its neighbours (H-055, H-057).
- If you find **a suspicious LSASS access** → pull the accessing process's parent chain and network connections, then search for that host's accounts authenticating to new hosts afterwards ([Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) step 2).
- If you find **a UAC-bypass pattern** (auto-elevated parent with a high-integrity shell child) → check the same host for credential access in the following hour and for the same technique elsewhere ([UAC bypass]({{ site.baseurl }}/hunt/playbooks/uac-bypass/) triage).
- If you find **a new account added to a privileged group** (4728/4732/4756) → identify who made the change and from where, and whether that actor is a sanctioned provisioning identity (H-019, H-023).
- If you find **a honey SPN or honey account touched** → treat it as an incident with no tuning required; trace the requesting source backward through the chain.
- If you find **a new GPO linked at the domain root or an `AdminSDHolder` ACL change** → open an incident; this is a domain-wide persistence or deployment mechanism.

## Detections to confirm are live

**Enumeration and roasting**

- [Active Directory Enumeration Tooling on the Command Line]({{ site.baseurl }}/research/sigma/T1087.002-ad-enumeration-tooling-command-line.yml)
- [SMB Session and Local Group Enumeration via IPC$ Named Pipes]({{ site.baseurl }}/research/sigma/T1018-session-enumeration-burst-smb.yml)
- [Kerberoasting - RC4 Service Ticket Requests]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml)

**Credential access and escalation**

- [Suspicious LSASS Process Access]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml)

**Certificate services and replication**

- [AD CS Certificate Request with Requester-Supplied Subject Alternative Name (ESC1)]({{ site.baseurl }}/research/sigma/T1649-certificate-request-with-san-esc1.yml)
- [AD CS Enumeration or Abuse Tooling Command Line]({{ site.baseurl }}/research/sigma/T1649-adcs-enumeration-tooling.yml)
- [DCSync - Directory Replication from Non-Domain-Controller Account]({{ site.baseurl }}/research/sigma/T1003.006-dcsync-replication.yml)

**Lateral movement and persistence**

- [Possible Pass-the-Hash Lateral Movement]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml)
- [Remote Desktop Enabled via Command Line or PowerShell]({{ site.baseurl }}/research/sigma/T1021.001-rdp-enabled-via-command-line.yml)
- [WinRM Host Process Spawning Shell or LOLBin]({{ site.baseurl }}/research/sigma/T1021.006-wsmprovhost-spawns-shell.yml)
- [Local Account Created via Command Line]({{ site.baseurl }}/research/sigma/T1136.001-local-account-created-cli.yml)
- [Suspicious Windows Service Installation]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml)

## What good looks like

- Replication rights, `AdminSDHolder` ACLs and unconstrained-delegation accounts are enumerated and every holder is attributable to a role
- No 4662 replication events exist from any account that is not a domain controller or a documented sync service
- Certificate templates that allow requester-supplied SANs or low-privileged enrolment are identified and either fixed or alerted on
- Every privileged logon to a DC or tier-0 host in the last 30 days maps to a person, a change ticket or a job
- Honey SPN and honey account tripwires are deployed and confirmed firing
- SPN accounts are inventoried with password age and encryption type; weak ones are on a remediation list
- The rules above are deployed, have fired in the lab ([Emulate → detect]({{ site.baseurl }}/labs/emulate-and-detect/)), and carry false-positive notes
- Backlog items exist for any phase the data did not support, each with a hypothesis id and the missing source

## Tabletop prompts

1. Which accounts can replicate the directory today, and how would we know within an hour if one of them was used from a workstation?
2. If a certificate were issued that authenticates as a domain admin, which log entry would show it, and who watches that log?
3. How many service accounts still use RC4 or a password older than a year, and which protect tier-0 systems?
4. Where do our domain admins log on from, and what would a logon to a random workstation look like in our data?
5. If `krbtgt` were compromised tonight, what is our detection story, and what is our recovery story?

## Hardening that shortens the next hunt

1. Tiered administration with separate admin accounts and privileged access workstations; domain admins never touch user endpoints
2. gMSA or long random passwords for every account with an SPN; remove unused SPNs; disable RC4 where feasible
3. Review and remediate AD CS template ACLs and enrolment permissions (the ESC1-ESC8 classes); enable CA auditing and require manager approval for sensitive templates
4. Restrict and monitor replication rights; alert on any `DS-Replication-Get-Changes` grant and on 4662 replication from non-DCs
5. Protect `AdminSDHolder`, the domain root and GPO objects with change alerting; review `SIDHistory` and delegation attributes regularly
6. LAPS for local administrator passwords; credential-guard and attack-surface-reduction rules that limit memory access to LSASS
7. Honey SPN and honey privileged accounts as zero-tuning tripwires

## Related

- Learn: [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/), [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/), [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/)
- Templates: [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card), [hunt report]({{ site.baseurl }}/templates/#hunt-report)
- Blog: [Pass-the-hash]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/), [Argon Dynamics case study]({{ site.baseurl }}/blog/argon-dynamics-case-study/)
- Cheat sheet: [Active Directory attacks]({{ site.baseurl }}/cheatsheets/active-directory-attacks/)
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) and the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/)
