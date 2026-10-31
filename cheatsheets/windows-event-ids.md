---
title: "Windows Security Event IDs for Hunters"
permalink: /cheatsheets/windows-event-ids/
excerpt: "The events that matter, what they mean, and which technique they expose."
---

> Events marked **(audit)** require the matching Advanced Audit Policy subcategory. See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/#windows-logging-that-must-be-enabled-it-is-not-by-default).

## Authentication and logon

| ID | Meaning | Hunting use |
|---|---|---|
| **4624** | Successful logon | Logon type, source IP, auth package, `LogonId` to link activity; lateral movement |
| **4625** | Failed logon | Brute force, password spray; `Status`/`SubStatus` codes below |
| **4634 / 4647** | Logoff / user-initiated logoff | Session duration |
| **4648** | Logon with explicit credentials | RunAs, PsExec `-u`, pass-the-hash tooling, lateral movement |
| **4672** | Special privileges assigned | Admin logons; new accounts with privileges |
| **4776** | NTLM credential validation (DC) | NTLM usage, spray against DCs |
| **4768** | Kerberos TGT requested | AS-REP roasting (pre-auth type 0), RC4 downgrade, unusual sources |
| **4769** | Kerberos service ticket requested | Kerberoasting (RC4 `0x17`), ticket requests by service |
| **4770 / 4771** | Ticket renewed / pre-auth failed | 4771 spikes = spray via Kerberos |
| **4778 / 4779** | RDP session reconnected / disconnected | RDP session tracing; `ClientName` and source |
| **4800 / 4801** | Workstation locked / unlocked | User presence |

### Logon types (4624/4625)

| Type | Name | Notes |
|---|---|---|
| 2 | Interactive | Console |
| 3 | Network | SMB, WinRM, many remote tools |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service start |
| 7 | Unlock | |
| 8 | NetworkCleartext | IIS basic auth, etc.; credential exposure |
| 9 | NewCredentials | `runas /netonly`; Mimikatz `sekurlsa::pth` |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Offline domain logon |

### Common failure codes (4625 `Status`/`SubStatus`)

| Code | Meaning |
|---|---|
| `0xC000006D` | Bad username or authentication info |
| `0xC000006A` | Right username, wrong password |
| `0xC0000064` | Username does not exist (spray or enumeration) |
| `0xC0000234` | Account locked out |
| `0xC0000072` | Account disabled |
| `0xC0000070` | Logon time restriction / workstation restriction |
| `0xC0000193` / `0xC0000071` | Account expired / password expired |

### Kerberos encryption types (4768/4769)

| Value | Cipher | Note |
|---|---|---|
| `0x17` | RC4-HMAC | Preferred by roasting tools; rare in modern AES-only estates |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | Normal |
| `0x11` | AES128-CTS-HMAC-SHA1-96 | Normal |
| `0x3` / `0x1` | DES-CBC-MD5 / DES-CBC-CRC | Legacy; investigate |

## Process, scheduled tasks and services

| ID | Meaning | Hunting use |
|---|---|---|
| **4688** | Process created **(audit; enable command line)** | Execution chains when Sysmon is absent |
| **4689** | Process exited | Duration of short-lived tools |
| **4698 / 4699 / 4700 / 4701 / 4702** | Scheduled task created / deleted / enabled / disabled / updated **(audit)** | Persistence, remote execution |
| **4697** | Service installed (Security) | Persistence, PsExec-like |
| **7045** (System) | New service installed | Same, higher coverage; image path |
| **7034 / 7036 / 7040** (System) | Service crashed / state change / start type changed | Tamper, defence evasion |

## Accounts and groups

| ID | Meaning |
|---|---|
| **4720** | User account created |
| **4722 / 4725** | Account enabled / disabled |
| **4723 / 4724** | Password change / reset attempt |
| **4726** | Account deleted |
| **4728 / 4729** | Member added / removed: global security group |
| **4732 / 4733** | Member added / removed: local security group (e.g. Administrators) |
| **4756 / 4757** | Member added / removed: universal group |
| **4738** | User account changed (e.g. `UserAccountControl` flags such as pre-auth off) |
| **4740** | Account locked out |
| **4767** | Account unlocked |
| **4794** | DSRM password set attempt |

## Directory service and Active Directory

| ID | Meaning | Hunting use |
|---|---|---|
| **4662** | Operation performed on an object **(audit)** | DCSync via replication GUIDs |
| **5136 / 5137 / 5141** | Directory object modified / created / deleted **(audit)** | ACL abuse, GPO tampering, AdminSDHolder changes, shadow credentials (`msDS-KeyCredentialLink`) |
| **4670** | Permissions on an object changed | Delegation backdoors |
| **4741 / 4742** | Computer account created / changed | RBCD, rogue machine accounts (`ms-DS-MachineAccountQuota` abuse) |
| **4928 / 4929** | AD replica source naming context established/removed | Rogue DC (DCShadow) |

## Network shares and object access

| ID | Meaning | Hunting use |
|---|---|---|
| **5140** | Network share accessed **(audit)** | `ADMIN$`, `C$`, `IPC$` access from unusual sources |
| **5145** | Network share object checked | File-level view; PsExec/payload copy to `ADMIN$` |
| **5142-5144** | Share created / modified / deleted | Staging shares |
| **4663 / 4656** | Object access attempt / handle requested | File/registry/LSASS SACL auditing |
| **4657** | Registry value modified | Persistence if SACL set |

## Policy, log and system integrity

| ID | Meaning |
|---|---|
| **1102** | Security log cleared |
| **104** (System) | Other event log cleared |
| **4719** | Audit policy changed (evasion) |
| **4616** | System time changed |
| **4624 + 4672 sequences** | Admin logon pairs for baselining |
| **6416** | New external device recognised (USB) |
| **4964** | Special groups assigned to new logon |
| **1100** | Event logging service shut down |

## Other logs worth ingesting

| Log | Highlights |
|---|---|
| `Microsoft-Windows-PowerShell/Operational` | 4104 script block, 4103 module logging |
| `Microsoft-Windows-WinRM/Operational` | 91, 168: WinRM session activity |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 1149: RDP auth succeeded (pre-logon), source IP |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 21, 22, 23, 24, 25: session logon/logoff/reconnect |
| `Microsoft-Windows-TaskScheduler/Operational` | 106, 140, 141, 200, 201: task registered/updated/removed/run |
| `Microsoft-Windows-WMI-Activity/Operational` | 5857, 5860, 5861: WMI provider load and event subscription activity |
| `Microsoft-Windows-Windows Defender/Operational` | 1116/1117 detections; 5001, 5007, 5010, 5012: tampering |
| `Microsoft-Windows-Bits-Client/Operational` | 3, 59, 60, 61: BITS jobs |
| `Microsoft-Windows-DNS-Client/Operational` | 3008, 3020: client DNS queries (without Sysmon) |
| `Microsoft-Windows-SMBServer/Security` | 1006, 1007...: SMB server security events |
| `Microsoft-Windows-Sysmon/Operational` | See [Sysmon sheet]({{ site.baseurl }}/cheatsheets/sysmon/) |

## Quick hunts by event

```text
Password spray       4625 (0xC000006A / 0xC0000064) from one source to many users; 4771 on DCs
Pass-the-hash        4624 type 3 NTLM, KeyLength 0; type 9 + seclogo
Kerberoasting        4769, 0x17, user-owned SPNs, many distinct SPNs per requester
DCSync               4662 with 1131f6aa-/1131f6ad-... GUIDs from non-DC
Remote exec (PsExec) 5145 ADMIN$ write -> 7045/4697 service -> child of services.exe
Scheduled task       4698 (Task XML shows command); 4699 deletion after use = cleanup
Log clearing         1102 / 104; 1100; 4719
Privilege change     4728/4732/4756 for admin groups; 4672 for new accounts
```
