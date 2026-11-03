---
title: "Windows Security Event IDs for Hunters"
excerpt: "The events that matter on Windows 11 and Server 2022/2025, the fields that carry the signal, the codes you decode mid-hunt, and the audit policy that has to be on first."
---

> Events marked **(audit)** are silent until the matching Advanced Audit Policy subcategory is enabled; the [Enable it](#enable-it) section at the end lists them. Field names are the XML `EventData` names (what Sentinel's `SecurityEvent` and Splunk's XmlWinEventLog use). See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/#windows-logging-that-must-be-enabled-it-is-not-by-default) for the collection side.

## Authentication and logon

| ID | Meaning | Hunting use (ATT&CK) |
|---|---|---|
| **4624** | Successful logon | The workhorse. Read `LogonType`, `IpAddress`, `WorkstationName`, `AuthenticationPackageName` (NTLM/Kerberos/Negotiate), `LogonProcessName` (`NtLmSsp`, `Kerberos`, `User32`, `seclogo` = runas/pth), `ElevatedToken` (`%%1842` yes, `%%1843` no), `TargetLogonId` to tie later activity to the session. Lateral movement, account misuse (T1021, T1078) |
| **4625** | Failed logon | Brute force and spray via `Status`/`SubStatus` (table below), `LogonType`, `IpAddress`. 4625 is logged on the machine that was targeted; sprays against DCs over NTLM show as 4776 instead (T1110) |
| **4634 / 4647** | Logoff / user-initiated logoff | Pair with 4624 on `TargetLogonId` for session duration; very short type-3 sessions in bulk = tooling |
| **4648** | Logon with explicit credentials | `runas`, PsExec `-u`, scheduled tasks under another identity, overpass-the-hash. `TargetUserName` is the account used, `SubjectUserName` who used it; a non-admin presenting admin creds is the signal (T1078, T1550) |
| **4672** | Special privileges assigned to new logon | Fires with every admin-equivalent 4624 (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`...). Baseline admin logons per host; first-time 4672 for an account = escalation (T1078.002) |
| **4776** | NTLM credential validation on the DC (or local SAM) | Where NTLM sprays and pass-the-hash land: `Workstation` is the source, `Status` carries the failure code; NTLM where Kerberos is expected (T1550.002, T1110) |
| **4768** | Kerberos TGT requested (AS-REQ) | `PreAuthType` 0 with `TicketEncryptionType` 0x17 = AS-REP roasting; `CertIssuerName`/`CertThumbprint` populated = PKINIT (AD CS or shadow-credential logon); unusual `IpAddress` for privileged accounts (T1558.004, T1649) |
| **4769** | Kerberos service ticket requested (TGS-REQ) | Kerberoasting: one `TargetUserName` requesting many `ServiceName` values with 0x17; silver-ticket hunts compare 4769 on the DC with 4624 on the service host (T1558.003, T1558.002) |
| **4770** | Service ticket renewed | Normal; abnormal renewal patterns hint at long-lived forged tickets |
| **4771** | Kerberos pre-authentication failed | Kerberos spray and lockout investigations: `Status` 0x18 bad password, 0x12 disabled/locked, `IpAddress` source (T1110) |
| **4778 / 4779** | RDP session reconnected / disconnected | `ClientName`, `ClientAddress` for RDP session tracing; combines with 4624 type 10 (T1021.001) |
| **4800 / 4801** | Workstation locked / unlocked | User presence; activity during a locked session is not the user |
| **4825** | RDP access denied (not in Remote Desktop Users) | Lateral-movement probing with low-priv accounts |
| **4964** | Special groups assigned to a new logon | Fires only if you configure Special Groups; cheap tripwire for tier-0 logons |

### Logon types (4624 / 4625 / 4634)

| Type | Name | What produces it |
|---|---|---|
| 2 | Interactive | Console or VNC-style keyboard logon |
| 3 | Network | SMB, WinRM, WMI, RPC, LDAP, IIS Windows auth; most lateral movement |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service start under an account |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Basic auth over IIS or PowerShell `-Authentication Basic`; credential exposure |
| 9 | NewCredentials | `runas /netonly`, Mimikatz `sekurlsa::pth`, Rubeus `createnetonly`; `LogonProcessName` is `seclogo` |
| 10 | RemoteInteractive | RDP, Remote Assistance |
| 11 | CachedInteractive | Domain logon with cached credentials, DC unreachable |
| 12 / 13 | CachedRemoteInteractive / CachedUnlock | Cached variants of 10 and 7 |

### Failure codes (4625 `Status`/`SubStatus`, 4776 `Status`)

| Code | Meaning | Read as |
|---|---|---|
| `0xC000006D` | Bad username or authentication information (wrapper) | Look at `SubStatus` |
| `0xC000006A` | Correct username, wrong password | Spray or brute force |
| `0xC0000064` | Username does not exist | Enumeration, spray with a guessed list |
| `0xC0000234` | Account locked out | Spray aftermath |
| `0xC0000072` | Account disabled | Attempts against stale accounts |
| `0xC000006F` / `0xC0000070` | Outside logon hours / workstation restriction | Policy, or an attacker using a restricted account |
| `0xC0000193` / `0xC0000071` | Account expired / password expired | Noise, unless clustered |
| `0xC000015B` | Logon type not granted | Service account used interactively, or blocked RDP |
| `0xC0000133` | Clock skew | Kerberos from a host with a bad clock, or a forged ticket |
| `0xC000035B` | NTLM authentication failed (SPN/MIC validation) | Relay attempts against hardened targets |

### Kerberos fields (4768 / 4769 / 4771)

| Field | Values | Note |
|---|---|---|
| `TicketEncryptionType` | `0x12` AES256, `0x11` AES128, `0x17` RC4-HMAC, `0x18` RC4-HMAC-EXP, `0x3` DES-CBC-MD5, `0x1` DES-CBC-CRC, `0xFFFFFFFF` on failure | Modern estates are AES; 0x17 for a user account is the roasting tell, DES means an ancient client or a forged ticket |
| `PreAuthType` (4768) | `0` none, `2` PA-ENC-TIMESTAMP (password), `11` PA-ETYPE-INFO, `15` PA-PK-AS-REP_OLD (older smart-card logon), `16` PA-PK-AS-REQ (PKINIT, certificate), `17` PA-PK-AS-REP, `138` PA-ENCRYPTED-CHALLENGE (FAST armouring) | `0` + success = AS-REP roastable account; `15`/`16` + an unusual `CertIssuerName` = certificate abuse (AD CS, shadow credentials) |
| `TicketOptions` | hex bitmask: `0x40000000` forwardable, `0x20000000` forwarded, `0x00800000` renewable, `0x00010000` canonicalize, `0x00000010` renewable-ok; Windows clients mostly send `0x40810010` or `0x40810000` | Uncommon combinations (for example `0x40800000`, `0x50800000`) are tool fingerprints; treat as a lead only |
| `Status` / `ResultCode` (4768, 4771, 4769) | `0x6` client not found (unknown user), `0x7` server not found (bad SPN), `0x12` client revoked (disabled or locked), `0x17` password expired, `0x18` pre-auth failed (bad password), `0x1F` integrity check failed, `0x20` ticket expired, `0x25` clock skew too great | `0x6` spikes = user enumeration (Kerbrute), `0x18` spikes = Kerberos spray, `0x25` from one host = forged ticket or broken clock |

## Process, scheduled tasks and services

| ID | Meaning | Hunting use (ATT&CK) |
|---|---|---|
| **4688** | Process created **(audit; enable command line)** | `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName`, `TokenElevationType` (`%%1936` full/UAC-off, `%%1937` elevated, `%%1938` limited), `MandatoryLabel`. Parent/child chains and LOLBins when Sysmon is absent (T1059, T1218). Without `CommandLine` it is nearly useless |
| **4689** | Process exited | `ExitStatus`; pair on `ProcessId` for lifetime of short-lived tools |
| **4696** | Primary token assigned to process | Token manipulation, rare (T1134) |
| **4697** | Service installed in the system **(audit: Security System Extension)** | `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`; PsExec-style services, binary paths in user-writable dirs (T1543.003, T1569.002) |
| **7045** (System) | New service installed | Same signal with no audit policy needed; `ImagePath`, `AccountName`; `cmd.exe /c` or `powershell` in the path = remote execution |
| **7034 / 7036 / 7040** (System) | Service crashed / entered state / start type changed | Defender or EDR service stopped or set to disabled (T1562.001); LSASS crash after a dump attempt |
| **4698 / 4699** | Scheduled task created / deleted **(audit: Other Object Access)** | `TaskName`, `TaskContent` (full XML: command, arguments, trigger, principal); creation then deletion within minutes = one-shot remote execution (T1053.005) |
| **4700 / 4701 / 4702** | Task enabled / disabled / updated | Updated tasks that now point at a new binary; disabled security tasks |
| **106 / 140 / 141 / 200 / 201** (TaskScheduler/Operational) | Task registered / updated / deleted / action started / action completed | Covers hosts without the Security audit; 200 names the exact executable that ran |

## Accounts and groups

| ID | Meaning | Hunting use (ATT&CK) |
|---|---|---|
| **4720** | User account created | `SamAccountName`, `UserAccountControl`, `SubjectUserName`; creation by a non-helpdesk account or on a workstation (T1136.001/.002) |
| **4722 / 4725** | Account enabled / disabled | Re-enabled stale accounts |
| **4723 / 4724** | Password change attempt (by user) / reset attempt (by admin) | Resets of privileged or service accounts outside change windows |
| **4726** | Account deleted | Cleanup after use |
| **4738** | User account changed | `UserAccountControl` deltas: pre-auth disabled (`%%2096`), password not required (`%%2082`), DES only, trusted for delegation (`%%2093`); `AllowedToDelegateTo`, `SidHistory`, `PrimaryGroupId` (T1098, T1558.004) |
| **4740 / 4767** | Account locked out / unlocked | `TargetUserName`, `TargetDomainName` = source host of the lockout |
| **4728 / 4729** | Member added / removed: security-enabled global group | Domain Admins is global: watch here (T1098) |
| **4732 / 4733** | Member added / removed: security-enabled local group | Local Administrators, Remote Desktop Users, Backup Operators |
| **4756 / 4757** | Member added / removed: security-enabled universal group | Enterprise Admins, Schema Admins |
| **4727 / 4730 / 4731 / 4734 / 4754 / 4758** | Group created / deleted | New groups that mimic admin names |
| **4741 / 4742 / 4743** | Computer account created / changed / deleted | Machine-account quota abuse (any user creating computers), `msDS-AllowedToActOnBehalfOfOtherIdentity` set (RBCD), `UserAccountControl` or `ServicePrincipalNames` changes on DC accounts (T1136.002, T1550) |
| **4781** | Account name changed | sAMAccountName spoofing: computer renamed to a DC name without `$` (CVE-2021-42278 pattern) |
| **4794** | DSRM administrator password set attempt | Persistence through the DSRM account; should be zero outside DC builds (T1098) |
| **4765 / 4766** | SID History added / add attempt failed | SIDHistory injection (T1134.005) |

## Directory service and Active Directory (DCs)

| ID | Meaning | Hunting use (ATT&CK) |
|---|---|---|
| **4662** | Operation performed on an AD object **(audit: Directory Service Access + SACL)** | DCSync: `Properties` containing `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes), `1131f6ad-...` (Get-Changes-All) or `89e95b76-444d-4c62-991a-0facbeda640c` (Get-Changes-In-Filtered-Set) from a `SubjectUserName` that is not a DC or Entra Connect account (T1003.006). Also reads of `msDS-ManagedPassword` (gMSA) and LAPS attributes |
| **5136** | Directory object modified **(audit: Directory Service Changes)** | `AttributeLDAPDisplayName` is the hunt key: `msDS-KeyCredentialLink` (shadow credentials, T1556), `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), `nTSecurityDescriptor` on AdminSDHolder or privileged objects (T1098), `gPCFileSysPath`/`versionNumber` on `groupPolicyContainer` (T1484.001), `servicePrincipalName` on users (targeted Kerberoast), `scriptPath`, `msDS-SupportedEncryptionTypes` |
| **5137 / 5141** | Directory object created / deleted | New objects in Configuration NC (`nTDSDSA`, `server` = DCShadow, T1207), new OUs or GPOs, deleted objects after abuse |
| **5138 / 5139** | Object undeleted / moved | Moves into less-audited OUs |
| **4670** | Permissions on an object changed | `ObjectName`, `OldSd`/`NewSd` SDDL; new ACEs on tier-0 objects, GenericAll/WriteDACL grants (T1222) |
| **4928 / 4929** | Replica source naming context established / removed | Rogue DC registration (DCShadow) |
| **4932 / 4933** | Replication started / ended | Replication from a source that is not a DC |
| **4886 / 4887 / 4888** (AD CS, on the CA) | Certificate request received / approved and issued / denied | `Requester`, `Attributes` (look for `SAN:` or `upn=` for another user: ESC1), `CertificateTemplate`; certs for privileged UPNs requested from non-tier-0 hosts (T1649) |
| **4889 / 4890 / 4891 / 4892** | Request set to pending / CA security changed / CA configuration changed / CA property changed | `EDITF_ATTRIBUTESUBJECTALTNAME2` flips (ESC6), new CA officers |
| **4896 / 4897** | Rows deleted from the CA database / role separation enabled | Cleanup of issued-cert evidence |
| **4898 / 4899 / 4900** | Template loaded / template updated / template security updated | Template edits that add Client Authentication EKU, enable enrollee-supplies-subject, or widen enrol rights (ESC4) |
| **1644** (Directory Service) | Expensive or inefficient LDAP search | Bulk LDAP recon (BloodHound, ADFind): `Client`, `Filter`, `Visited entries`. Enable with `Field Engineering = 5` and `Expensive Search Results Threshold` / `Inefficient Search Results Threshold` under `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` (T1087.002, T1482) |
| **2889** (Directory Service) | Unsigned or simple LDAP bind | Relay-prone clients; `Client IP`, `Identity` |
| **5827 / 5828 / 5829** (System, Netlogon) | Netlogon secure channel denied / vulnerable connection allowed | Zerologon-style abuse and machines still using RC4 secure channels (T1210) |

## Network shares and object access

| ID | Meaning | Hunting use (ATT&CK) |
|---|---|---|
| **5140** | Network share accessed **(audit: File Share)** | `ShareName` (`\\*\ADMIN$`, `\\*\C$`, `\\*\IPC$`, `\\*\SYSVOL`), `IpAddress`, `SubjectUserName`, `AccessMask`; one account touching many hosts' admin shares (T1021.002, T1135) |
| **5145** | Share object access checked **(audit: Detailed File Share)** | `RelativeTargetName` gives the file: `PSEXESVC.exe`, `*.exe` written to `ADMIN$`, `svcctl`/`srvsvc`/`samr`/`lsarpc`/`winreg` pipes over `IPC$`, `ntds.dit` on backup shares, reads of `.kdbx`/`id_rsa`/`web.config` (T1021.002, T1039). High volume on file servers, filter by `AccessMask` 0x2 (write) or by sensitive names |
| **5142 / 5143 / 5144** | Share created / modified / deleted | Staging shares, exposed `C$`-like shares on workstations |
| **5168** | SPN check for SMB/SMB2 failed | NTLM relay to SMB with signing (lead) |
| **4656 / 4658 / 4663** | Handle requested / handle closed / object accessed **(audit: File System, Registry, Kernel Object + SACL on the object)** | SACL-driven: LSASS handle requests (`ObjectName` ends `lsass.exe`, `AccessMask` 0x1010/0x1FFFFF), reads of honey files, SAM/SECURITY hive access (T1003). Nothing is logged without a SACL |
| **4657** | Registry value modified **(audit: Registry + SACL)** | Run keys, `Image File Execution Options`, Winlogon, services `ImagePath`, Defender exclusions (T1547.001, T1546.012, T1562.001) |
| **4670** | Permissions on an object changed | File or registry ACL loosened before abuse |
| **4660** | Object deleted | Paired with 4663 for evidence removal |
| **5379 / 5381 / 5382** | Credential Manager credentials read / Vault credentials read (two sources) | `cmdkey /list`, Mimikatz `vault::cred`, browser and RDP credential theft via DPAPI (T1555.004) |
| **4673 / 4674** | Privileged service called / operation on a privileged object | `SeDebugPrivilege` use by non-debuggers, `SeTcbPrivilege`; noisy, filter by privilege and process (T1134) |

## Policy, log and system integrity

| ID | Meaning | Hunting use (ATT&CK) |
|---|---|---|
| **1102** | Security log cleared | Always investigate; `SubjectUserName` is who did it (T1070.001) |
| **104** (System) | Other event log cleared | System/Application/PowerShell logs wiped |
| **1100** | Event logging service shut down | Outside clean shutdowns = tamper |
| **1104 / 1105** | Security log full / automatic backup | Log flooding to roll evidence |
| **4719** | System audit policy changed | `SubcategoryGuid`, `AuditPolicyChanges` (`%%8448` success removed, `%%8450` failure removed); auditing switched off before action (T1562.002) |
| **4817** | Auditing settings on an object changed | SACL removed from LSASS or a honey object |
| **4904 / 4905** | Security event source registered / unregistered | Rare; source tampering |
| **4616** | System time changed | `PreviousTime`/`NewTime`, `ProcessName`; timestomping of logs, Kerberos manipulation (T1070.006) |
| **4826** | Boot configuration data loaded | `TestSigning`, `DisableIntegrityChecks`, `HypervisorDebug`; BYOVD and Safe-Mode tricks (T1553, T1562) |
| **4697 / 4702 / 4719 / 1102 within minutes** | Classic evasion sequence | Stack by host |
| **6416** | New external device recognised | `DeviceDescription`, `ClassName`; USB storage and HID devices on servers (T1091, T1200) |
| **5038 / 6281** | Code integrity: image hash invalid / page hashes invalid | Tampered or unsigned system files, bootkits (T1014) |
| **4608 / 4609** | Windows starting up / shutting down | Reboot after persistence install |

## Other logs worth ingesting

| Log (channel) | IDs | Why |
|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | **4104** script block (content, `ScriptBlockText`, `Path`), **4103** module logging (parameters), **4105/4106** script start/stop; classic **400/403** engine state, **800** pipeline execution in `Windows PowerShell` | Encoded commands, AMSI bypass strings, download cradles; 4104 level Warning fires automatically for suspicious blocks even without the policy (T1059.001). Enable Script Block Logging and Module Logging; transcription to a write-only share for full text |
| `Microsoft-Windows-WinRM/Operational` | **91** session created (server), **142** request failed, **168** session created by user, **169** user authenticated, **6** WSMan session init (client) | Remote PowerShell: pair 91/168 on the target with 4104 on the target and 4624 type 3 `wsmprovhost.exe` children (T1021.006) |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | **1149** network-layer authentication succeeded | Earliest RDP evidence with `Source Network Address`, fires before 4624 (T1021.001) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | **21** session logon, **22** shell start, **23** logoff, **24** disconnected, **25** reconnected, **39/40** session arbitration | RDP session timeline per `Session ID` and source address |
| `Microsoft-Windows-TaskScheduler/Operational` | 106, 140, 141, 200, 201 | See above; off by default on Server, enable the channel |
| `Microsoft-Windows-WMI-Activity/Operational` | **5857** provider loaded, **5858** query error, **5859** permanent subscription started, **5860** temporary subscription, **5861** permanent subscription created (shows filter and consumer) | WMI persistence and remote WMI execution; 5861 is the one to alert on (T1546.003, T1047) |
| `Microsoft-Windows-Windows Defender/Operational` | **1006/1007/1015** malware detected / action taken / suspicious behaviour, **1116/1117/1118/1119** detection / action succeeded / failed / critically failed, **5001** real-time protection disabled, **5004** RTP configuration changed, **5007** configuration changed (exclusions), **5010/5012** scanning for malware/scripts disabled, **5013** tamper protection blocked a change, **1121/1122** ASR block/audit, **2050/2051** sample submission | Defender tampering and the attacks it caught but you ignored (T1562.001) |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | **2004** rule added, **2005** rule modified, **2006** rule deleted, **2033** all rules deleted, **4946-4950** (Security) | New allow rules for RDP, SMB or a C2 port (T1562.004) |
| `Microsoft-Windows-AppLocker/EXE and DLL`, `/MSI and Script`, `/Packaged app-*` | **8002** allowed, **8003** audit-would-block, **8004** blocked, **8005/8006/8007** script allowed/audit/blocked | Audit-mode output is a free execution inventory (T1218, T1059) |
| `Microsoft-Windows-CodeIntegrity/Operational` (WDAC, LSA protection) | **3076** audit: would be blocked, **3077** blocked, **3089** signature info, **3033** driver or process blocked by policy, **3065/3066** LSA protection: plug-in failed signing requirements (audit/enforce) | Unsigned drivers and binaries, BYOVD, attempts to load code into protected LSASS (T1068, T1553.006, T1003.001) |
| `Microsoft-Windows-NTLM/Operational` | **8001** outgoing NTLM to a remote server, **8002** incoming NTLM, **8003** NTLM to the domain, **8004** NTLM audited/blocked by policy | Requires `Restrict NTLM: Audit...` policies; relay, PtH and legacy-protocol inventory (T1557.001, T1550.002) |
| `Microsoft-Windows-Bits-Client/Operational` | **3** job created, **59** transfer started (URL), **60** transfer completed, **61** transfer failed, **4** job completed | `bitsadmin`/`Start-BitsTransfer` downloads with the full URL (T1197, T1105) |
| `Microsoft-Windows-DNS-Client/Operational` | **3008** query completed (`QueryName`, `QueryResults`), **3020** response | Process-less DNS when Sysmon 22 is absent; analytic channel must be enabled and is noisy (T1071.004) |
| `Microsoft-Windows-Kernel-PnP/Configuration` | **400/410** device configured / started | USB device history with VID/PID, complements 6416 (T1091) |
| `Microsoft-Windows-Security-Mitigations/KernelMode` and `/UserMode` | **10-23** exploit-protection blocks (ACG, CFG, child-process, image load) | Exploit attempts and injection blocked by Exploit Protection (T1055, T1203) |
| `Microsoft-Windows-Sysmon/Operational` | 1-29 | See the [Sysmon sheet]({{ site.baseurl }}/cheatsheets/sysmon/) |

## Quick hunts by event

| Hunt | Events and query idea | Playbook |
|---|---|---|
| Password spray | 4625 with `SubStatus` 0xC000006A or 0xC0000064, one `IpAddress`, many `TargetUserName`, few tries each; 4771 0x18 and 4776 on DCs for the Kerberos/NTLM variants | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) (spray section), [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| Pass-the-hash | 4624 `LogonType` 3, `AuthenticationPackageName` NTLM, `KeyLength` 0, `LogonProcessName` `NtLmSsp` from a workstation to many servers; 4624 type 9 `seclogo` on the source | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| Kerberoasting | 4769 `TicketEncryptionType` 0x17, `ServiceName` not ending `$`, dcount(`ServiceName`) per `TargetUserName` per 10 min | [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| AS-REP roasting | 4768 `PreAuthType` 0, 0x17, `TargetUserName` with `DONT_REQ_PREAUTH` | [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| DCSync | 4662 `Properties` has `1131f6aa` or `1131f6ad`, `SubjectUserName` not a DC `$` account or Entra Connect | [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| Shadow credentials / RBCD | 5136 `AttributeLDAPDisplayName` in (`msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity`) by a non-sync account, then 4768 `PreAuthType` 15/16 | [AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/), [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| ESC1 certificate abuse | 4886/4887 `Attributes` contains `SAN:` or `upn=` for a user other than `Requester`, template with enrollee-supplies-subject | [AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) |
| PsExec-style remote execution | 5145 `ShareName` `ADMIN$`, `RelativeTargetName` `*.exe`, `AccessMask` 0x2, then 7045/4697 on the target, service child of `services.exe` | [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| Remote scheduled task | 4698 with `TaskContent` command in a user-writable path, `SubjectLogonId` from a type-3 session; 4699 within minutes | [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| WMI persistence | 5861 with `CommandLineEventConsumer` or `ActiveScriptEventConsumer`; 5859/5860 bursts | [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| RDP from the inside | 1149 then 21/22 with `Source Network Address` internal, stack by source; 4778/4779 reconnects at odd hours | [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| WinRM lateral movement | 91/168 on the target, 4624 type 3 with `wsmprovhost.exe` children in 4688, 4104 on the target | [RDP & WinRM anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| Defender tampering | 5001, 5007 (`Exclusions\Paths` or `Processes` added), 5010/5012, 5013 blocked attempts; 7036 Defender service stopped | [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| Log clearing and audit tampering | 1102, 104, 1100, 4719 with `%%8448`/`%%8450`, 4817 on LSASS or honey objects | [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| Privilege group changes | 4728/4732/4756 where `TargetUserName` is an admin group; 4672 first-seen per account | [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) (what precedes it) |
| Ransomware precursors | 7036 for backup/AV services stopping, 4697 new services from `C:\Users` or `C:\ProgramData`, 5140 bursts across many hosts by one account | [Ransomware precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |

## Enable it

Nothing above fires on a default install except the basics. Set the **Advanced Audit Policy** (Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration) and force it with *Audit: Force audit policy subcategory settings to override audit policy category settings*.

| Section above | Subcategories (Success unless noted) |
|---|---|
| Authentication and logon | Logon/Logoff: Logon (S+F), Logoff, Special Logon, Other Logon/Logoff Events; Account Logon: Credential Validation (S+F), Kerberos Authentication Service (S+F), Kerberos Service Ticket Operations (S+F) on DCs |
| Process, tasks, services | Detailed Tracking: Process Creation, Process Termination; Object Access: Other Object Access Events (tasks); System: Security System Extension (4697) |
| Accounts and groups | Account Management: User Account Management, Computer Account Management, Security Group Management, Other Account Management Events |
| Directory service | DS Access: Directory Service Access (4662; needs SACLs, default SACL covers replication), Directory Service Changes (5136-5141) |
| Shares and object access | Object Access: File Share, Detailed File Share (5145, heavy), File System, Registry, Kernel Object (LSASS), Handle Manipulation off (too noisy) |
| Policy and integrity | Policy Change: Audit Policy Change, Authentication Policy Change, Authorization Policy Change; System: Security State Change, System Integrity, Other System Events |

- **Command line in 4688**: Computer Configuration > Administrative Templates > System > Audit Process Creation > *Include command line in process creation events* = Enabled (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`). 4688 without it tells you `cmd.exe` ran and nothing else.
- **PowerShell**: Administrative Templates > Windows Components > Windows PowerShell: *Turn on Module Logging* (`*`), *Turn on PowerShell Script Block Logging*, *Turn on PowerShell Transcription*; PowerShell 7 reads the same policies from its own key.
- **Sizes**: Security log 1 GB or more on DCs and servers, 256 MB on workstations; forward with WEF or an agent rather than relying on local retention.
- **Verify**: `auditpol /get /category:*` on a sample of hosts, then confirm the events actually arrive in the SIEM (a query on a missing log is not a negative result).
