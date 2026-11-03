---
title: "Hunt Hypothesis Library"
permalink: /hunt/hypotheses/
excerpt: "A ready-to-use backlog of 122 testable hunt hypotheses, grouped by ATT&CK tactic, each with the data it needs, the analytical technique and the playbook that runs it."
classes: wide
toc: true
toc_sticky: true
---

A hunt team runs out of ideas faster than it runs out of time. This page is a backlog you can pull from: every row is a hypothesis in the form *"If X is occurring, then we would see Y in Z"*, mapped to ATT&CK, the data it needs, the analytical technique that fits it, and the Hunt-Sage playbook that already contains the queries where one exists.

Each hypothesis is numbered (`H-001` ...) so you can reference it in tickets and hunt reports. Before you run one, copy it into the [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card) and fill in scope, success/failure criteria and time-box; the card is the thing that gets tracked, not this page.

## How to pick from the library

Do not start at H-001 and work down. Choose by one of three lenses, then score with the prioritisation table in [Hypotheses & threat intelligence]({{ site.baseurl }}/learn/hypotheses-and-intelligence/).

| Lens | Question | Pick hypotheses that... |
|---|---|---|
| **Crown jewels** | Which five systems or identities would hurt most if lost? | ...sit on the path to them: Credential Access, Lateral Movement, Cloud/Identity for the tier-0 accounts, Impact for the backup infrastructure |
| **Intel** | What did the last three relevant reports (sector ISAC, CISA, vendor DFIR) describe? | ...match the ATT&CK IDs in the report; run IOC sweeps in parallel but hunt the behaviour |
| **Coverage gaps** | Which techniques on the [coverage map]({{ site.baseurl }}/research/mitre-mapping/) have no detection and no recent hunt? | ...cover those techniques, provided the data exists; if it does not, the output is a visibility finding rather than a hunt |

A mixed quarter works well: two-thirds from crown jewels and intel, one-third from coverage gaps so the map keeps improving.

### Sizing a hunt

| Size | Time-box | Typical shape | Examples |
|---|---|---|---|
| **Small** | 2-4 hours | One data source, one or two queries, stack or search | H-031 (log clearing), H-046 (honey SPN), H-087 (Entra consent grants) |
| **Medium** | 1-2 days | Two data sources, baseline against 30 days, triage of a long tail | H-012 (rare parent/child), H-057 (first-time logon pairs), H-069 (beacon timing) |
| **Large** | 3-5 days | Cross-source correlation, scripted enrichment, fleet-wide clustering | H-016 (fleet persistence stacking), H-071 (DNS tunnelling), H-090 (CloudTrail from new ASN) |

If a hypothesis cannot be finished inside its box, split it. "Hunt for lateral movement" is a programme; "find accounts with type-3 logons to more than ten servers in an hour" is a hunt. The library is written at the second level deliberately.

### Reading the tables

- **Technique** is the analytical method from [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/): *search* (known pattern), *stack* (frequency / long tail), *baseline* (compare now with a known-good period), *cluster* (group by attributes and look at outliers), *timing* (intervals, sequences, bursts), *honeytoken* (planted object; any touch is a hit).
- **Data needed** uses the same source names as the playbooks. Verify coverage first with the checklist in [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/); a negative result on a missing log is not a result.
- **Playbook** links to the playbook whose queries run this hypothesis. `-` means you will write the queries yourself; the [query index]({{ site.baseurl }}/hunt/query-index/) has the reusable patterns.

<div class="hs-filter" data-hs-filter data-placeholder="Filter hypotheses: H-012, T1059, kerberos, honeytoken, m365-audit..."></div>

## Initial Access

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-001 | If users are opening malicious attachments, then we would see Office or PDF reader processes spawning script hosts, LOLBins or binaries from user-writable paths in EDR/Sysmon process creation (Sysmon 1, 4688 with command line). | T1566.001, T1204.002 | edr, sysmon | stack | [initial-access-phishing]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) |
| H-002 | If phishing links are being clicked, then we would see browser downloads of archive, ISO, LNK or HTA files followed within five minutes by a process launched from `Downloads` or `%TEMP%`. | T1566.002, T1204.001 | edr, proxy, sysmon | timing | [initial-access-phishing]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) |
| H-003 | If an internet-facing application has been exploited, then we would see the web server worker process (`w3wp.exe`, `httpd`, `tomcat`, `nginx` workers) spawning `cmd`, `powershell`, `sh` or `whoami`. | T1190 | edr, sysmon, iis | search | [web-shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) |
| H-004 | If a web shell has been dropped, then we would see newly written `.aspx`, `.jsp`, `.php` or `.ashx` files under web roots (Sysmon 11, FIM) that no deployment pipeline wrote. | T1505.003 | sysmon, iis | baseline | [web-shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) |
| H-005 | If external remote services are being abused with stolen credentials, then we would see VPN or RDP gateway logons from countries, ASNs or devices that account has never used, or from two distant locations within an hour. | T1133, T1078 | vpn, windows-security, entra-id | baseline | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-006 | If a vendor's remote access is compromised, then we would see vendor accounts authenticating outside their contracted hours or to hosts outside their support scope. | T1199, T1078 | windows-security, vpn | baseline | - |
| H-007 | If removable media is a delivery vector, then we would see processes executing from drive letters other than the system volume, or `autorun`-style `.lnk` launches shortly after a USB device arrival event (Event 6416, Sysmon 1). | T1091 | windows-security, sysmon | timing | - |

## Execution

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-008 | If PowerShell is being used for post-exploitation, then we would see encoded commands (`-enc`, `-EncodedCommand`), `IEX`, `DownloadString` or `FromBase64String` in 4104 script blocks and process command lines. | T1059.001 | powershell, edr | search | [powershell-abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) |
| H-009 | If attackers are living off the land, then we would see `mshta`, `regsvr32`, `rundll32`, `certutil`, `msbuild` or `installutil` with network-looking arguments or executing from user-writable paths, and the pairing would be rare across the fleet. | T1218, T1105, T1127 | edr, sysmon | stack | [lolbin-proxy-execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) |
| H-010 | If `wscript`/`cscript` are being used to run droppers, then we would see them executing `.js`, `.vbs` or `.wsf` files from `%TEMP%`, `%APPDATA%` or `Downloads`, with Office or a browser as the grandparent. | T1059.005, T1059.007 | edr, sysmon | search | [initial-access-phishing]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) |
| H-011 | If an implant is executing commands, then we would see `cmd.exe` or `powershell.exe` with a parent that never normally spawns a shell (`winword.exe`, `outlook.exe`, `svchost.exe`, `spoolsv.exe`, `w3wp.exe`). | T1059.003 | edr, sysmon | stack | [lolbin-proxy-execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) |
| H-012 | If unknown tooling is running, then we would see parent/child process pairs that occur on fewer than three hosts in 30 days when stacked by (parent name, child name) across the fleet. | T1059, T1204 | edr, sysmon | stack | - |
| H-013 | If WMI is being used for remote execution, then we would see `wmiprvse.exe` spawning `cmd`, `powershell` or scripts, and on the source host `wmic.exe` with `/node:` or `process call create`. | T1047 | edr, sysmon | search | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| H-014 | If the ScheduledTasks or Services APIs are being used to execute payloads, then we would see tasks or services whose action is a script host, LOLBin or binary in a user-writable path (4698, 7045). | T1053.005, T1569.002 | windows-security, sysmon | stack | [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| H-015 | If obfuscated commands are being run, then we would see command lines longer than 1,000 characters, or with character-frequency anomalies (carets, excessive `+` concatenation, `^`, backtick padding), from non-developer hosts. | T1027, T1059 | edr, sysmon | cluster | [powershell-abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) |

## Persistence

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-016 | If persistence has been planted, then we would see run-key values, scheduled task actions and service image paths that exist on fewer than three hosts in the fleet when stacked by command (Sysmon 12/13, 4698, 7045). | T1547.001, T1053.005, T1543.003 | sysmon, windows-security | stack | [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| H-017 | If WMI event subscriptions are being used, then we would see `__EventFilter`, `__EventConsumer` and `__FilterToConsumerBinding` creation (Sysmon 19/20/21) outside SCCM and monitoring agents. | T1546.003 | sysmon | search | [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| H-018 | If a DLL search-order or phantom-DLL hijack is in place, then we would see a signed Microsoft binary loading an unsigned DLL from the binary's own directory or a user-writable path (Sysmon 7, `DeviceImageLoadEvents`). | T1574.001 | sysmon, edr | stack | [dll-hijacking]({{ site.baseurl }}/hunt/playbooks/dll-hijacking/) |
| H-019 | If an attacker has created a local account for backup access, then we would see 4720 followed by 4732 to Administrators or Remote Desktop Users on a workstation or server, by a non-provisioning account. | T1136.001 | windows-security | timing | [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| H-020 | If Accessibility Features or IFEO are hijacked, then we would see `Debugger` values under `Image File Execution Options` for `sethc.exe`, `utilman.exe`, `osk.exe` etc. (Sysmon 13), or those binaries spawning `cmd.exe` on the logon screen. | T1546.008, T1546.012 | sysmon | search | [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| H-021 | If a web shell is persisting on a server, then we would see the web worker process making outbound connections or reading files outside the web root, days after an initial drop. | T1505.003 | edr, iis, sysmon | baseline | [web-shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) |
| H-022 | If a Startup-folder or logon-script persistence exists, then we would see new files in `Start Menu\Programs\Startup` or `UserInitMprLogonScript` values set (Sysmon 11/13) on hosts where that has never happened before. | T1547.001, T1037.001 | sysmon | baseline | [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/) |
| H-023 | If an attacker holds a privileged AD account, then we would see new or modified `msDS-AllowedToDelegateTo`, `AdminSDHolder` ACL changes or `SIDHistory` additions (5136, 4738, 4765/4766) by non-provisioning accounts. | T1098, T1134.005 | windows-security | search | [dcsync]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| H-024 | If a mailbox has been backdoored, then we would see new inbox rules that forward, delete or move messages matching security or finance keywords (`New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`) in the M365 audit log. | T1137.005, T1114.003 | email | stack | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |

## Privilege Escalation

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-025 | If UAC bypasses are being used, then we would see `fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe` or `sdclt.exe` with a high-integrity child, or `ms-settings` / `mscfile` shell-open registry values written under HKCU (Sysmon 13). | T1548.002 | sysmon, edr | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-026 | If a vulnerable certificate template (ESC1/ESC2) is being abused, then we would see 4886/4887 certificate requests with a supplied SAN for a different, privileged principal, then 4768 with certificate pre-authentication for that principal. | T1649 | adcs, windows-security | search | [adcs-abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) |
| H-027 | If token manipulation is being used, then we would see processes running as SYSTEM whose parent is a user-context process, or 4624 logon type 9 (NewCredentials) events clustered on one host. | T1134.001, T1134.002 | windows-security, edr | cluster | [process-injection]({{ site.baseurl }}/hunt/playbooks/process-injection/) |
| H-028 | If a named-pipe impersonation (potato-family) escalation occurred, then we would see `CreateNamedPipe` for unusual pipe names (Sysmon 17/18) immediately followed by a SYSTEM-level child of the same process. | T1134.001 | sysmon | timing | [process-injection]({{ site.baseurl }}/hunt/playbooks/process-injection/) |
| H-029 | If a service is being hijacked for escalation, then we would see `ImagePath` or `binPath` changes to existing services (Sysmon 13, 7040) pointing at a user-writable path, or unquoted-path services receiving a new executable in the path's prefix directory. | T1574.011, T1574.009 | sysmon, windows-security | search | [dll-hijacking]({{ site.baseurl }}/hunt/playbooks/dll-hijacking/) |
| H-030 | If downloaded tools are being used for escalation, then we would see executables in user-writable paths with a `Zone.Identifier` ADS (Sysmon 15) that later run elevated (`IntegrityLevel == High` or `System`). | T1068, T1204.002 | sysmon, edr | timing | - |
| H-102 | If a UAC bypass is in use, then we would see an auto-elevated binary (fodhelper, computerdefaults, sdclt, eventvwr) spawn a shell or LOLBin at High integrity whose parent chain ran at Medium integrity. | T1548.002 | edr, sysmon | search | [uac-bypass]({{ site.baseurl }}/hunt/playbooks/uac-bypass/) |
| H-103 | If a shell-handler UAC bypass is in use, then we would see a write to an `open\command` or `DelegateExecute` value under `HKCU\Software\Classes\` seconds before an auto-elevated binary runs, often followed by deletion of the key. | T1548.002, T1112 | sysmon, edr | timing | [uac-bypass]({{ site.baseurl }}/hunt/playbooks/uac-bypass/) |
| H-104 | If UAC is being weakened to ease elevation, then we would see `EnableLUA` or `ConsentPromptBehaviorAdmin` set to 0 outside a change window. | T1548.002, T1112 | sysmon, windows-security | search | [uac-bypass]({{ site.baseurl }}/hunt/playbooks/uac-bypass/) |

## Defense Evasion

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-031 | If logs are being cleared, then we would see 1102 (Security log cleared) or 104 (System/Application log cleared), `wevtutil cl` or `Clear-EventLog` command lines, outside planned maintenance. | T1070.001 | windows-security, edr | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-032 | If security tooling is being disabled, then we would see Defender tamper events (5001, 5010, 5012), `Set-MpPreference -Disable*`, `Add-MpPreference -ExclusionPath`, or stops of EDR/AV services (7036, 7040) by non-management accounts. | T1562.001 | windows-security, windefend, edr | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-033 | If binaries are being renamed to evade name-based detections, then we would see process creations where `OriginalFileName` (PE header) does not match the on-disk file name for known tools (`powershell.exe`, `rundll32.exe`, `psexec`, `rclone`). | T1036.003 | edr, sysmon | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-034 | If attackers are masquerading as system processes, then we would see `svchost.exe`, `lsass.exe`, `csrss.exe` or `services.exe` running from a path other than `System32`, or with the wrong parent. | T1036.005 | edr, sysmon | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-035 | If process injection is occurring, then we would see `CreateRemoteThread` (Sysmon 8) or process-access with `0x1F0FFF`/`0x1F3FFF` masks (Sysmon 10) from a source that is not a debugger, AV or injector we have documented. | T1055 | sysmon, edr | stack | [process-injection]({{ site.baseurl }}/hunt/playbooks/process-injection/) |
| H-036 | If hollowed or injected processes are beaconing, then we would see network connections initiated by processes that have no business talking externally (`notepad.exe`, `werfault.exe`, `dllhost.exe`, `searchprotocolhost.exe`). | T1055, T1071 | edr, sysmon | stack | [process-injection]({{ site.baseurl }}/hunt/playbooks/process-injection/) |
| H-037 | If ETW or AMSI are being patched or disabled, then we would see 4104 script blocks referencing `AmsiScanBuffer`, `amsiInitFailed`, `EtwEventWrite`, or registry changes to `COMPlus_ETWEnabled` and the PowerShell `EnableScriptBlockLogging` policy keys. | T1562.006, T1562.002 | powershell, sysmon | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-038 | If timestomping is being used, then we would see Sysmon 2 (file creation time changed) events for executables and scripts, from processes other than installers and backup agents. | T1070.006 | sysmon | stack | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-039 | If an attacker is hiding in signed-but-abusable tooling, then we would see remote-management binaries (`AnyDesk`, `ScreenConnect`, `Atera`, `TeamViewer`) on hosts where IT has not deployed them, stacked by host count. | T1219 | edr | stack | - |

## Credential Access

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-040 | If LSASS is being dumped, then we would see process access to `lsass.exe` with `GrantedAccess` containing `0x1010`, `0x1038`, `0x1fffff` or `0x1410` (Sysmon 10) from a non-AV, non-EDR source process. | T1003.001 | sysmon, edr | stack | [lsass-credential-dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) |
| H-041 | If LSASS is dumped via a legitimate tool, then we would see `procdump`, `rundll32 comsvcs.dll MiniDump`, `taskmgr.exe` or Werfault writing a `.dmp` file whose name or content relates to `lsass` (Sysmon 11). | T1003.001 | sysmon, edr | search | [lsass-credential-dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) |
| H-042 | If the SAM or NTDS is being stolen, then we would see `reg save hklm\sam`, `ntdsutil "ifm"`, `vssadmin create shadow` or `esentutl /y` command lines, or 4663 reads of `ntds.dit` by non-system accounts. | T1003.002, T1003.003 | edr, windows-security | search | [lsass-credential-dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) |
| H-043 | If Kerberoasting is occurring, then we would see one account requesting 4769 service tickets for five or more distinct user-owned SPNs within ten minutes, often with encryption type 0x17. | T1558.003 | windows-security | timing | [kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| H-044 | If AS-REP roasting is occurring, then we would see 4768 with `PreAuthType 0` and RC4 for accounts that do not require pre-authentication, from a source that does not normally authenticate as them. | T1558.004 | windows-security | search | [kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| H-045 | If DCSync is being performed, then we would see 4662 with replication GUIDs (`1131f6aa`, `1131f6ad`, `89e95b76`) from an account that is not a DC computer account or the Entra Connect service account. | T1003.006 | windows-security | search | [dcsync]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| H-046 | If anyone is Kerberoasting or enumerating SPNs, then we would see any 4769 or 4662 touch on a honey SPN account that has no legitimate use. | T1558.003 | windows-security | honeytoken | [kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| H-047 | If password spraying is underway, then we would see 4625 or 4771 failures for many distinct accounts from one source with one or two attempts each, in a burst, followed by a 4624 success for one of them. | T1110.003 | windows-security, entra-id | timing | [rdp-winrm-anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| H-048 | If credentials are being harvested from browsers or vaults, then we would see non-browser processes reading `Login Data`, `logins.json`, `Cookies` or `vaultcli.dll` loads, and `cmdkey /list` or `vaultcmd /listcreds` command lines. | T1555.003, T1555.004 | sysmon, edr | search | - |
| H-049 | If certificates are being used as credentials, then we would see 4887 issuance of client-authentication certificates to accounts that have never requested one, then 4768 with `CertIssuerName` populated from new hosts. | T1649, T1550 | adcs, windows-security | baseline | [adcs-abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) |
| H-050 | If credentials are being phished internally via a captive page or LLMNR/NBT-NS poisoning, then we would see 4648 explicit-credential logons to hosts that are not servers, or NTLMv2 authentication (4624 with `AuthenticationPackageName NTLM`) to a workstation from many peers. | T1557.001 | windows-security | stack | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |

## Discovery

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-051 | If an attacker is enumerating AD, then we would see BloodHound/SharpHound indicators: LDAP queries for all users, groups, sessions and ACLs in a short window (1644 or LDAP telemetry), or `-CollectionMethod`, `Invoke-BloodHound`, `SharpHound` in command lines and 4104. | T1087.002, T1069.002, T1482 | windows-security, edr, powershell | timing | [ad-discovery-bloodhound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) |
| H-052 | If post-exploitation recon is running, then we would see three or more of `whoami`, `net user`, `net group`, `nltest`, `ipconfig /all`, `systeminfo`, `tasklist`, `quser` from the same process tree within two minutes. | T1033, T1087, T1016, T1082 | edr, sysmon | timing | [ad-discovery-bloodhound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) |
| H-053 | If network scanning is underway from a compromised host, then we would see one internal source connecting to more than 50 distinct internal hosts on 445, 3389, 5985 or 22 within ten minutes, with mostly failed or reset connections. | T1046 | firewall, zeek, edr | cluster | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| H-054 | If shares are being enumerated for staging or spread, then we would see 5140/5145 access to `IPC$` and `ADMIN$` on many hosts from one account in a burst, or `net view /all` and `Get-SmbShare` across hosts. | T1135, T1018 | windows-security, edr | stack | [ransomware-precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| H-055 | If an attacker is looking for high-value sessions, then we would see 4624 logon type 3 to many hosts with no file access (session enumeration via `NetSessionEnum`/`NetWkstaUserEnum`), by an account that is not a monitoring service. | T1033, T1049 | windows-security | stack | [ad-discovery-bloodhound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) |
| H-056 | If security tooling is being enumerated, then we would see `tasklist /svc`, `sc query`, `Get-MpComputerStatus`, `wmic /namespace:\\root\SecurityCenter2` or `fltmc` in command lines from non-admin users. | T1518.001 | edr, sysmon | search | [defense-evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) |
| H-105 | If an adversary is locating data, then we would see one account enumerate or access an unusually large number of distinct shares or servers within an hour versus its 45-day baseline. | T1135, T1021.002 | windows-security, zeek | baseline | [network-share-discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |
| H-106 | If share-enumeration tooling is being run, then we would see three or more `net view`, `net share`, `Find-DomainShare`, SharpShares or Snaffler commands from one host in 15 minutes. | T1135, T1083 | edr, sysmon | stack | [network-share-discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |
| H-107 | If data on shares is being collected, then we would see reads of sensitive file types (`.kdbx`, `id_rsa`, `web.config`, `unattend.xml`, `NTDS.dit`) in 5145 detailed file-share events. | T1039, T1083 | windows-security | search | [network-share-discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |
| H-108 | If an intruder is sweeping shares, then we would see any access (5140/5145) to a decoy share that no business process uses. | T1135, T1039 | windows-security | honeytoken | [network-share-discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |

## Lateral Movement

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-057 | If an account is moving laterally, then we would see a user account producing 4624 logon type 3 or 10 on a host it has never logged on to in the previous 30 days, especially where the (user, host) pair is new for both sides. | T1021 | windows-security | baseline | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| H-058 | If pass-the-hash is in use, then we would see 4624 logon type 9 with `seclogo` logon process, or type 3 NTLM logons from a workstation to many servers without a preceding 4768 TGT from that source. | T1550.002 | windows-security | timing | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| H-059 | If RDP is being used for hands-on-keyboard movement, then we would see 4624 type 10 or 1149 `RemoteConnectionManager` from workstation-to-workstation, from a jump host at unusual hours, or chains of RDP hops within one session (A → B → C in under 30 minutes). | T1021.001 | windows-security | timing | [rdp-winrm-anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| H-060 | If WinRM/PSRemoting is being abused, then we would see `wsmprovhost.exe` as a parent of shells on hosts where remoting is not part of administration, or 5985/5986 connections from non-management subnets. | T1021.006 | edr, windows-security, firewall | stack | [rdp-winrm-anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |
| H-061 | If PsExec-style tooling is in use, then we would see 7045 service installs with random names or `PSEXESVC`, writes to `ADMIN$` followed by a service start (5145 then 7045 within 30 seconds), and named pipes like `\PSEXESVC`, `\paexec`, `\csexec` (Sysmon 17). | T1021.002, T1569.002 | windows-security, sysmon | timing | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| H-062 | If DCOM or scheduled-task lateral execution is used, then we would see `mmc.exe`, `excel.exe` or `ShellWindows` spawned by `svchost -k DcomLaunch` with a network logon, or 4698 task creations where the subject logon is type 3. | T1021.003, T1053.005 | windows-security, edr | search | [lateral-movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) |
| H-063 | If a service account is being used interactively, then we would see 4624 logon types 2, 10 or 11 for accounts whose 90-day history is exclusively type 3, 4 or 5. | T1078.002 | windows-security | baseline | [rdp-winrm-anomalies]({{ site.baseurl }}/hunt/playbooks/rdp-winrm-anomalies/) |

## Collection

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-064 | If data is being staged for exfiltration, then we would see archive utilities (`7z`, `rar`, `WinRAR`, `tar`, `Compress-Archive`) producing multi-hundred-MB files in `%TEMP%`, `C:\ProgramData`, `C:\PerfLogs` or a recycle bin. | T1560.001, T1074.001 | edr, sysmon | search | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-065 | If a file server is being bulk-read, then we would see one account generating 5145 read access to more than 1,000 distinct files in an hour on a share it rarely touches. | T1039, T1005 | windows-security | baseline | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-066 | If mailboxes are being harvested, then we would see `MailItemsAccessed` with high counts from an unfamiliar client app ID or IP, `New-MailboxExportRequest`, or eDiscovery searches by non-compliance staff. | T1114.002 | email | baseline | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-067 | If keystrokes or screens are being captured, then we would see unsigned processes calling `SetWindowsHookEx` style APIs (EDR API telemetry), or periodic image file writes (`.png`, `.jpg`) to a hidden folder by a non-graphics process. | T1056.001, T1113 | edr | cluster | - |
| H-068 | If clipboard or credential-prompt capture is being used, then we would see `powershell.exe` or scripts loading `System.Windows.Forms` with `Get-Clipboard`, or `Get-Credential` prompts from non-admin tooling in 4104. | T1115, T1056.002 | powershell | search | [powershell-abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) |
| H-109 | If a mailbox has been taken over for BEC, then we would see an inbox rule created via New-InboxRule or Set-InboxRule that deletes, marks as read or moves mail to RSS Feeds, Archive or Conversation History, keyed on words such as invoice, payment or password, from a client IP the user has never signed in from. | T1564.008, T1114 | m365-audit, entra-id | search | [business-email-compromise]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |
| H-110 | If an adversary is maintaining access to a compromised mailbox, then we would see ForwardingSmtpAddress set, an inbox rule with ForwardTo or RedirectTo, or a transport rule redirecting mail to a domain that is not one of our accepted or partner domains. | T1114.003 | m365-audit | search | [business-email-compromise]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |
| H-111 | If a stolen session is being used for BEC, then we would see a successful sign-in from a new country or ASN, or with no MFA claim, followed within an hour by a New-InboxRule, Set-Mailbox, Add-MailboxPermission, OAuth consent to Mail.Read or Mail.ReadWrite, or a new MFA method registration for the same account. | T1078.004, T1098.002, T1556.006 | entra-id, m365-audit | timing | [business-email-compromise]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |
| H-112 | If a mailbox is being bulk-collected before a payment fraud, then we would see MailItemsAccessed counts more than five times the account's 30-day daily average from a new client or IP, alongside mailbox searches for invoice, wire, bank or payroll terms. | T1114.002 | m365-audit | baseline | [business-email-compromise]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |

## Command & Control

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-069 | If a host is beaconing, then we would see connections from one host to one external destination at a regular interval with low coefficient of variation (under 0.35) across 30 or more connections. | T1071.001, T1573 | proxy, firewall, edr, zeek | timing | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| H-070 | If C2 infrastructure is new to us, then we would see external destinations contacted by exactly one host in the last day that were not contacted by any host in the previous 30 days. | T1071, T1568 | proxy, dns, edr | baseline | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| H-071 | If DNS is being used as a covert channel, then we would see more than 200 unique subdomains under one parent domain from one client in a day, with average label length over 20, or heavy TXT/NULL query types. | T1071.004, T1572 | dns, zeek | cluster | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| H-072 | If a C2 framework is using a default or library HTTP client, then we would see user agents in proxy logs that are used by fewer than three hosts, match library defaults (`python-requests`, `Go-http-client`, `curl`), or do not match the installed browser version. | T1071.001 | proxy, zeek | stack | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| H-073 | If an interactive tunnel or SOCKS proxy is active, then we would see external connections lasting more than four hours with roughly balanced bytes in and out, from a process that is not a VPN or collaboration client. | T1572, T1090 | zeek, firewall, edr | cluster | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| H-074 | If a legitimate web service is being used for C2, then we would see non-browser processes connecting to `pastebin`, `discord`, `telegram`, `github`, `dropbox` or `onedrive` APIs, or those domains contacted by servers that have no user sessions. | T1102 | edr, proxy | stack | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |
| H-075 | If ingress tool transfer is happening, then we would see `certutil -urlcache`, `bitsadmin /transfer`, `Invoke-WebRequest`, `curl -o` or `Start-BitsTransfer` writing executables to disk, followed within five minutes by execution of the written file. | T1105 | edr, sysmon | timing | [lolbin-proxy-execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) |
| H-113 | If an implant is using a non-application-layer channel, then we would see ICMP to the internet with non-default payload sizes or steady rates, or raw TCP/UDP flows to high ports with no recognised service and a regular interval, from a host-protocol pair never seen in the 30-day baseline. | T1095 | zeek, firewall | baseline | [c2-beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |

## Exfiltration

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-076 | If data is leaving through cloud storage, then we would see a host uploading more than 1 GB in a day to `mega.nz`, `wetransfer`, `transfer.sh`, `dropbox`, `pcloud` or similar, where its 30-day daily upload median is under 50 MB. | T1567.002 | proxy, firewall | baseline | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-077 | If `rclone`, `MEGAsync` or `WinSCP` are being used for bulk exfiltration, then we would see processes with those `OriginalFileName` values (even if renamed), or command lines with `copy`/`sync` and `--config`, on servers that do not normally run them. | T1567.002, T1048 | edr, sysmon | search | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-078 | If exfiltration is over an alternative protocol, then we would see outbound SSH, FTP or raw TCP to public IPs from servers whose normal egress is HTTP(S) only, with outbound bytes exceeding inbound by 10:1. | T1048 | firewall, zeek | baseline | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-079 | If exfiltration is scheduled to blend in, then we would see large outbound transfers that recur at the same hour daily from the same host to the same destination, and that destination is not a backup or replication target. | T1029, T1041 | firewall, proxy | timing | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-114 | If exfiltration has been automated, then we would see one host sending near-identical byte volumes to the same external destination at a regular interval, or a scheduled task or cron job whose command line contains `curl`, `rclone`, `aws s3 cp`, `scp` or `Invoke-WebRequest -Method Post`. | T1020 | firewall, zeek, edr | timing | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |

## Impact

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-080 | If ransomware deployment is imminent, then we would see `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no` or `Remove-WmiObject Win32_ShadowCopy` on any host. | T1490 | edr, sysmon | search | [ransomware-precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| H-081 | If backups are being targeted first, then we would see backup console or vault accounts logging on from new hosts, backup jobs deleted or retention shortened in the backup application's audit log, or `net stop` of backup services. | T1490, T1489 | windows-security, edr | baseline | [ransomware-precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| H-082 | If mass encryption is starting, then we would see one process renaming or writing more than 500 files per minute across many directories (Sysmon 11, EDR file events), with a new consistent extension and a ransom-note file name repeated per folder. | T1486 | edr, sysmon | timing | [ransomware-precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| H-083 | If attackers are preparing to deploy via GPO or SCCM, then we would see new GPOs linked at domain root (5136 on `gPLink`), scheduled-task GPO preferences pointing at `SYSVOL` binaries, or new SCCM packages created by non-SCCM admins. | T1484.001, T1072 | windows-security | search | [ransomware-precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| H-084 | If an account-lockout or destruction stage is underway, then we would see bulk 4726 (user deleted), 4740 lockouts across many accounts, or 4738 password changes for many privileged accounts within minutes. | T1531, T1485 | windows-security | timing | [ransomware-precursors]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |

## Cloud & Identity

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-085 | If a cloud identity is compromised, then we would see Entra ID sign-ins from a country or ASN that user has never used in 30 days, or two sign-ins from locations more than 1,000 km apart within an hour (impossible travel). | T1078.004 | entra-id | baseline | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-086 | If a session token has been stolen (AiTM phishing), then we would see a successful sign-in with the same session ID from a new IP and device within minutes of the user's legitimate sign-in, often with no MFA prompt recorded. | T1550.004, T1557 | entra-id | timing | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-087 | If a malicious OAuth application has been consented to, then we would see `Consent to application` or `Add delegated permission grant` audit events for apps requesting `Mail.Read`, `Files.ReadWrite.All` or `offline_access` that fewer than three users have consented to. | T1528, T1550.001 | entra-id | stack | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-088 | If a cloud role has been granted for persistence, then we would see `Add member to role` for Global Administrator, Privileged Role Administrator or Application Administrator, or AWS `AttachUserPolicy`/`AttachRolePolicy` with `AdministratorAccess`, by a principal that has never made that call. | T1098.003 | entra-id, aws-cloudtrail | baseline | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-089 | If MFA is being tampered with, then we would see `User registered security info` or `Update user` events changing authentication methods shortly after a risky sign-in, or MFA fatigue patterns (ten or more MFA denials then one approval in 30 minutes). | T1556.006, T1621 | entra-id | timing | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-090 | If AWS access keys have been stolen, then we would see CloudTrail `GetCallerIdentity`, `ListBuckets`, `DescribeInstances` and `GetSecretValue` from a new source ASN for that key, or an access key used from both a corporate IP and a residential/cloud IP in the same hour. | T1078.004, T1580 | aws-cloudtrail | baseline | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-091 | If cloud logging is being blinded, then we would see `StopLogging`, `DeleteTrail`, `PutEventSelectors`, `DeleteFlowLogs` or Entra diagnostic-setting deletions, outside change windows. | T1562.008 | aws-cloudtrail, entra-id | search | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |
| H-092 | If cloud data is being exfiltrated, then we would see S3 bucket policy changes to public, `GetObject` bursts from a single principal across many buckets, or SharePoint/OneDrive `FileDownloaded` counts in the thousands from one session. | T1530, T1537 | aws-cloudtrail, email | baseline | [data-exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| H-093 | If a service principal's credentials have been added for backdoor access, then we would see `Add service principal credentials` or `Update application – Certificates and secrets management` on apps that already hold privileged Graph permissions, by a non-automation account. | T1098.001 | entra-id | search | [cloud-identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) |

## Linux

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-094 | If a Linux host is compromised, then we would see new `authorized_keys` entries written by a process other than the configuration-management agent (auditd `PATH` records, FIM), or keys added to root and service accounts. | T1098.004 | linux-auditd | baseline | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-095 | If persistence is being planted, then we would see new cron entries in `/etc/cron.*`, user crontabs or `systemd` unit files whose command includes `curl`, `wget`, `base64 -d`, `/tmp` or `/dev/shm`. | T1053.003, T1543.002 | linux-auditd | stack | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-096 | If an attacker has an interactive shell, then we would see reverse-shell indicators: `bash -i`, `/dev/tcp/`, `nc -e`, `python -c 'import pty'`, `socat exec`, or a shell whose parent is a web server, database or `cron` process. | T1059.004 | linux-auditd, edr | search | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-097 | If a web application or service account has been escalated, then we would see `sudo` executions by `www-data`, `nginx`, `tomcat` or `postgres`, or SUID binaries created or modified outside package manager transactions. | T1548.001, T1548.003 | linux-auditd | search | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-098 | If a rootkit or preload hijack is installed, then we would see writes to `/etc/ld.so.preload`, new kernel modules (`init_module`, `finit_module` syscalls) not shipped by the distribution, or `insmod`/`modprobe` from non-root-session processes. | T1014, T1574.006, T1547.006 | linux-auditd | search | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-099 | If execution from writable locations is being used, then we would see processes whose executable path is `/tmp`, `/dev/shm`, `/var/tmp` or a home directory, stacked by hash across the fleet and present on fewer than three hosts. | T1059.004, T1105 | linux-auditd, edr | stack | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-100 | If logs are being tampered with on Linux, then we would see `history -c`, `unset HISTFILE`, `HISTSIZE=0`, truncation of `/var/log/auth.log`, `wtmp`, `btmp` or `lastlog`, or `auditctl -e 0` outside maintenance. | T1070.002, T1070.003, T1562.012 | linux-auditd | search | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |
| H-101 | If SSH is being used to pivot, then we would see one host opening SSH sessions to more than ten internal hosts in an hour, or accepted SSH logons for accounts from a source IP that has never authenticated to that host. | T1021.004 | linux-auditd, firewall, zeek | baseline | [linux-hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) |

## Containers & Kubernetes

Clusters are servers with a richer audit log. The API server records every request, so the hunts are about identity, verb and object: who did what to which resource, from where.

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-115 | If a kubeconfig or service-account token has been stolen, then we would see pods/exec, pods/attach or pods/portforward requests in the API audit log from a system:serviceaccount identity, from a source IP outside the cluster and admin ranges, or with a curl, python-requests or Go-http-client user agent. | T1609, T1552.007 | kubernetes-audit | stack | [kubernetes-containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/) |
| H-116 | If an adversary is preparing a container escape, then we would see a pod, deployment or job created with privileged: true, hostPID, hostNetwork, a hostPath volume on / or the container runtime socket, or SYS_ADMIN capabilities, by an identity that is not the GitOps controller or a known DaemonSet owner. | T1611, T1610 | kubernetes-audit | search | [kubernetes-containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/) |
| H-117 | If a compromised identity is escalating in the cluster, then we would see a new ClusterRoleBinding or RoleBinding to cluster-admin or a role with wildcard verbs or resources, a subject that is a workload ServiceAccount, or impersonation of system:masters, outside a change window. | T1078.004, T1613 | kubernetes-audit | search | [kubernetes-containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/) |
| H-118 | If a cluster is being enumerated or has been seeded with persistence, then we would see one identity list eight or more resource types in ten minutes with many 403 responses, bulk secrets reads across namespaces, or CronJobs and DaemonSets created in kube-system by a non-controller identity pulling images from a registry outside our allow-list. | T1613, T1552.007, T1053.007, T1525 | kubernetes-audit | stack | [kubernetes-containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/) |

## macOS

Mac fleets get the same persistence-first treatment as Windows; the locations differ, the long-tail logic does not.

| # | Hypothesis | ATT&CK | Data needed | Technique | Playbook |
|---|---|---|---|---|---|
| H-119 | If a Mac has been compromised, then we would see a LaunchAgent or LaunchDaemon plist created in `~/Library/LaunchAgents`, `/Library/LaunchAgents` or `/Library/LaunchDaemons` by a shell, `osascript`, Python, a browser or a process in `/tmp` or `/Volumes`, with `ProgramArguments` pointing to a user-writable path. | T1543.001, T1543.004 | edr, osquery | stack | [macos-hunting]({{ site.baseurl }}/hunt/playbooks/macos-hunting/) |
| H-120 | If a stealer is prompting the user for their macOS password, then we would see `osascript` run with `display dialog` and `hidden answer` from a non-MDM parent, followed within minutes by Keychain reads from the same process tree. | T1056.002, T1555.001, T1059.002 | edr, macos-unified-log | timing | [macos-hunting]({{ site.baseurl }}/hunt/playbooks/macos-hunting/) |
| H-121 | If a dropper is bypassing Gatekeeper, then we would see the quarantine attribute removed with `xattr` or Gatekeeper disabled with `spctl` from a process in `Downloads`, `/tmp` or a mounted disk image, with the affected file executing within ten minutes. | T1553.001, T1105 | edr | search | [macos-hunting]({{ site.baseurl }}/hunt/playbooks/macos-hunting/) |
| H-122 | If malware is checking for defences before acting on a Mac, then we would see `sw_vers`, `system_profiler SPApplicationsDataType` and `ps` or `pgrep` for EDR process names within one minute from the same non-MDM parent. | T1518.001 | edr, osquery | timing | [macos-hunting]({{ site.baseurl }}/hunt/playbooks/macos-hunting/) |

## Retire, recycle, promote

A hypothesis is not finished when the hunt ends. Decide its fate in the hunt report and record it on the card, so the backlog stays honest.

| Outcome | What to do | Record |
|---|---|---|
| **Promote to detection** | The query found something, or found nothing but is cheap, precise and would catch the behaviour if it occurred. Convert to a Sigma rule, add an allow-list from the benign activity you documented, and hand off with the [detection handoff checklist]({{ site.baseurl }}/templates/#detection-handoff-checklist). Mark the technique as detected on the coverage map. | Card status `Done`; link to rule in [Sigma rules]({{ site.baseurl }}/research/sigma/) |
| **Recycle quarterly** | The hypothesis is valid but the technique is too noisy or too context-dependent to automate (most baseline and clustering hunts). Schedule it to re-run every quarter, or whenever intel names the technique. Save the queries and the last triage notes so the next run starts from the long tail, not from zero. | Card status `Backlog` with a `Re-run after` date and a link to the saved queries |
| **Retire with reason** | The data does not exist (and a visibility ticket has been raised), the technique does not apply to your estate (no AD CS, no AWS), or the hypothesis has been superseded by a better one. Never retire silently: the reason is what stops someone re-proposing it in six months. | Card status `Dropped` with one of: `no-data`, `not-applicable`, `superseded by H-nnn`, `covered by detection <id>` |

Three rules of thumb:

1. **One hypothesis, one outcome.** If a hunt produced a detection for one half of the hypothesis and a visibility gap for the other half, split the card and give each half its own fate.
2. **Negative results count.** "We looked for H-045 across all DCs for 90 days with verified 4662 coverage and found only the two DC accounts and Entra Connect" is a result worth writing down, and it is the justification for promoting the query.
3. **Review the map after every hunt**, not every quarter. Each promoted or retired hypothesis changes which techniques on the [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) are detected, hunted or unseen; keeping it current is what makes the coverage-gap lens work the next time you pick from this library.

See also: [Hunt playbooks]({{ site.baseurl }}/hunt/), [Hunting query index]({{ site.baseurl }}/hunt/query-index/), [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/), [Hunt backlog template]({{ site.baseurl }}/templates/#hunt-backlog).
