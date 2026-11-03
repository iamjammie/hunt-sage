---
title: "Playbook: Active Directory Discovery & BloodHound Collection"
permalink: /hunt/playbooks/ad-discovery-bloodhound/
excerpt: "Catch SharpHound, PowerView, AdFind and net/nltest enumeration through command lines, LDAP query volume, SMB session-enumeration bursts and honey accounts."
tactic: "Discovery"
attack: [T1087.002, T1069.002, T1482, T1018, T1016]
difficulty: 2
timebox: "3-5 hours"
data: [windows-security, edr, sysmon, powershell]
---

{% include playbook-meta.html %}

**Data used:** Process creation with command line (4688 / Sysmon 1 / EDR); DC Security log 4661, 4662, 4798/4799, 5145; LDAP query logging (DC 1644 or Defender for Identity `IdentityQueryEvents`); Sysmon 3; Entra sign-in and audit logs for AzureHound

## Background

Discovery is the quietest phase and the earliest one you can still act on cheaply. Nothing is broken yet: the attacker holds one user's credentials and is working out where the Domain Admins log on, which hosts they can reach, and what the trust map looks like. Every later phase (Kerberoasting, lateral movement, DCSync) depends on the answers, so catching the questions is worth the tuning effort.

| Tool | How it looks |
|---|---|
| SharpHound / BloodHound CE | Thousands of LDAP queries from one host, then SMB to *every* computer for session and local-group enumeration |
| SOAPHound | Same data via ADWS (TCP 9389), so classic LDAP logging sees nothing; look for the process and for 4662 on decoys |
| AzureHound | Microsoft Graph and Azure RM calls with a non-browser user agent, every object type in minutes |
| PowerView (`Get-DomainUser`, `Get-NetComputer`, `Find-LocalAdminAccess`) | PowerShell LDAP + SMB; script-block logging shows the function names |
| AdFind, ldapdomaindump, dsquery, ADExplorer | Bulk LDAP dumps, often from a "temporary" directory |
| `net group "domain admins" /domain`, `net user /domain`, `nltest /dclist`, `nltest /domain_trusts`, `whoami /groups`, `ipconfig /all` | Hands-on-keyboard recon, usually in a burst within a minute of first access |

## Hypothesis

> *If an adversary is mapping the domain, one host or account will issue an abnormal volume and breadth of directory queries (LDAP, SAMR, Graph) or SMB session enumeration against many computers in a short window, often from a workstation, a new account, or a service account that has no business reading the directory.*

## Data required

- Process creation with command line (Sysmon 1, EDR, or 4688 with *Audit Process Creation* and "Include command line") on workstations, not just servers
- DC Security log: *Audit Detailed File Share* (5145), *Audit Directory Service Access* (4662, needs a SACL on the decoy object), *Audit SAM* (4661), *Audit Security Group Management* / *User Account Management* (4798, 4799)
- LDAP query logging: NTDS diagnostics `15 Field Engineering` = 5 (plus `Expensive Search Results Threshold` / `Inefficient Search Results Threshold` set low, e.g. 1) produces **1644** in *Directory Service*; or Defender for Identity for `IdentityQueryEvents`
- PowerShell 4104 script-block logging for PowerView
- Entra ID `SigninLogs` / `AADNonInteractiveUserSignInLogs` and `AuditLogs` for AzureHound

## Hunt steps

### 1. Enumeration tooling by command line

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName in~ ("SharpHound.exe","AdFind.exe","AzureHound.exe","SOAPHound.exe","ADExplorer.exe")
   or ProcessCommandLine has_any ("-c All", "--CollectionMethods", "SharpHound", "Invoke-BloodHound", "AzureHound", "SOAPHound",
                                   "adfind -f", "adfind.exe -f", "ldapdomaindump", "Get-DomainUser", "Get-NetComputer", "Get-DomainComputer",
                                   "Find-LocalAdminAccess", "Get-DomainTrust", "dsquery * -limit", "net group \"domain admins\"",
                                   "net group \"enterprise admins\"", "nltest /domain_trusts", "nltest /dclist", "net user /domain")
| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, ProcessCommandLine, InitiatingProcessFileName
```

```spl
index=sysmon EventCode=1
  (OriginalFileName IN ("SharpHound.exe","AdFind.exe","AzureHound.exe","SOAPHound.exe","ADExplorer.exe")
   OR CommandLine="*-c All*" OR CommandLine="*--CollectionMethods*" OR CommandLine="*SharpHound*" OR CommandLine="*Invoke-BloodHound*"
   OR CommandLine="*AzureHound*" OR CommandLine="*adfind* -f*" OR CommandLine="*ldapdomaindump*" OR CommandLine="*Get-DomainUser*"
   OR CommandLine="*Get-NetComputer*" OR CommandLine="*dsquery * -limit*" OR CommandLine="*net group \"domain admins\"*"
   OR CommandLine="*nltest /domain_trusts*" OR CommandLine="*nltest /dclist*" OR CommandLine="*net user /domain*")
| table _time host User ParentImage Image OriginalFileName CommandLine
```

For 4688 use `index=wineventlog EventCode=4688 Process_Command_Line=...`; `New_Process_Name` is the image and `Creator_Process_Name` the parent. Renamed SharpHound still carries `OriginalFileName: SharpHound.exe` unless the attacker rebuilt it; PowerShell-only collection shows up in 4104 as `Invoke-BloodHound` or the embedded `SharpHound` assembly load.

### 2. Rare parents and bursts of built-in recon commands

`net.exe`, `nltest.exe`, `whoami.exe`, `dsquery.exe` are normal from an admin's console. They are not normal from `w3wp.exe`, `wmiprvse.exe`, `rundll32.exe`, Office, a browser, or `powershell.exe` under a non-admin user. Stack the parent, and count distinct recon commands per host per 10 minutes.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("net.exe","net1.exe","nltest.exe","whoami.exe","dsquery.exe","dsget.exe","ipconfig.exe","nslookup.exe","quser.exe","qwinsta.exe")
| summarize Cmds = dcount(ProcessCommandLine), Sample = make_set(ProcessCommandLine, 10), Hosts = dcount(DeviceName)
          by InitiatingProcessFileName, AccountName, DeviceName, bin(Timestamp, 10m)
| where Cmds >= 5 or InitiatingProcessFileName !in~ ("cmd.exe","powershell.exe","explorer.exe")
| order by Cmds desc
```

Splunk: same image list, then `bin _time span=10m | stats dc(CommandLine) as cmds by host User ParentImage _time | where cmds>=5`.

### 3. LDAP query volume against the DCs

With Field Engineering logging on, every expensive or inefficient search produces a **1644** with client IP, user, filter and attribute list. Collectors stand out by filter breadth (`(objectClass=*)`, `(samAccountType=805306368)`, `(objectCategory=group)`) and by volume from one client. If you have Defender for Identity, `IdentityQueryEvents` gives the same without touching DC logging.

```kql
IdentityQueryEvents
| where Timestamp > ago(7d) and Protocol == "Ldap"
| summarize Queries = count(), Targets = dcount(QueryTarget), Filters = make_set(Query, 5)
          by AccountName, DeviceName, IPAddress, bin(Timestamp, 15m)
| where Queries > 500 or Targets > 200           // starting thresholds; baseline per role first
| order by Queries desc
```

```spl
index=wineventlog source="WinEventLog:Directory Service" EventCode=1644
| rex field=Message "Client:\s+(?<client>[\d\.]+):\d+.*?Filter:\s+(?<filter>.+?)\n.*?User:\s+(?<user>\S+)"
| bin _time span=15m
| stats count dc(filter) as filters values(filter) as sample by client user _time
| where count>200
```

1644 is verbose; raise the thresholds to only log searches that visit more than, say, 1000 objects, or restrict collection to the DCs serving workstation VLANs. Note that SOAPHound (ADWS) and SAMR-based tools do not appear here at all.

### 4. SMB session enumeration burst (the SharpHound fingerprint)

After LDAP, SharpHound connects to **every** computer in the domain over 445 to call `NetSessionEnum` / `NetWkstaUserEnum` and `SAMR` for local groups. One workstation touching hundreds of hosts in minutes is not a user. On the targets this is 5145 against `IPC$` with `RelativeTargetName` `srvsvc`, `wkssvc` or `samr`; on the source it is a Sysmon 3 fan-out.

```kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 5145
| where ShareName =~ @"\\*\IPC$" and RelativeTargetName in~ ("srvsvc","wkssvc","samr","lsarpc")
| summarize Targets = dcount(Computer), Pipes = make_set(RelativeTargetName), Events = count()
          by SubjectUserName, IpAddress, bin(TimeGenerated, 10m)
| where Targets >= 20
| order by Targets desc
```

```spl
index=wineventlog EventCode=5145 Share_Name="\\\\*\\IPC$" (Relative_Target_Name=srvsvc OR Relative_Target_Name=wkssvc OR Relative_Target_Name=samr OR Relative_Target_Name=lsarpc)
| bin _time span=10m
| stats dc(ComputerName) as targets values(Relative_Target_Name) as pipes count by Account_Name, Source_Address, _time
| where targets>=20
```

Source-side equivalent: Sysmon 3 / `DeviceNetworkEvents` where `RemotePort == 445` summarised by `DeviceName, InitiatingProcessFileName` with `dcount(RemoteIP) >= 20` in 10 minutes. The initiating process is usually `SharpHound.exe`, `powershell.exe` or a renamed binary, which is the pivot back to step 1.

### 5. SAMR and local-group enumeration on the DC and members

SAMR lookups land as **4661** (object type `SAM_USER`, `SAM_GROUP`, `SAM_DOMAIN`) on the DC and **4798** (user's local group membership enumerated) / **4799** (security-enabled local group membership enumerated) on every member host. A burst of 4798/4799 across many hosts from one `SubjectUserName` with `CallerProcessName` not being `svchost.exe`/`lsass.exe` is SharpHound's `LocalGroup`/`Session` collection or `net localgroup administrators` in a loop.

```kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID in (4798, 4799)
| where CallerProcessName !endswith @"\svchost.exe" and CallerProcessName !endswith @"\lsass.exe" and CallerProcessName !endswith @"\mmc.exe"
| summarize Hosts = dcount(Computer), Groups = make_set(TargetUserName, 10), Procs = make_set(CallerProcessName, 5), Events = count()
          by SubjectUserName, bin(TimeGenerated, 15m)
| where Hosts >= 10 or Events >= 50
```

### 6. Honey accounts: any touch is a hit

Create one or two decoy users (plausible names, old `pwdLastSet`, membership of an interesting-looking group, never used) and put a SACL on them for *Read Property* by Everyone. Any **4662** whose `ObjectName` is the decoy's GUID is a directory read nobody should have made. Do the same for a decoy computer object so session enumeration against it (5145 from step 4) is unambiguous.

```kql
let decoys = dynamic(["{11111111-2222-3333-4444-555555555555}", "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"]);   // decoy objectGUIDs
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4662 and ObjectName in~ (decoys)
| where SubjectUserName !endswith "$"
| project TimeGenerated, Computer, SubjectUserName, SubjectLogonId, Properties, AccessMask
```

LDAP reads of the decoy also appear in 1644 / `IdentityQueryEvents` with the decoy's `sAMAccountName` in the filter or result. Keep the account out of your own inventory scripts or you will alert on yourself.

### 7. AzureHound and Graph enumeration

AzureHound walks Microsoft Graph (`/users`, `/groups`, `/servicePrincipals`, `/roleManagement`) and Azure Resource Manager with a Go HTTP client. In Entra it shows as a sign-in to the **Microsoft Graph** resource with an unfamiliar `UserAgent` (`azurehound/...`, `Go-http-client`, or a bare `python-requests`) and an app ID that is not a known client, followed by hundreds of Graph calls in minutes.

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and ResourceDisplayName in~ ("Microsoft Graph", "Windows Azure Active Directory", "Azure Resource Manager")
| where UserAgent has_any ("azurehound", "Go-http-client", "python-requests", "ROADtools", "AADInternals") or isempty(UserAgent)
| summarize Signins = count(), Apps = make_set(AppDisplayName, 5), IPs = make_set(IPAddress, 5) by UserPrincipalName, UserAgent, bin(TimeGenerated, 1h)
```

Pair with `AuditLogs` for consent grants or device-code flows by the same user; AzureHound often follows a device-code phish.

## Triage

| Check | Interpretation |
|---|---|
| Source is a workstation or a freshly created / service account | Users and service accounts do not run `nltest /dclist`; strong signal |
| Breadth: one host → hundreds of computers on 445 in minutes | SharpHound session/local-group collection, or a vulnerability scanner (check allow-list) |
| Command line names Domain Admins, Enterprise Admins, trusts, DC list | Attacker targeting, not troubleshooting |
| Decoy object read (4662 / decoy in LDAP filter) | True positive by construction; find what else the account did |
| Discovery followed within an hour by 4769 bursts or new logons to servers | Discovery → Kerberoast / lateral movement chain; escalate |
| `OriginalFileName` mismatch with `Image` | Renamed tool; treat as hostile |

## Common false positives

- Vulnerability scanners, asset inventory and compliance tools (Nessus, Qualys, Lansweeper, SCCM discovery) producing LDAP and 5145/4799 bursts; allow-list by service account **and** source host
- Monitoring that queries group membership (PingCastle, Purple Knight, ADAudit) on a schedule
- Helpdesk and admins running `net group` / `nltest` interactively from jump hosts
- Exchange, SharePoint and backup servers that read large parts of the directory legitimately
- Your own scripts touching the honey account (exclude the inventory account explicitly)

## Escalate when

Any decoy read; `SharpHound`/`AzureHound`/`AdFind` by name from a non-security account; an LDAP or SMB fan-out burst from a workstation or a new account; or built-in recon commands spawned by a web server, Office, or a script host. Capture the source host's full process tree and network connections, and check for the follow-on in the [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) and [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) playbooks.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1087.002` (net user /domain, Get-DomainUser), `T1069.002` (net group domain admins), `T1482` (nltest /domain_trusts), `T1018` (net view, nltest /dclist), `T1016`; run SharpHound CE with `-c All` from a lab workstation and confirm steps 3-5 light up
- Detection: [AD enumeration tooling command line]({{ site.baseurl }}/research/sigma/T1087.002-ad-enumeration-tooling-command-line.yml), [SMB session enumeration burst]({{ site.baseurl }}/research/sigma/T1018-session-enumeration-burst-smb.yml)
- Hardening: `NetCease` (restrict `NetSessionEnum` to admins) and `SAMRi10` (restrict remote SAM to admins; Windows 10 1607+ default policy "Network access: Restrict clients allowed to make remote calls to SAM"); remove Authenticated Users read on sensitive attributes where feasible; tiered admin model so admin sessions never appear on workstations; honey accounts and honey SPNs; alert on 4798/4799 fan-out; conditional access and device-code flow restrictions for Graph.

See also: [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/), [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/), [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/), [Active Directory attacks cheat sheet]({{ site.baseurl }}/cheatsheets/active-directory-attacks/).

{% include playbook-footer.html %}
