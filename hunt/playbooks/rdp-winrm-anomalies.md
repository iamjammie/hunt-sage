---
title: "Playbook: Remote Access Anomalies (RDP & WinRM)"
permalink: /hunt/playbooks/rdp-winrm-anomalies/
excerpt: "Baseline RDP and WinRM, then hunt the exceptions: peer-to-peer RDP, RDP switched on from the command line, tunnelled 3389, wsmprovhost spawning shells and admin-share bursts."
tactic: "Lateral Movement"
attack: [T1021.001, T1021.006, T1021.002]
difficulty: 2
timebox: "3-4 hours"
data: [windows-security, sysmon, edr]
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1021.001 (Remote Desktop Protocol), T1021.006 (Windows Remote Management), T1021.002 (SMB/Windows Admin Shares) |
| **Tactic** | Lateral Movement |
| **Data** | Security 4624 (LogonType 10/7/3), 4778/4779, 5140/5145; TerminalServices-LocalSessionManager 21/22/25; PowerShell 4104; Sysmon 1/3/13; EDR process, network and registry events |
| **Time-box** | 3-4 hours |
| **Difficulty** | ★★☆ |

## Background

RDP and WinRM are the two remote-access channels most environments *must* allow for administration, which is why attackers prefer them: the traffic is expected, the tooling is built in, and a stolen credential is all it takes. The [Lateral movement playbook]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) covers fan-out and PsExec-style movement at a high level; this playbook goes deep on the two interactive protocols and the admin shares that usually accompany them.

The signal is almost never "RDP happened". It is RDP or WinRM that breaks the organisation's own pattern: workstation to workstation, one source to many destinations, a host that had RDP disabled yesterday and enabled today, a 3389 connection that did not come from `mstsc.exe`, or a WinRM session that immediately spawns `cmd.exe`.

## Hypothesis

> *If an adversary is moving with RDP or WinRM, the source/destination pair, the enabling change, the connecting process or the child processes of the remote session will fall outside a baseline built from 30 days of normal administration.*

## Data required

- **Security log** on endpoints and servers: 4624 with `LogonType` (10 = RemoteInteractive, 7 = unlock/reconnect, 3 = network), 4778/4779 (session reconnect/disconnect, carries `ClientName` and `ClientAddress`), 5140/5145 (share access; needs *Audit File Share* / *Audit Detailed File Share*)
- **Microsoft-Windows-TerminalServices-LocalSessionManager/Operational**: 21 (logon), 22 (shell start), 25 (reconnect). Logged on the *destination*; often the only RDP record when 4624 is noisy or NLA failed early
- **Microsoft-Windows-PowerShell/Operational 4104** with Script Block Logging for `Enter-PSSession` / `Invoke-Command`
- **Sysmon** 1 (process), 3 (network, for `DestinationPort` 3389/5985/5986 and the initiating `Image`), 13 (registry, `fDenyTSConnections`)
- **EDR**: `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`
- An asset list that separates workstations, servers, jump hosts and DCs. Without it every query below is noise.

## Hunt steps

### 1. Baseline RDP: who logs on where with type 10

Build the 30-day set of (source, destination, account) for type 10 and look at what is new in the last day. Type 7 reconnects and 4778 fill in sessions that were already open.

```kql
let lookback = 30d;
let recent = 1d;
let baseline = SecurityEvent
  | where TimeGenerated between (ago(lookback) .. ago(recent)) and EventID == 4624 and LogonType == 10
  | distinct IpAddress, Computer, TargetUserName;
SecurityEvent
| where TimeGenerated > ago(recent) and EventID == 4624 and LogonType in (10, 7)
| where IpAddress !in ("-", "::1", "127.0.0.1")
| join kind=leftanti baseline on IpAddress, Computer, TargetUserName
| summarize FirstSeen = min(TimeGenerated), Logons = count() by IpAddress, Computer, TargetUserName, LogonType
| order by FirstSeen desc
```

```spl
index=wineventlog EventCode=4624 (Logon_Type=10 OR Logon_Type=7) Source_Network_Address!="-" Source_Network_Address!="::1" Source_Network_Address!="127.0.0.1" earliest=-30d
| eval period=if(_time > relative_time(now(), "-1d"), "recent", "baseline")
| stats min(_time) as first_seen values(period) as periods count by Source_Network_Address, ComputerName, Account_Name
| where periods="recent" AND NOT match(periods, "baseline")
| convert ctime(first_seen)
```

The TerminalServices-LocalSessionManager channel (event 21, fields `User` and `Address`) gives the same pairs with less noise; use it when 4624 is not forwarded from workstations.

### 2. Workstation-to-workstation and one-to-many RDP

Peer-to-peer RDP is rare in most organisations; admins RDP *from* jump hosts *to* servers. Resolve `IpAddress` against your asset inventory (here a watchlist) and flag workstation sources, then count distinct destinations per source.

```kql
let workstations = _GetWatchlist("Assets") | where Role == "workstation" | project IpAddress = Ip, SourceHost = Hostname;
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4624 and LogonType == 10
| join kind=inner workstations on IpAddress
| summarize Destinations = dcount(Computer), DestList = make_set(Computer, 20), Accounts = make_set(TargetUserName, 5) by SourceHost, IpAddress, bin(TimeGenerated, 1d)
| where Destinations >= 3
| order by Destinations desc
```

```spl
index=wineventlog EventCode=4624 Logon_Type=10 earliest=-7d
| lookup assets.csv ip AS Source_Network_Address OUTPUT role AS src_role hostname AS src_host
| where src_role="workstation"
| bin _time span=1d
| stats dc(ComputerName) as destinations values(ComputerName) as dest_list values(Account_Name) as accounts by src_host, Source_Network_Address, _time
| where destinations>=3
```

Three destinations in a day from a workstation is a starting threshold; helpdesk machines will exceed it and should be allow-listed by hostname, not by account.

### 3. RDP enabled from the command line or registry

Attackers who land on a host with RDP disabled turn it on. The two artefacts are `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 0` and a firewall rule opening 3389. Look at the process that made the change: `reg.exe`, `netsh.exe`, `powershell.exe` or something unsigned are suspicious; `svchost.exe` (Group Policy), `TiWorker.exe` and SCCM agents are normal.

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Control\Terminal Server" and RegistryValueName =~ "fDenyTSConnections" and RegistryValueData == "0"
| where InitiatingProcessFileName !in~ ("svchost.exe", "TiWorker.exe", "ccmexec.exe", "SystemSettings.exe", "SystemPropertiesRemote.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| union (
  DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where (FileName =~ "netsh.exe" and ProcessCommandLine has_any ("remote desktop", "3389", "remotedesktop"))
     or (ProcessCommandLine has "fDenyTSConnections" and ProcessCommandLine has_any (" 0", "0x0", "$false"))
  | project Timestamp, DeviceName, InitiatingProcessAccountName = AccountName, InitiatingProcessFileName = FileName, InitiatingProcessCommandLine = ProcessCommandLine
)
```

```spl
(index=sysmon EventCode=13 TargetObject="*\\Control\\Terminal Server\\fDenyTSConnections" Details="DWORD (0x00000000)"
   NOT Image IN ("C:\\Windows\\System32\\svchost.exe","C:\\Windows\\WinSxS\\*\\TiWorker.exe","*\\CCM\\CcmExec.exe","C:\\Windows\\System32\\SystemPropertiesRemote.exe"))
OR (index=sysmon EventCode=1 ((Image="*\\netsh.exe" (CommandLine="*remote desktop*" OR CommandLine="*3389*"))
   OR (CommandLine="*fDenyTSConnections*" (CommandLine="* 0*" OR CommandLine="*0x0*" OR CommandLine="*$false*"))))
| table _time host User Image CommandLine TargetObject Details
```

Sysmon 13 requires a rule for `Terminal Server\fDenyTSConnections` in your configuration (SwiftOnSecurity and Olaf Hartong's configs include it). Commands that pair the registry change with `net user /add` or `net localgroup "Remote Desktop Users"` within a few minutes are near-certain intrusions.

### 4. RDP that did not come from mstsc, or arrived through a tunnel

Legitimate 3389 clients are `mstsc.exe`, `msrdc.exe` (the new Remote Desktop client), `mRemoteNG`, Royal TS and a few others. Anything else initiating a connection to 3389 (`plink.exe`, `ssh.exe`, `ngrok.exe`, `chisel`, Python, `rundll32.exe`, an unknown binary in `%TEMP%`) is either a tunnel endpoint or a scanner. On the destination side, a 4624 type 10 with `IpAddress` of `127.0.0.1` / `::1` means the RDP session arrived over a local port forward.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemotePort == 3389 and ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("mstsc.exe", "msrdc.exe", "mRemoteNG.exe", "RoyalTS.exe", "RTSApp.exe", "vmconnect.exe", "svchost.exe")
| summarize Connections = count(), Targets = dcount(RemoteIP), TargetList = make_set(RemoteIP, 10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Targets desc
```

```spl
index=sysmon EventCode=3 DestinationPort=3389 Initiated=true
  NOT Image IN ("*\\mstsc.exe","*\\msrdc.exe","*\\mRemoteNG.exe","*\\RoyalTS.exe","*\\vmconnect.exe","C:\\Windows\\System32\\svchost.exe")
| stats count dc(DestinationIp) as targets values(DestinationIp) as target_list by host, User, Image, CommandLine
| sort - targets
```

On the RDP *server* side, the listener is `svchost.exe` hosting `TermService`; a 4624 type 10 whose `IpAddress` is `127.0.0.1`/`::1` (query in step 5 of the [Lateral movement playbook]({{ site.baseurl }}/hunt/playbooks/lateral-movement/)) means the session was proxied on the host. Also hunt the tunnel process directly: `plink.exe -R`, `ssh -L 3389` / `-R 3389`, `ngrok tcp 3389`, `chisel client`. These rarely have a business reason on a Windows server.

### 5. WinRM: wsmprovhost spawning shells and the matching logons

Every remote PowerShell session runs inside `wsmprovhost.exe` on the destination. Its children are the commands the remote user ran. `cmd.exe`, `powershell.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `certutil.exe` and `whoami.exe` as children are either an admin doing admin things or an attacker doing attacker things; the account, source and command line tell you which.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe")
| summarize Children = count(), Commands = make_set(ProcessCommandLine, 10) by DeviceName, AccountName, FileName, bin(Timestamp, 1h)
| order by Children desc
```

```spl
index=sysmon EventCode=1 ParentImage="*\\wsmprovhost.exe"
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe","*\\rundll32.exe","*\\regsvr32.exe","*\\mshta.exe","*\\certutil.exe","*\\whoami.exe","*\\net.exe","*\\net1.exe","*\\nltest.exe")
| bin _time span=1h
| stats count values(CommandLine) as commands by host, User, Image, _time
| sort - count
```

Tie the child process back to the session: WinRM produces a 4624 **LogonType 3** on the destination (`LogonProcessName: Kerberos` or `NtLmSsp`) seconds before `wsmprovhost.exe` starts, and the source shows an outbound connection to **5985** (HTTP) or **5986** (HTTPS). On the *source*, 4104 script blocks with `Enter-PSSession`, `Invoke-Command` or `New-PSSession` plus `-ComputerName` name the targets.

```kql
DeviceEvents
| where ActionType == "PowerShellCommand" and AdditionalFields has_any ("Enter-PSSession", "Invoke-Command", "New-PSSession")
| summarize Commands = count(), Sample = make_set(AdditionalFields, 5) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1h)
```

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*Enter-PSSession*" OR ScriptBlockText="*Invoke-Command*" OR ScriptBlockText="*New-PSSession*")
  (ScriptBlockText="*-ComputerName*" OR ScriptBlockText="*-Session*" OR ScriptBlockText="*-ConnectionUri*")
| rex field=ScriptBlockText "-ComputerName\s+(?<targets>[^\s|;]+)"
| stats count values(targets) as targets by host, UserID
```

**Evil-WinRM artefacts.** Evil-WinRM (the Ruby WinRM shell favoured by ransomware affiliates) leaves a recognisable trail on the destination: bursts of `wsmprovhost.exe` children, a 4624 type 3 with **NTLM** from a non-domain client (`WorkstationName` empty or a Linux hostname), and 4104 blocks containing `Invoke-Binary`, `Donut-Loader`, `Bypass-4MSI` or `[System.Reflection.Assembly]::Load` from Base64. Add those strings to the 4104 hunt above.

### 6. Admin-share bursts (C$ / ADMIN$)

RDP and WinRM movement is usually preceded or followed by file staging over SMB. 5140 (share connected) and 5145 (object accessed, needs *Detailed File Share* auditing and is high volume) show `ShareName` and `IpAddress`.

```kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID in (5140, 5145)
| where ShareName in~ (@"\\*\C$", @"\\*\ADMIN$", @"\\*\IPC$")
| where SubjectUserName !endswith "$"
| summarize Hosts = dcount(Computer), Events = count(), Shares = make_set(ShareName), HostList = make_set(Computer, 20) by SubjectUserName, IpAddress, bin(TimeGenerated, 15m)
| where Hosts >= 5 or Events >= 200
| order by Hosts desc
```

```spl
index=wineventlog (EventCode=5140 OR EventCode=5145) (Share_Name="\\\\*\\C$" OR Share_Name="\\\\*\\ADMIN$") Account_Name!="*$"
| bin _time span=15m
| stats dc(ComputerName) as hosts count values(Share_Name) as shares values(ComputerName) as host_list by Account_Name, Source_Address, _time
| where hosts>=5 OR count>=200
```

A 5145 for `ADMIN$` with `RelativeTargetName` ending in `.exe`, `.dll`, `.bat` or `.ps1` followed by a 7045 service install or a type 3 logon and `wsmprovhost.exe` child on the same host within two minutes is the classic stage-then-execute sequence.

## Triage

| Check | Interpretation |
|---|---|
| Source host role | Jump host or PAW = expected; workstation or server-to-server = investigate |
| Source IP `127.0.0.1` / `::1` on type 10 | Tunnelled RDP; find the forwarding process on that host |
| Account vs. host tier | Domain Admin RDP to a workstation, or a service account with type 10 at all, is a tiering violation |
| Children of `wsmprovhost.exe` | `cmd /c whoami`, `net group "Domain Admins"`, `nltest /dclist` = recon; installers and config scripts = admin |
| Was RDP enabled just before the logon? | `fDenyTSConnections` flip followed by type 10 within the hour = attacker preparing a foothold |
| `WorkstationName` in 4624 | Empty, random, or `kali`/`DESKTOP-xxxxxx` not in inventory = non-domain client (Impacket, Evil-WinRM, xfreerdp) |

## Common false positives

- Helpdesk and desktop-support teams using RDP/Remote Assistance workstation-to-workstation: allow-list their hosts, not their accounts
- Configuration management (SCCM, Intune, Ansible over WinRM, Chef) producing `wsmprovhost.exe` children and 5145 bursts on schedule; model by account + source + time window
- Monitoring and vulnerability scanners (Nessus, Qualys, Rapid7) that authenticate over SMB and WinRM to hundreds of hosts: exclude by source IP, review their account's privilege
- Group Policy setting `fDenyTSConnections` on build: `svchost.exe` as the initiating process, at boot or policy refresh

## Escalate when

- RDP or WinRM to a host from a workstation that has never administered anything, especially with a privileged account
- `fDenyTSConnections` set to 0 or a 3389 firewall rule created by `reg.exe`/`netsh.exe`/`powershell.exe` outside a change window, followed by a new remote logon
- Type 10 logon from a loopback address or any 3389 connection initiated by `plink`, `ssh`, `ngrok`, `chisel` or an unknown binary
- `wsmprovhost.exe` children running discovery (`whoami`, `net`, `nltest`, `ipconfig /all`), credential tooling, or binaries from `\Temp\`/`\Users\Public\`
- Any of the above chained with a credential-theft precursor (see [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/))

Contain by disabling the account, isolating the source host and reviewing every destination in the fan-out for persistence.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1021.001` (enable RDP via registry/netsh, RDP to a lab host), `Invoke-AtomicTest T1021.006` (`Enter-PSSession`, `Invoke-Command`), `Invoke-AtomicTest T1021.002` (admin share copy). Run each from a workstation-class VM so the source-role logic is exercised.
- Detection: [WinRM host process spawning a shell]({{ site.baseurl }}/research/sigma/T1021.006-wsmprovhost-spawns-shell.yml), [RDP enabled via command line]({{ site.baseurl }}/research/sigma/T1021.001-rdp-enabled-via-command-line.yml). Convert the baseline queries in steps 1, 2 and 6 into scheduled hunts rather than alerts; they need the asset-role join that Sigma cannot express.
- Hardening: restrict RDP and WinRM to jump hosts with host firewall rules (block 3389/5985/5986 workstation-to-workstation); require NLA and MFA on RDP gateways; deny `Remote Desktop Users` membership by Group Policy; set WinRM `AllowUnencrypted = false` and limit `TrustedHosts`; enforce admin tiering so privileged accounts cannot log on to workstations; enable Restricted Admin or Remote Credential Guard to stop credential exposure on the destination; turn on *Detailed File Share* auditing on servers only, where its volume is manageable.

See also: [Lateral movement playbook]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) · [Windows Security event IDs cheat sheet]({{ site.baseurl }}/cheatsheets/windows-event-ids.pdf) · [Sysmon cheat sheet]({{ site.baseurl }}/cheatsheets/sysmon.pdf) · [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/).
