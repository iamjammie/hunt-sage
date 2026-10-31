---
title: "Playbook: Lateral Movement"
permalink: /hunt/playbooks/lateral-movement/
excerpt: "Hunt SMB/PsExec, RDP, WinRM, WMI and pass-the-hash/ticket movement using logon graphs and fan-out analysis."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1021.001 (RDP), T1021.002 (SMB/Admin Shares), T1021.006 (WinRM), T1047 (WMI), T1569.002 (Service Execution), T1550.002/.003 (PtH / PtT) |
| **Tactic** | Lateral Movement |
| **Data** | Security 4624/4625/4648/4672/4776, 5140/5145 (shares), 7045/4697 (services); Sysmon 1/3; network flow |
| **Time-box** | 1-2 days |
| **Difficulty** | ★★★ |

## Hypothesis

> *Attackers moving laterally authenticate to many hosts with one account or from one source, use admin-only channels (ADMIN$/C$, service creation, WinRM, WMI), and do so from hosts that do not normally administer others.*

## Data required

Authentication (4624 with LogonType, source IP, auth package), service installs (7045), share access (5140/5145), process creation with parent (`services.exe`, `wmiprvse.exe`, `wsmprovhost.exe`, `winrshost.exe` as parents), network flows for 135/445/3389/5985/5986.

**Logon type quick ref:** 2 interactive · 3 network · 4 batch · 5 service · 7 unlock · 9 NewCredentials (RunAs /netonly, Mimikatz PtH uses this) · 10 RemoteInteractive (RDP) · 11 cached.

## Hunt steps

### 1. Fan-out: one account → many hosts

```kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624 and LogonType in (3, 10)
| where TargetUserName !endswith "$" and TargetUserName !in~ ("ANONYMOUS LOGON")
| summarize Hosts = dcount(Computer), HostList = make_set(Computer, 25), Sources = dcount(IpAddress)
          by TargetUserName, bin(TimeGenerated, 1h)
| where Hosts >= 10
| order by Hosts desc
```

```spl
index=wineventlog EventCode=4624 (Logon_Type=3 OR Logon_Type=10) Account_Name!="*$" Account_Name!="ANONYMOUS LOGON"
| bin _time span=1h
| stats dc(ComputerName) as hosts values(ComputerName) as targets by Account_Name, _time
| where hosts>=10
```

Tune thresholds per role; vulnerability scanners, patching and monitoring accounts will dominate; allow-list them explicitly.

### 2. Rare source → destination admin paths

Build a 30-day baseline of (source host, destination, logon type) pairs and alert on new pairs where the destination is a server/DC and the source is a workstation.

```kql
let baseline = SecurityEvent | where TimeGenerated between (ago(30d) .. ago(1d)) and EventID == 4624 and LogonType == 3
  | distinct IpAddress, Computer;
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624 and LogonType == 3 and IpAddress !in ("-","::1","127.0.0.1")
| distinct IpAddress, Computer, TargetUserName
| join kind=leftanti baseline on IpAddress, Computer
```

### 3. PsExec-style service execution

New services are logged as **4697** (Security log; needs *Audit Security System Extension*) and **7045** (System log, Service Control Manager).

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4697
| where ServiceFileName has_any ("\\\\", "ADMIN$", "%COMSPEC%", "cmd.exe /c", "powershell", "\\Temp\\", "PSEXESVC")
   or ServiceName =~ "PSEXESVC"
| project TimeGenerated, Computer, SubjectUserName, ServiceName, ServiceFileName
```

```spl
index=wineventlog source="WinEventLog:System" EventCode=7045
  (Service_File_Name="*ADMIN$*" OR Service_File_Name="*%COMSPEC%*" OR Service_File_Name="*cmd.exe /c*"
   OR Service_File_Name="*powershell*" OR Service_File_Name="*\\Temp\\*" OR Service_Name="PSEXESVC")
| table _time host Service_Name Service_File_Name Service_Account
```

Process view: child processes of `services.exe` running `cmd.exe`/`powershell.exe`, or binaries from `\ADMIN$` / `C:\Windows\` that were written seconds earlier (5145 + Sysmon 11).

### 4. WMI, WinRM and DCOM

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wmiprvse.exe","wsmprovhost.exe","winrshost.exe")
| where FileName in~ ("cmd.exe","powershell.exe","rundll32.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Impacket `wmiexec` leaves `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<epoch> 2>&1` command lines.

### 5. RDP

4624 type 10 (and 4778/4779 reconnect/disconnect). Hunt for: RDP **from servers/workstations to workstations** (peer-to-peer), RDP from the internet-facing zone, and RDP through tunnels (source IP 127.0.0.1 or ::1 with type 10: tunnelled via SSH/ngrok/chisel).

```kql
SecurityEvent | where EventID == 4624 and LogonType == 10 and IpAddress in ("127.0.0.1","::1")
```

### 6. Pass-the-hash / pass-the-ticket indicators

- **PtH**: 4624 type 3 + NTLM + `KeyLength` 0 (see [Sigma rule]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml)) and, for local accounts, **type 9** logons with `LogonProcessName: seclogo` and `AuthenticationPackageName: Negotiate` followed by network authentication as a *different* user
- **Overpass-the-hash**: 4768 TGT request with RC4 for an account that normally uses AES, from an unexpected host
- **Pass-the-ticket**: 4769 service tickets for a user with **no preceding 4768** from that source; ticket lifetimes beyond policy (Golden Ticket)
- See the detailed walk-through: [Hunting lateral movement: pass-the-hash]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/)

### 7. Explicit-credential logons

`4648` (logon with explicit credentials) from one account to many targets, especially with `TargetServerName` ≠ `localhost`.

## Triage

1. Source: is it a jump host/management server? If not, why is it administering others?
2. Account: privileged? Did it just appear on a host it never touched?
3. What ran at the destination within 5 minutes of the logon? (4688/Sysmon 1)
4. Is there a credential-theft precursor on the source (LSASS access, Kerberoast)? See [LSASS]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/).
5. How many destinations? Chain them: A→B→C is a lateral path; build the graph.

## Common false positives

Patch management, EDR deployment, backup, vulnerability scanners, admin jump boxes, SCCM/Intune, helpdesk remote tools. Build allow-lists as **account + source + destination group**.

## Escalate when

Privileged account activity from a non-admin source, `PSEXESVC`/`ADMIN$` execution from unexpected hosts, or any movement chain tied to credential theft.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1021.002`, `T1021.006`, `T1047`, `T1569.002`
- Detection: [Suspicious service install]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml), [Pass-the-hash]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml)
- Hardening: LAPS for local admin; deny network logon for local accounts; tiering/PAWs; restrict SMB/RDP/WinRM between workstations with host firewall; disable NTLM where feasible; Credential Guard.
