---
title: "Build a Threat Hunting Lab"
permalink: /labs/
excerpt: "A practical, low-cost lab you can build in an afternoon: logging, telemetry, a SIEM, and a place to detonate attack techniques safely."
---

You learn hunting by **generating attacker behaviour, finding it in logs, then writing the detection**. This page gets you a lab to do exactly that.

> **Safety first.** Keep the lab **isolated** (host-only/NAT network or a dedicated cloud VPC with no production connectivity), snapshot before every test, and never run offensive tooling against systems you do not own or have written authorisation to test.

## Lab architecture (minimal)

```text
                   ┌──────────────── isolated lab network ────────────────┐
 ┌───────────┐     │  ┌───────────┐   ┌────────────┐   ┌──────────────┐   │
 │ Hunter    │────►│  │ DC01      │   │ WS01       │   │ SIEM/Hunt    │   │
 │ laptop    │     │  │ Win Server│◄─►│ Win 10/11  │──►│ Splunk /     │   │
 └───────────┘     │  │ AD DS, DNS│   │ Sysmon+WEF │   │ Elastic /    │   │
                   │  └───────────┘   └────────────┘   │ Security Onion│  │
                   │        ▲               ▲          └──────────────┘   │
                   │  ┌───────────┐   ┌────────────┐                      │
                   │  │ SRV01     │   │ LIN01      │   (optional)         │
                   │  │ Win Server│   │ Ubuntu     │   Attacker VM (Kali) │
                   │  │ IIS/SMB   │   │ auditd     │   for emulation      │
                   │  └───────────┘   └────────────┘                      │
                   └───────────────────────────────────────────────────────┘
```

| Component | Spec (minimum) | Purpose |
|---|---|---|
| Hypervisor | 32 GB RAM / 8 cores / 250 GB SSD host (VirtualBox, VMware Workstation, Proxmox, Hyper-V) or a cloud account | Runs everything |
| **DC01**: Windows Server 2019/2022 | 2 vCPU, 4 GB | Active Directory, DNS, GPO; Kerberos/DCSync hunts |
| **WS01**: Windows 10/11 | 2 vCPU, 4 GB | Victim workstation; user activity |
| **SRV01**: Windows Server | 2 vCPU, 4 GB | File/web server; lateral movement and web-shell hunts |
| **LIN01**: Ubuntu Server | 1-2 vCPU, 2 GB | Linux hunting |
| **SIEM**: Splunk Free/Developer, Elastic stack, Security Onion, or Microsoft Sentinel (trial) | 4-8 vCPU, 8-16 GB | Collect, search, hunt |
| **ATTACKER** (optional): Kali / Parrot | 2 vCPU, 4 GB | External-style emulation |

Evaluation ISOs for Windows are available from the Microsoft Evaluation Center. Ready-made AD lab builders: **DetectionLab**, **Ludus**, **GOAD (Game of Active Directory)**, **Splunk Attack Range**, **HELK** (verify each project's maintenance status before adopting it).

## Step 1: Build AD

1. Install DC01, promote to a domain controller (e.g. `hunt.lab`).
2. Create OUs, ~20 users, a few groups, service accounts with SPNs (for Kerberoasting practice), and a few "admin" users.
3. Join WS01 and SRV01. Create realistic activity: logins, file shares, a web app on SRV01.

## Step 2: Turn on the logging that matters

Group Policy (Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy):

| Category | Enable (Success + Failure unless noted) |
|---|---|
| Account Logon | Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations |
| Account Management | User Account, Computer Account, Security Group Management |
| Detailed Tracking | **Process Creation** (+ *Include command line in process creation events*) |
| DS Access | Directory Service Access, Directory Service Changes (DC only) |
| Logon/Logoff | Logon, Logoff, Special Logon, Account Lockout |
| Object Access | File Share, Detailed File Share, Other Object Access Events (tasks) |
| Policy Change | Audit Policy Change, Authentication Policy Change |
| System | Security System Extension |

Then:

- **PowerShell**: Script Block Logging + Module Logging (GPO: Administrative Templates → Windows Components → Windows PowerShell)
- Increase Security log size (e.g. 1 GB) on DC and servers
- Enable Defender and keep **Tamper Protection** on, adding lab exclusions deliberately for test directories only when needed

## Step 3: Deploy Sysmon

```powershell
# On each Windows VM (as admin)
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
# Use a maintained config: SwiftOnSecurity/sysmon-config or olafhartong/sysmon-modular
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
# Update later:  Sysmon64.exe -c C:\Sysmon\newconfig.xml
```

Review the config before deploying it and pin the version. See the [Sysmon cheat sheet]({{ site.baseurl }}/cheatsheets/sysmon/).

## Step 4: Ship logs to a SIEM

| Option | How |
|---|---|
| **Splunk (free dev/trial)** | Install Universal Forwarder on each host; inputs for `WinEventLog://Security`, `WinEventLog://System`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `...PowerShell/Operational`; Splunk Add-on for Microsoft Windows + Sysmon |
| **Elastic** | Elastic Agent with the *Windows* and *Sysmon* integrations; Fleet-managed |
| **Security Onion** | Standalone distribution includes Elastic, Zeek, Suricata; ship host logs with Elastic Agent |
| **Microsoft Sentinel** | Log Analytics workspace + Azure Monitor Agent; Windows Security Events via AMA; Sysmon via Windows Event collection |
| **Velociraptor** | Lightweight agent for live queries and collection; great for hunts without a SIEM |

Verify ingestion before you attack anything:

```spl
| tstats count where index=* by host, sourcetype
```

```kql
Event | where TimeGenerated > ago(1h) | summarize count() by Computer, Source
```

## Step 5: Network visibility (optional but valuable)

Mirror the lab switch/vSwitch to a sensor running **Zeek** (and **Suricata**). Security Onion does this out of the box. Zeek logs feed the beaconing, DNS and lateral-movement hunts. See [Network & DNS (Zeek)]({{ site.baseurl }}/cheatsheets/network-zeek/).

## Step 6: Linux telemetry

On LIN01: install `auditd` with the [starter ruleset]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/), forward auth/audit logs, optionally install `osquery`.

## Step 7: Operate the lab

1. **Snapshot** every VM after a clean baseline.
2. Generate benign noise for a day or two (logins, browsing, scripts) so you have a baseline.
3. Run an [emulation exercise]({{ site.baseurl }}/labs/emulate-and-detect/).
4. Hunt it, write the detection, restore snapshots, repeat.

## Cloud lab variants

- **Entra ID / M365**: a free M365 developer tenant (where available) plus Sentinel free trial; test accounts only.
- **AWS**: a dedicated sandbox account with CloudTrail to S3 and Athena; use [Stratus Red Team](https://github.com/DataDog/stratus-red-team) for emulation; set billing alarms.
- **Kubernetes**: kind/minikube with audit logging and Falco.

## No lab? Use datasets

See [practice datasets]({{ site.baseurl }}/labs/datasets/) for pre-recorded attack telemetry you can load into any SIEM or analyse with Python.
