---
title: "Playbook: Kerberoasting & AS-REP Roasting"
permalink: /hunt/playbooks/kerberoasting/
excerpt: "Spot offline-crackable Kerberos ticket requests on the domain controller."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting) |
| **Tactic** | Credential Access |
| **Data** | Domain controller Security log: 4769 (service ticket), 4768 (TGT request); LDAP query telemetry if available |
| **Time-box** | 2-3 hours |
| **Difficulty** | ★★☆ |

## Background

- **Kerberoasting**: any authenticated domain user can request a service ticket (TGS) for any SPN. The ticket is encrypted with the service account's key, so an attacker can crack it **offline**. Weak, user-owned service-account passwords fall quickly. Tools: Rubeus, Impacket `GetUserSPNs.py`, PowerView.
- **AS-REP roasting**: accounts with *"Do not require Kerberos preauthentication"* let anyone request an AS-REP encrypted with the user's key; also crackable offline.

The attacker usually requests **RC4-HMAC (etype 0x17)** tickets because they crack fastest, even though AES is supported. That downgrade is the main signal in environments that otherwise use AES.

## Hypothesis

> *If Kerberoasting is occurring, one account will request service tickets for many distinct SPNs in a short window, often with encryption type 0x17, for user-owned (non-computer) service accounts.*

## Data required

- Audit **Kerberos Service Ticket Operations** (Success) → 4769, on **all DCs** (ticket requests land on whichever DC served them)
- Audit **Kerberos Authentication Service** → 4768
- Know which accounts have SPNs and which are legitimately RC4-only

## Hunt steps

### 1. Burst of distinct SPNs requested by one account

```kql
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4769
| where ServiceName !endswith "$" and ServiceName !~ "krbtgt"
| where TicketEncryptionType == "0x17"
| summarize Spns = dcount(ServiceName), SpnList = make_set(ServiceName, 20), Count = count()
          by TargetUserName, IpAddress, bin(TimeGenerated, 10m)
| where Spns >= 5
| order by Spns desc
```

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=10m
| stats dc(Service_Name) as spns values(Service_Name) as spn_list count by Account_Name, Client_Address, _time
| where spns>=5
```

Field names depend on the add-on version (`Client_Address` vs. `IpAddress`, `TargetUserName` vs. `Account_Name`). Remove the RC4 filter in AES-only environments to see *any* burst.

### 2. RC4 tickets for accounts that should use AES

List accounts with `msDS-SupportedEncryptionTypes` not including RC4 but receiving RC4 tickets; or simply chart RC4 4769 per service over time. A sudden RC4 request for an AES-capable service is anomalous.

```kql
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17" and ServiceName !endswith "$"
| summarize Requests = count(), Requesters = dcount(TargetUserName) by ServiceName
| order by Requests desc
```

### 3. Honey SPN (high-fidelity)

Create a fake service account with an SPN (long random password, no real use, logon denied). **Any** 4769 for it is a Kerberoast attempt. Alert on it with zero tuning.

### 4. AS-REP roasting

```kql
SecurityEvent
| where EventID == 4768 and TicketEncryptionType == "0x17" and PreAuthType == "0"
| project TimeGenerated, TargetUserName, IpAddress
```

Also enumerate exposed accounts (defensive):

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth | Select SamAccountName
```

### 5. Recon preceding it

SPN enumeration via LDAP `(servicePrincipalName=*)`, `setspn -T <domain> -Q */*`, or PowerView `Get-DomainUser -SPN`: look in EDR command lines.

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("setspn -q","setspn.exe -q","GetUserSPNs","Invoke-Kerberoast","kerberoast","Get-DomainUser -SPN","asktgs","/tgtdeleg")
```

## Triage

| Check | Interpretation |
|---|---|
| Source host/IP | Workstation of a non-admin user requesting dozens of SPNs = classic |
| Which SPNs? | Privileged service accounts (SQL, backup, admin-tier) = high impact |
| Same source later authenticating as a requested account? | Cracked and used (check 4624 for that account from new host) |
| Time pattern | Burst within seconds is tool-driven |

## Common false positives

- Vulnerability scanners and inventory tools that enumerate SPNs
- Legacy apps hard-coded to RC4
- Admins running `setspn` during troubleshooting

## Escalate when

Burst from a non-admin workstation or any request for a honey SPN. Reset targeted service-account passwords (25+ random chars or switch to **gMSA**), and review the source host.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1558.003` (Rubeus/PowerShell), `T1558.004`
- Detection: [Kerberoasting via RC4 TGS requests]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml)
- Hardening: gMSA for services; AES-only (`msDS-SupportedEncryptionTypes`, disable RC4 where feasible); long random passwords; remove unnecessary SPNs; require preauth everywhere.

See also: [Active Directory attacks cheat sheet]({{ site.baseurl }}/cheatsheets/active-directory-attacks.pdf).
