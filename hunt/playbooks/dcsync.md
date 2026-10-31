---
title: "Playbook: DCSync"
permalink: /hunt/playbooks/dcsync/
excerpt: "Catch directory replication requests from non-domain-controller accounts."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1003.006 (DCSync) |
| **Tactic** | Credential Access |
| **Data** | DC Security log: 4662 (operation on an AD object) with *Audit Directory Service Access*; network: DRSUAPI RPC (Zeek `dce_rpc.log`) |
| **Time-box** | 2 hours |
| **Difficulty** | ★★☆ |

## Background

DCSync abuses the Directory Replication Service Remote Protocol (MS-DRSR). An account with **Replicating Directory Changes** and **Replicating Directory Changes All** (usually Domain Admins, Enterprise Admins, DCs) can ask a DC to replicate password data, including `krbtgt`. Mimikatz `lsadump::dcsync` and Impacket `secretsdump.py` do this over the network with no code on the DC.

Extended-right GUIDs in event 4662 `Properties`:

| GUID | Right |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

## Hypothesis

> *If an adversary has replication rights, we will see 4662 events with the replication GUIDs where `SubjectUserName` is not a domain controller computer account (or the known Entra Connect sync account).*

## Data required

- **Audit Directory Service Access** (Success) on DCs, and a SACL on the domain root object for "Everyone / Control Access" (default domain policy typically includes it; verify)
- A list of legitimate replicators: DC machine accounts, Entra Connect `MSOL_*` / `AAD_*` account, Azure ATP/Defender for Identity sensor accounts

## Hunt steps

### 1. 4662 with replication GUIDs from non-DC accounts

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4662
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ad-9c07-11d1-f79f-00c04fc2dcd2","89e95b76-444d-4c62-991a-0facbeda640c")
| where SubjectUserName !endswith "$"
| where SubjectUserName !startswith "MSOL_" and SubjectUserName !startswith "AAD_"
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName, SubjectLogonId, Properties
```

```spl
index=wineventlog EventCode=4662
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
  NOT Account_Name="*$"
| stats count by Account_Name, Computer
```

Correlate the 4662 `SubjectLogonId` with the matching **4624** on the DC to find the **source IP**. If the IP is not a DC, it is DCSync.

### 2. Who *can* DCSync? (exposure review)

```powershell
# Requires ActiveDirectory module
$root = (Get-ADDomain).DistinguishedName
(Get-ACL "AD:\$root").Access |
  Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
  Select IdentityReference, ObjectType, AccessControlType
```

Unexpected principals = standing risk and a backdoor candidate (attackers add replication rights to persist; see event **5136** for ACL changes on the domain object, or 4670).

### 3. Network view

Zeek: `dce_rpc.log` with `endpoint == "drsuapi"` and `operation == "DRSGetNCChanges"` from a non-DC source.

### 4. Tool strings

```kql
DeviceProcessEvents | where ProcessCommandLine has_any ("lsadump::dcsync","secretsdump","/domain:" ) and ProcessCommandLine has_any ("dcsync","secretsdump","krbtgt")
```

## Triage

- Source IP and host; is it a DC, Entra Connect server, or a workstation/server?
- Which object was replicated? `krbtgt`, all users, or one account?
- Was a replication right recently granted (5136/4670)?
- Follow-on: Golden Ticket use (TGTs with anomalous lifetime, 4768/4769 for users that did not log on)

## Common false positives

Entra Connect sync, Defender for Identity, backup/replication products, DC promotion. All should be enumerable and few.

## Escalate when

Any non-DC, non-allow-listed source performs replication. This implies **Domain Admin–equivalent compromise**. IR should plan for krbtgt double-reset, privileged credential rotation and AD forensic review.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1003.006`
- Detection: [DCSync replication from non-DC]({{ site.baseurl }}/research/sigma/T1003.006-dcsync-replication.yml)
- Hardening: minimise replication rights; tiered admin model; monitor ACL changes on the domain root; protect/rotate `krbtgt` regularly.
