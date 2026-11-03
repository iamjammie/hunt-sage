---
title: "Playbook: Network Share & File Discovery"
permalink: /hunt/playbooks/network-share-discovery/
excerpt: "Catch the hands-on-keyboard sweep for file shares and the secrets inside them: enumeration tooling, SMB fan-out, and honey-share touches."
tactic: "Discovery"
attack: [T1135, T1083, T1039, T1021.002, T1018]
difficulty: 2
timebox: "3-5 hours"
data: [windows-security, edr, sysmon, zeek]
---

{% include playbook-meta.html %}

**Data used:** EDR/Sysmon process creation; Windows Security file-share auditing (5140 network share accessed, 5145 detailed file share) on file servers; 4624 type 3; Zeek `smb_mapping`/`smb_files`

## Background

Between landing and acting, an intruder has to answer one question: where are the files worth taking, and which shares can this account reach? That reconnaissance is loud if you are collecting share-access events, and quiet if you are not, which is the usual state. This hunt assumes the attacker is enumerating shares and then reading from them, and looks for the two shapes that leaves:

1. **Tooling and command bursts** on an endpoint: `net view`, `net share`, PowerShell share cmdlets, or named tools (PowerView `Find-DomainShare`/`Invoke-ShareFinder`, SharpShares, Snaffler, smbmap, NetExec `--shares`) that walk the domain for shares and flag the interesting ones.
2. **Fan-out at the file server**: one account mapping or touching many shares across many hosts in a short window, reading sensitive file types, or touching a share nobody should (a decoy).

The best signal is breadth over time: a normal user touches a handful of shares they always use; a sweep touches dozens it has never touched before. So the queries lean on stacking, `dcount` and first-seen rather than single events.

## Hypothesis

> *If an adversary is hunting for data, then we would see one account enumerate or access an unusually large number of distinct shares or hosts in a short window, run share-enumeration tooling, or touch file types and shares (secrets, backups, decoys) it has never touched before.*

## Data required

- Process creation with command line (EDR or Sysmon 1 + 4688 with command-line auditing on) for step 1.
- **File-share auditing on file servers**: enable *Audit File Share* (5140) and *Audit Detailed File Share* (5145). 5145 is high-volume, so scope it to servers that hold sensitive data and forward centrally. Without it, steps 2-4 are blind.
- 4624 type 3 (network logon) for host fan-out when 5145 is unavailable.
- Zeek `smb_mapping` and `smb_files` if you have network sensors covering the file-server segment.

## Hunt steps

### 1. Share-enumeration tooling and command bursts

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName in~ ("net.exe","net1.exe") and ProcessCommandLine has_any ("view","share","use"))
     or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any
         ("Get-SmbShare","Find-DomainShare","Invoke-ShareFinder","Get-NetShare","Get-ChildItem -Recurse"))
     or ProcessCommandLine has_any ("SharpShares","Snaffler","smbmap",".ListShares()","--shares")
| summarize Commands = make_set(ProcessCommandLine, 20), Count = count()
          by DeviceName, AccountName, bin(Timestamp, 15m)
| where Count >= 3
| order by Count desc
```

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ((Image IN ("*\\net.exe","*\\net1.exe") AND CommandLine IN ("*view*","*share*","*use*"))
   OR (Image IN ("*\\powershell.exe","*\\pwsh.exe") AND CommandLine IN
       ("*Get-SmbShare*","*Find-DomainShare*","*Invoke-ShareFinder*","*Get-NetShare*"))
   OR CommandLine IN ("*SharpShares*","*Snaffler*","*smbmap*","*--shares*"))
| bin _time span=15m
| stats values(CommandLine) as commands count by host User _time
| where count>=3
```

A single `net view` is normal; three or more share-enumeration commands from one user in fifteen minutes, especially from a workstation, is the recon pattern.

### 2. SMB share fan-out: one account, many shares/hosts

The core behavioural query. Baseline each account's normal breadth, then flag the outliers.

```kql
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 5140
| extend Share = tostring(ShareName)
| summarize Shares = dcount(Share), Servers = dcount(Computer),
            ShareList = make_set(Share, 30)
          by SubjectUserName, SubjectUserSid, bin(TimeGenerated, 1h)
| where Shares >= 10 or Servers >= 5
| order by Shares desc
```

```spl
index=wineventlog EventCode=5140
| bin _time span=1h
| stats dc(Share_Name) as shares dc(host) as servers values(Share_Name) as share_list
        by Account_Name _time
| where shares>=10 OR servers>=5
| sort - shares
```

Tune the thresholds to your environment; start high and lower them until the results are reviewable. A service account that always touches many shares is a baseline exclusion, not evidence.

### 3. First-seen shares per account (baseline)

Fan-out catches volume; first-seen catches an account suddenly reaching shares it never has before, which survives a slow-and-low sweep.

```kql
let history = SecurityEvent
    | where TimeGenerated between (ago(45d) .. ago(2d)) and EventID == 5140
    | distinct SubjectUserName, ShareName;
SecurityEvent
| where TimeGenerated > ago(2d) and EventID == 5140
| join kind=leftanti history on SubjectUserName, ShareName
| summarize NewShares = dcount(ShareName), Sample = make_set(ShareName, 20)
          by SubjectUserName
| where NewShares >= 5
| order by NewShares desc
```

### 4. Sensitive file types and detailed access (5145)

When detailed file-share auditing is on, look for reads of the file names that matter.

```kql
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 5145
| extend File = tostring(RelativeTargetName)
| where File has_any (".kdbx",".config","unattend.xml","web.config","id_rsa",".ppk",
        ".pem",".bak",".vmdk","NTDS.dit","GroupPolicy","sysvol")
| summarize Count = count(), Files = make_set(File, 30), Hosts = dcount(Computer)
          by SubjectUserName, bin(TimeGenerated, 1h)
| order by Count desc
```

### 5. Honey-share touches (high-fidelity)

Stand up a share that no business process uses, with an inviting name (`Finance_Backup`, `HR_Archive`, `Admin$Tools`), SACL it, and alert on **any** 5140/5145 for it. There is no legitimate access, so it needs no tuning.

```spl
index=wineventlog (EventCode=5140 OR EventCode=5145) Share_Name IN ("*\\Finance_Backup*","*\\HONEY*","*Decoy*")
| table _time host Account_Name Source_Address Share_Name Relative_Target_Name
```

### 6. Zeek SMB fan-out (network view)

If you lack file-server auditing but have Zeek, the mapping and file logs give you breadth from the wire.

```spl
index=zeek sourcetype=zeek_smb_mapping
| bin _time span=1h
| stats dc(path) as shares dc(dest_ip) as servers values(path) as share_list by id.orig_h _time
| where shares>=10 OR servers>=5
| sort - shares
```

## Triage

| Check | Interpretation |
|---|---|
| Source is a workstation enumerating many servers' shares | Classic discovery from a foothold |
| Account's first-seen share count spikes | Account is being driven somewhere new; compare with its role |
| Tooling names in the command line (SharpShares, Snaffler, ShareFinder) | Not ambiguous: investigate the host now |
| Sensitive file types read (`.kdbx`, `id_rsa`, `web.config`, `NTDS.dit`) | Collection is already underway, not just discovery |
| Any honey-share touch | True positive by construction |
| Vulnerability scanner or inventory tool as the source | Likely benign; confirm the asset and exclude by SID, not by name |

## Common false positives

- Backup, inventory, DLP and vulnerability-scanning tools that enumerate shares by design (exclude by account SID).
- File-server migrations and audits that legitimately walk every share.
- Power users and IT staff who routinely touch many shares.
- Logon scripts and GPO drive-mapping that produce broad but consistent, baselineable access.

## Escalate when

Share-enumeration tooling runs on an endpoint, an account's first-seen share breadth spikes with reads of sensitive file types, or a decoy share is touched. Preserve the file-server audit events, identify every share and file the account reached, and treat it as pre-exfiltration: check the same account and host against the [data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) playbook.

## Validate and operationalise

- **Emulate:** `Invoke-AtomicTest T1135` (net view / Get-SmbShare enumeration) and `T1083` (file & directory discovery) in a lab; walk a decoy share to confirm your 5140/5145 pipeline fires.
- **Detection:** [Share-enumeration tooling on the command line]({{ site.baseurl }}/research/sigma/T1135-share-enumeration-tooling-command-line.yml) and [Access to a decoy / honey share]({{ site.baseurl }}/research/sigma/T1135-honey-share-access.yml).
- **Hardening:** enable *Audit File Share* and scope *Audit Detailed File Share* to sensitive servers; apply least-privilege share and NTFS ACLs so a single account cannot read everything; remove stale and over-shared folders; deploy honey shares with alerting; disable SMBv1.

See also: [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) for the account and host recon that usually precedes a share sweep, [lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/), and the [Windows Security event ID sheet]({{ site.baseurl }}/cheatsheets/windows-event-ids/).

{% include playbook-footer.html %}
