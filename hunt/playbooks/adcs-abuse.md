---
title: "Playbook: Active Directory Certificate Services (AD CS) Abuse"
permalink: /hunt/playbooks/adcs-abuse/
excerpt: "Hunt certificate requests with attacker-chosen identities, template tampering, NTLM relay to web enrolment, first-time certificate logons and CA key theft."
tactic: "Credential Access"
attack: [T1649, T1557.001, T1550]
difficulty: 3
timebox: "1-2 days"
data: [windows-security, adcs, edr]
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1649 (Steal or Forge Authentication Certificates), T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay, used for ESC8), T1550 (Use Alternate Authentication Material) |
| **Tactic** | Credential Access / Privilege Escalation / Persistence |
| **Data** | CA Security log 4886-4889 (requests), 4898-4900 (templates), 4876/4877 (CA backup); DC Security log 4768 (PKINIT), 4624; IIS logs on the CA for `/certsrv/`; client `Microsoft-Windows-CertificateServicesClient-Lifecycle-System`; EDR process creation |
| **Time-box** | 1-2 days |
| **Difficulty** | ★★★ |

## Background

AD CS is the enterprise PKI almost every domain has and almost nobody audits. A certificate with a client-authentication EKU is a credential: it authenticates via Kerberos PKINIT or Schannel, survives password resets, and lasts for its validity period (often years). SpecterOps' [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) catalogued the misconfigurations as **ESC1-ESC8** (later research added ESC9-ESC15):

| Code | Misconfiguration | What you see |
|---|---|---|
| ESC1 | Template lets the enrollee supply the subject (`ENROLLEE_SUPPLIES_SUBJECT`), has an auth EKU, low-priv enrol rights | Request with `SAN:upn=<other user>` in attributes |
| ESC2/3 | Any-purpose EKU or enrolment-agent EKU | Request on behalf of another user |
| ESC4 | Weak ACL on the template object | Template modified (4899/4900) then enrolled in |
| ESC6 | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | SAN supplied on *any* template |
| ESC7 | Dangerous CA permissions (ManageCA / ManageCertificates) | Pending request approved by unexpected account (4889) |
| ESC8 | Web enrolment (`/certsrv/`) accepts NTLM | Relayed machine or user auth → certificate issued |
| Golden certificate | CA private key stolen | 4876 backup, then certificates the CA never logged issuing |

The attacker outcome is the same in every case: a certificate for an identity they did not have, exchanged for a TGT (4768 with certificate fields) or an NT hash.

## Hypothesis

> *If AD CS is being abused, the CA will log certificate requests where the identity in the request differs from the requester, template objects will change shortly before enrolments, NTLM authentication to the CA web endpoint will arrive from hosts that never enrol, and domain controllers will see certificate-based Kerberos logons for accounts that have never used a certificate.*

## Data required

- On each CA, in the CA properties **Auditing** tab, tick **Issue and manage certificate requests**, **Change CA configuration**, **Change CA security settings** and **Back up and restore the CA database**, plus the advanced audit subcategory *Object Access > Audit Certification Services* (Success, Failure). CA auditing is **off by default**; without both settings, 4886-4900 are never written.
- Forward the CA Security log. Fields of interest in 4886/4887: `Attributes`, `Requester`, `Subject`, and the template name in the disposition message. Client side, `Microsoft-Windows-CertificateServicesClient-Lifecycle-System` records enrolments and renewals on the endpoint.
- DC Security log 4768 with the **Certificate Information** block (`CertIssuerName`, `CertSerialNumber`, `CertThumbprint`) populated for PKINIT; 4624 and IIS logs on the CA if web enrolment or CES/CEP is installed; EDR process creation with `OriginalFileName`.
- Template inventory: run [Locksmith](https://github.com/TrimarcJake/Locksmith) or [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) once so you know which templates are exposed before you hunt.

## Hunt steps

### 1. Requests that supply a Subject Alternative Name (ESC1 / ESC6)

Auto-enrolment never passes a SAN in the attribute string; the CA builds the subject from AD. A SAN in `Attributes` is a human or a tool.

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID in (4886, 4887)
| extend Attrs = tostring(EventData), Requester = column_ifexists("Requester", ""), Subject = column_ifexists("Subject", "")
| where Attrs has_any ("SAN:", "san:", "upn=", "dns=")
| extend SanUpn = extract(@"(?i)upn=([^&\s,""]+)", 1, Attrs)
| extend RequesterSam = tolower(extract(@"\\([^\\]+)$", 1, Requester)), SanSam = tolower(extract(@"^([^@]+)@", 1, SanUpn))
| where isnotempty(SanUpn) and RequesterSam != SanSam
| project TimeGenerated, Computer, EventID, Requester, SanUpn, Subject, Attrs
```

```spl
index=wineventlog (EventCode=4886 OR EventCode=4887) (Attributes="*SAN:*" OR Attributes="*san:*" OR Attributes="*upn=*")
| rex field=Attributes "(?i)upn=(?<san_upn>[^&\s,\"]+)"
| rex field=Requester "\\\\(?<requester_sam>[^\\\\]+)$"
| eval san_sam=lower(mvindex(split(san_upn,"@"),0)), requester_sam=lower(requester_sam)
| where san_sam!=requester_sam
| table _time host EventCode Requester san_upn Subject Attributes
```

Field names vary: Sentinel often leaves 4886/4887 unparsed in `EventData` XML (use `parse_xml` or `extract`); the Splunk Windows TA exposes `Requester`, `Attributes` and `Subject` directly. A SAN naming a **privileged** account or a DC machine account (`$`) from a non-admin requester is the ESC1 picture.

### 2. Template changes followed by enrolment (ESC4)

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID in (4898, 4899, 4900)
| extend Template = column_ifexists("TemplateInternalName", extract(@"Template[^:]*:\s*([^\r\n]+)", 1, tostring(EventData)))
| project TimeGenerated, Computer, EventID, SubjectUserName, Template, EventData
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(30d) and EventID == 4887
    | extend Template = extract(@"CertificateTemplate:\s*([^\r\n,]+)", 1, tostring(EventData)), Requester = column_ifexists("Requester", "")
    | project IssuedAt = TimeGenerated, Template, Requester
  ) on Template
| where IssuedAt between (TimeGenerated .. (TimeGenerated + 24h))
```

```spl
index=wineventlog (EventCode=4899 OR EventCode=4900)
| table _time host EventCode user Template_Internal_Name Template_Information
```

4898 is logged when the CA *loads* a template (bursts at service start are normal); 4899 is **template updated**; 4900 is **template security updated**. Any 4899/4900 outside a PKI change window is worth a look; one followed within a day by enrolments in the same template, especially by the modifying account, is the ESC4 chain. Also diff `msPKI-Certificate-Name-Flag` (bit `0x1` = enrollee supplies subject), `pKIExtendedKeyUsage` and the template ACL between inventory snapshots.

### 3. NTLM relay to web enrolment (ESC8)

The relay target is `http://<ca>/certsrv/certfnsh.asp`. The CA sees an NTLM network logon from an unexpected host, then a request for a machine or user certificate.

```kql
SecurityEvent
| where TimeGenerated > ago(14d) and EventID == 4624 and LogonType == 3
| where Computer in~ ("CA01.corp.local","CA02.corp.local")   // your CA hosts
| where AuthenticationPackageName == "NTLM" and TargetUserName !in~ ("ANONYMOUS LOGON")
| summarize Logons = count(), Accounts = make_set(TargetUserName, 20) by IpAddress, WorkstationName, bin(TimeGenerated, 1h)
| join kind=leftanti (
    SecurityEvent | where TimeGenerated between (ago(90d) .. ago(14d)) and EventID == 4624 and Computer in~ ("CA01.corp.local","CA02.corp.local") | distinct IpAddress
  ) on IpAddress
```

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM host IN ("CA01","CA02") Account_Name!="ANONYMOUS LOGON"
| stats count values(Account_Name) as accounts by Source_Network_Address Workstation_Name
| sort - count
```

Two strong tells: **`WorkstationName` in 4624 does not match the host that owns `IpAddress`** (the relay box presents the victim's name from its own IP), and a **machine account** (`HOST$`) authenticating to the CA from an IP that is not that host. Confirm in IIS logs (`POST /certsrv/certfnsh.asp`, `401` then `200` from the same client) and a 4886/4887 within seconds whose `Requester` is the relayed account. The relay is usually triggered by authentication coercion against a DC, so pair with the 4624 baselines in the [lateral movement playbook]({{ site.baseurl }}/hunt/playbooks/lateral-movement/).

### 4. First-time certificate logons (PKINIT) and `/getcredentials`

A stolen or forged certificate is cashed in at the KDC. 4768 then carries `CertIssuerName`, `CertSerialNumber` and `CertThumbprint`. Most user accounts never log on with a certificate; a first occurrence is the hunt.

```kql
let certlogons = SecurityEvent
| where EventID == 4768 and isnotempty(column_ifexists("CertThumbprint", ""))
| extend Thumb = tostring(column_ifexists("CertThumbprint", "")), Issuer = tostring(column_ifexists("CertIssuerName", ""));
let baseline = certlogons | where TimeGenerated between (ago(90d) .. ago(7d)) | distinct TargetUserName;
certlogons
| where TimeGenerated > ago(7d)
| join kind=leftanti baseline on TargetUserName
| summarize First = min(TimeGenerated), Count = count(), Sources = make_set(IpAddress, 10), Thumbs = make_set(Thumb, 5), Issuer = any(Issuer) by TargetUserName
```

```spl
index=wineventlog EventCode=4768 Certificate_Thumbprint=* Certificate_Thumbprint!="-"
| stats earliest(_time) as first latest(_time) as last count values(Client_Address) as sources values(Certificate_Serial_Number) as serials by Account_Name Certificate_Issuer_Name
| where first > relative_time(now(), "-7d@d")
```

Cross-check `CertSerialNumber` against the CA's issued list (`certutil -view` or 4887 history): **a serial the CA never issued means a forged (golden) certificate**. Also hunt accounts whose password was reset during an incident yet keep producing PKINIT 4768s: the certificate outlived the reset. `Rubeus asktgt /getcredentials` turns a certificate logon into the account's NT hash via PKINIT supplemental credentials; the DC sees an ordinary PKINIT 4768 followed shortly by NTLM (4776) activity for the same account from the same source.

### 5. Tooling and native command lines

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName in~ ("Certify.exe","Certipy.exe","ForgeCert.exe")
   or ProcessCommandLine has_any ("find /vulnerable","/enrolleeSuppliesSubject","/altname:","certipy find","certipy req","certipy auth","certipy shadow","certipy relay","certipy forge","-vulnerable -enabled")
   or (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-dstemplate","-catemplates","-v -template"))
   or (FileName =~ "certreq.exe" and ProcessCommandLine has_all ("-submit","-attrib") and ProcessCommandLine has "SAN:")
   or (ProcessCommandLine has "asktgt" and ProcessCommandLine has_any ("/certificate:","/getcredentials"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, ProcessCommandLine, InitiatingProcessFileName
```

```spl
index=sysmon EventCode=1
  (OriginalFileName IN ("Certify.exe","Certipy.exe","ForgeCert.exe")
   OR CommandLine="*find /vulnerable*" OR CommandLine="*/enrolleeSuppliesSubject*" OR CommandLine="*/altname:*"
   OR CommandLine="*certipy *" OR (Image="*\\certutil.exe" AND (CommandLine="*-dstemplate*" OR CommandLine="*-catemplates*"))
   OR (Image="*\\certreq.exe" AND CommandLine="*-submit*" AND CommandLine="*-attrib*" AND CommandLine="*SAN:*")
   OR (CommandLine="*asktgt*" AND (CommandLine="*/certificate:*" OR CommandLine="*/getcredentials*")))
| table _time host User ParentImage Image OriginalFileName CommandLine
```

Certipy usually runs from Linux and only shows on the CA as LDAP template reads (`CN=Certificate Templates,CN=Public Key Services`) and the request itself, so step 1 is the reliable catch. `certutil -pulse` forces auto-enrolment and is noisy on its own; it matters only right after a template change (step 2).

### 6. Golden certificate persistence (CA key theft)

```kql
SecurityEvent
| where TimeGenerated > ago(90d) and EventID in (4876, 4877)
| project TimeGenerated, Computer, EventID, SubjectUserName, SubjectDomainName, EventData
```

4876 is **CA backup started**, 4877 completed. Outside scheduled backup windows and backup accounts, this is how the CA private key leaves the box. Also hunt `certutil -backupkey`, MMC key export, and reads of `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` on the CA by non-CA processes (EDR file access). After key theft every certificate the attacker mints is trusted and **never appears in 4887**; step 4's serial cross-check is the only detection, and the fix is to re-key the CA.

## Triage

| Check | Interpretation |
|---|---|
| Requester vs. SAN / Subject | Different identities, especially SAN = privileged account = ESC1; same identity = probably legitimate manual request |
| Template in 4887 | Does it allow enrollee-supplied subject and an auth EKU? Check your Locksmith / PSPKIAudit output |
| Requester type | Machine account requesting a user certificate, or user requesting a machine template = abuse |
| Request origin | 4886 from the CA's own IIS worker (`/certsrv/`) with NTLM from a workstation = possible relay |
| 4768 serial number | Not in CA issued list = forged; in list but issued to a different requester = stolen/ESC1 |
| Timing | Template change → enrolment → PKINIT logon within hours = complete chain |
| Account history | First-ever certificate logon, or certificate logon after password reset = persistence in play |

## Common false positives

- PKI admins issuing web-server or service certificates with a SAN by hand (`certreq` / MMC): requester is a known admin, SAN is a **host name**
- NDES, Intune or MDM certificate connectors enrolling on behalf of devices from fixed service accounts
- Smart-card and Windows Hello for Business users: PKINIT 4768 is normal for them; baseline by group membership
- Scheduled CA backups (4876/4877) from the backup account; template edits in documented change windows; 4898 bursts at CA start

## Escalate when

Any 4886/4887 whose SAN names a privileged account or DC and whose requester is not; a template name-flag or ACL change with no change record; a 4768 certificate serial the CA did not issue; 4876 outside the backup schedule. Revoke the certificate, confirm the CRL/OCSP path works, reset the targeted account **and** decide whether the CA must be re-keyed.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1649` against a lab CA with a deliberately vulnerable template; replay a manual `certreq -submit -attrib "SAN:upn=..."` as a lab admin and confirm 4886/4887 carry the attribute and step 1 fires. For ESC8, verify the IIS and 4624 NTLM signals from a lab host rather than against production.
- Detection: [Certificate request with requester-supplied SAN]({{ site.baseurl }}/research/sigma/T1649-certificate-request-with-san-esc1.yml), [AD CS enumeration or abuse tooling]({{ site.baseurl }}/research/sigma/T1649-adcs-enumeration-tooling.yml); pair with [Pass-the-hash]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml) for post-`/getcredentials` NTLM use.
- Hardening: remove `ENROLLEE_SUPPLIES_SUBJECT` from every template with a client-auth EKU or require **CA certificate manager approval**; clear `EDITF_ATTRIBUTESUBJECTALTNAME2`; disable NTLM on web enrolment and CES, enable **Extended Protection for Authentication** with HTTPS only, or remove the web enrolment role; restrict enrolment permissions; enable **strong certificate mapping** (`StrongCertificateBindingEnforcement = 2`, KB5014754) so certificates without the SID extension fail; audit with Locksmith / PSPKIAudit on a schedule and treat the CA as tier 0.

See also: [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) for other ticket-based credential access, [DCSync]({{ site.baseurl }}/hunt/playbooks/dcsync/), [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/) for NTLM relay precursors, and the [Active Directory attacks cheat sheet]({{ site.baseurl }}/cheatsheets/active-directory-attacks.pdf).
