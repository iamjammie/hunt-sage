---
title: "Playbook: Cloud & Identity (Entra ID, M365, AWS)"
permalink: /hunt/playbooks/cloud-identity/
excerpt: "Hunt token theft, risky sign-ins, illicit consent grants, mailbox rules, privileged role changes and AWS credential abuse."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1078.004 (Cloud Accounts), T1110 (Brute Force / Password Spray), T1556 (Modify Auth Process), T1528 (Steal App Access Token), T1098.001/.003 (Additional creds / roles), T1114.003 (Email Forwarding Rule), T1566 (Phishing; AiTM), T1537 (Transfer to Cloud Account), T1530 (Data from Cloud Storage) |
| **Tactics** | Initial Access, Persistence, Privilege Escalation, Credential Access, Exfiltration |
| **Data** | Entra ID: SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs; M365 Unified Audit (OfficeActivity / CloudAppEvents); AWS CloudTrail (management + S3 data events), GuardDuty, VPC Flow Logs |
| **Time-box** | 1-2 days |
| **Difficulty** | ★★★ |

Identity is the new perimeter. Most cloud intrusions begin with a **valid account**, not malware, and so the hunt is about *sessions, tokens, roles and consents*.

## Hypothesis

> *An adversary with a stolen password or session token will sign in from atypical locations/devices, register persistence (new MFA methods, app consents, mailbox rules, access keys), and escalate by assigning privileged roles or creating credentials on service principals.*

## Hunt steps: Entra ID / Microsoft 365

### 1. Password spray and brute force

```kql
SigninLogs
| where TimeGenerated > ago(2d) and ResultType in ("50126","50053","50057")      // bad password, locked, disabled
| summarize Failures = count(), Users = dcount(UserPrincipalName), Apps = make_set(AppDisplayName, 5) by IPAddress, bin(TimeGenerated, 1h)
| where Users > 20 and Failures > 30
```

Spray = **many accounts, few attempts each, one source** (or botnet-distributed). A success (`ResultType == 0`) from the same IP after failures is the pivot.

### 2. Atypical sign-ins and token theft (AiTM)

```kql
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == 0
| summarize Countries = dcount(tostring(LocationDetails.countryOrRegion)), Ips = dcount(IPAddress), Devices = dcount(tostring(DeviceDetail.deviceId))
          by UserPrincipalName, bin(TimeGenerated, 1d)
| where Countries >= 3
```

Hunt for:
- **Same session ID, different IP/user-agent** (token replay). Join `SigninLogs` on `SessionId` / `CorrelationId` across `AADNonInteractiveUserSignInLogs`.
- Sign-ins satisfying MFA via **token claim** then **immediately** registering a new MFA method.
- Legacy auth (`ClientAppUsed` in IMAP/POP/SMTP/Exchange ActiveSync) still allowed.
- Sign-ins from hosting/VPN ASNs, anonymous proxies, or user agents like `python-requests`, `axios`, `Go-http-client`.
- Risk signals: `RiskLevelDuringSignIn`, Entra ID Protection detections (`impossible travel`, `anomalous token`, `unfamiliar sign-in properties`).

### 3. Persistence: MFA methods, app consents, service principals

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("User registered security info","User registered all required security info","Add authentication method","Admin registered security info")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Actor, Target, Result
```

```kql
AuditLogs
| where OperationName in ("Consent to application","Add app role assignment grant to user","Add delegated permission grant","Add service principal credentials","Add owner to application","Update application – Certificates and secrets management")
| extend App = tostring(TargetResources[0].displayName), Actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, OperationName, App, Actor, ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
```

**Illicit consent grants** (OAuth phishing): user-consented apps with `Mail.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`, `offline_access`, `full_access_as_app`. Review newly consented multi-tenant apps with unfamiliar publishers.

### 4. Privileged role changes

```kql
AuditLogs
| where OperationName in ("Add member to role","Add eligible member to role","Add member to role in PIM completed (permanent)")
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator","Privileged Role Administrator","Application Administrator","Exchange Administrator","User Administrator","Privileged Authentication Administrator","Cloud Application Administrator")
| project TimeGenerated, OperationName, Role, Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName)
```

Also hunt **Conditional Access policy changes**, new federated domains / federation trust changes (Golden SAML-style; `Set domain authentication`, `Add unverified domain`), and changes to named locations.

### 5. Mailbox and data access (BEC)

```kql
OfficeActivity
| where TimeGenerated > ago(14d) and OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","New-TransportRule")
| where Parameters has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo","DeleteMessage","MarkAsRead","MoveToFolder") 
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
```

Suspicious rules: forward externally, delete/move to RSS or Archive, match keywords `invoice|payment|wire|bank`. Also mass `MailItemsAccessed` (E5 audit), `SearchExport`, mass SharePoint `FileDownloaded`/`FileSyncDownloadedFull`.

## Hunt steps: AWS

### 6. CloudTrail: credentials, privilege and recon

```sql
-- Athena over CloudTrail: IAM persistence and privilege changes
SELECT eventtime, useridentity.arn, eventname, sourceipaddress, useragent, requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey','CreateUser','CreateLoginProfile','UpdateLoginProfile','AttachUserPolicy',
                    'AttachRolePolicy','PutUserPolicy','PutRolePolicy','CreatePolicyVersion','AddUserToGroup',
                    'UpdateAssumeRolePolicy','CreateRole','DeactivateMFADevice','DeleteVirtualMFADevice')
  AND eventtime > date_format(date_add('day', -14, now()), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;
```

Hunts:
- **Defense evasion**: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteFlowLogs`, `DisableSecurityHub`, GuardDuty `DeleteDetector` / `UpdateDetector`
- **Recon bursts**: many `List*`/`Describe*`/`Get*` calls from one principal; `GetCallerIdentity` from new IP; `ListBuckets`, `ListSecrets`
- **Instance credential theft**: IMDS credentials (role `ASIA...` session keys) **used from an IP outside your AWS ranges**: compare `userIdentity.arn` for EC2 roles against source IPs
- **Console login** without MFA (`ConsoleLogin` where `additionalEventData.MFAUsed = No`), root usage (`userIdentity.type = Root`)
- **Data**: bursts of `GetObject`, `PutBucketPolicy` / `PutBucketAcl` making buckets public, `ModifySnapshotAttribute` / `ModifyDBSnapshotAttribute` sharing snapshots with unknown accounts (T1537), `CreateSnapshot` + share, `GetSecretValue` / `GetParameter` spikes
- **Compute abuse**: `RunInstances` of large/GPU instance types in unused regions (crypto-mining)

### 7. Kubernetes / containers (if relevant)

Audit logs: `exec` into pods, `create` of privileged pods or ClusterRoleBindings to `cluster-admin`, access to `secrets`, anonymous API requests, service account tokens used from outside the cluster.

## Triage

| Check | Interpretation |
|---|---|
| Source IP/ASN and geo vs. user's baseline | Hosting provider/VPN/TOR for a normal office worker = suspicious |
| Device compliance / join state | Unmanaged device obtaining tokens |
| Actions after sign-in within 10 minutes | MFA registration, inbox rule, consent, role change |
| Correlation across Entra, M365, AWS federation | One identity, multiple clouds |
| Is the user travelling/using a new device (HR, calendar)? | Benign explanation |

## Common false positives

Travel and mobile roaming, corporate VPN egress changes, IT admin bulk changes, CI/CD roles making many API calls, approved automation creating keys.

## Escalate when

Risky sign-in followed by persistence (MFA method, consent, inbox rule, key, role) or any privileged role/CA/federation change without a ticket. **Revoke sessions and refresh tokens** (not only reset passwords), remove attacker persistence, and review all mailbox/data access since first compromise.

## Validate and operationalise

- Emulate with Atomic Red Team's cloud tests (`T1098.003`, `T1078.004`, AWS and Azure suites) or [Stratus Red Team](https://github.com/DataDog/stratus-red-team) in a **sandbox** account/tenant.
- Detection: build analytics rules in Sentinel / CloudWatch / GuardDuty custom rules for the events above; many are one-line atomic rules.
- Hardening: phishing-resistant MFA (FIDO2/passkeys), Conditional Access with compliant-device + token protection, block legacy auth, restrict user consent, PIM with approval for admin roles, IMDSv2, least-privilege IAM, SCPs preventing log tampering, CloudTrail to a separate log-archive account with object lock.
