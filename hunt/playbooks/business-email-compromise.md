---
title: "Playbook: Business Email Compromise & Mailbox Abuse"
permalink: /hunt/playbooks/business-email-compromise/
excerpt: "Find the mailbox rules, forwarding, delegations, consents and token-replay sign-ins that follow a stolen Microsoft 365 account."
tactic: "Collection"
attack: [T1114.002, T1114.003, T1564.008, T1098.002, T1078.004, T1621, T1556.006]
difficulty: 2
timebox: "3-5 hours"
data: [m365-audit, entra-id, email]
---

{% include playbook-meta.html %}

**Data used:** Microsoft 365 Unified Audit Log (Exchange and Entra workloads: `OfficeActivity`, `CloudAppEvents`), Entra ID `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`; mail-flow / transport logs

## Background

Business email compromise rarely involves malware. The adversary phishes or buys a password, defeats MFA with an adversary-in-the-middle (AiTM) proxy or push fatigue, and then lives inside the mailbox. The goal is money: redirect a supplier payment, insert a fraudulent invoice, or hijack a payroll change. Everything they do to stay hidden and keep access leaves an audit trail in Exchange Online and Entra ID:

- **Hiding rules**: inbox rules that delete, mark as read or move replies to folders nobody checks (`RSS Feeds`, `RSS Subscriptions`, `Archive`, `Conversation History`, `Junk Email`), typically keyed on words such as *invoice*, *payment*, *wire*, *bank*, *password*, *hacked*.
- **Forwarding**: `ForwardingSmtpAddress` on the mailbox, `ForwardTo`/`RedirectTo` in a rule, or a tenant-wide transport rule redirecting mail to an external domain.
- **Delegation**: `FullAccess` or `SendAs` granted to a second compromised account or a freshly created one, so access survives a password reset.
- **OAuth consent**: a user grants an attacker-controlled app `Mail.Read`, `Mail.ReadWrite`, `offline_access`; the refresh token keeps working after the password changes.
- **MFA tampering**: a new authenticator or phone number registered minutes after a sign-in from a new country.
- **Reconnaissance**: searches and bulk reads (`MailItemsAccessed`) for finance threads before the fraudulent email is sent.

Password resets alone do not evict this adversary. The hunt is for the persistence objects and the sessions, not the sign-in that started it.

## Hypothesis

> *If a mailbox has been taken over for BEC, then we would see an inbox rule, forwarding setting, delegation or OAuth consent created shortly after an anomalous sign-in (new country, new ASN, AiTM user agent, no MFA claim), followed by bulk mail access or searches for payment-related terms.*

## Data required

- **Unified Audit Log** switched on for the tenant (`Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`); Exchange mailbox auditing is on by default for E3/E5 but verify `AuditEnabled` on mailboxes that were migrated.
- `MailItemsAccessed`, `Send` and `SearchQueryInitiatedExchange` require **Purview Audit (Premium)** / E5 licences; without them you still have the rule, forwarding, delegation and consent events.
- Entra ID sign-in and audit logs exported to the SIEM (diagnostic settings: `SignInLogs`, `NonInteractiveUserSignInLogs`, `AuditLogs`, `RiskyUsers`).
- Know your **accepted domains** and legitimate forwarding targets (partner domains, archiving services) so you can exclude them.
- Latency: Unified Audit Log events can take 30-60 minutes to appear; `MailItemsAccessed` is aggregated per two-minute bin.

## Hunt steps

### 1. Inbox rules that hide or delete mail

```kql
OfficeActivity
| where TimeGenerated > ago(30d) and OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend P = parse_json(Parameters)
| mv-apply P on (summarize Params = make_bag(bag_pack(tostring(P.Name), tostring(P.Value))))
| extend Delete = tostring(Params.DeleteMessage), MoveTo = tostring(Params.MoveToFolder),
         MarkRead = tostring(Params.MarkAsRead), Subject = tostring(Params.SubjectContainsWords),
         Body = tostring(Params.BodyContainsWords), From = tostring(Params.From)
| where Delete == "True" or MarkRead == "True"
   or MoveTo has_any ("RSS", "Archive", "Conversation History", "Junk", "Deleted", "Notes")
   or Subject has_any ("invoice", "payment", "wire", "bank", "remit", "password", "hacked", "suspicious", "phish")
| project TimeGenerated, UserId, Operation, ClientIP, Delete, MarkRead, MoveTo, Subject, Body, From
| order by TimeGenerated desc
```

```spl
sourcetype="o365:management:activity" Workload=Exchange Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| spath output=pname path="Parameters{}.Name" | spath output=pvalue path="Parameters{}.Value"
| eval params=mvzip(pname, pvalue, "=")
| eval delete=if(match(params,"DeleteMessage=True"),1,0), markread=if(match(params,"MarkAsRead=True"),1,0)
| eval moveto=mvindex(pvalue, mvfind(pname,"MoveToFolder")), subj=mvindex(pvalue, mvfind(pname,"SubjectContainsWords"))
| where delete=1 OR markread=1 OR match(moveto,"(?i)rss|archive|conversation history|junk|deleted|notes") OR match(subj,"(?i)invoice|payment|wire|bank|remit|password|hacked|phish")
| table _time, UserId, Operation, ClientIP, delete, markread, moveto, subj
```

Rules with single-character names (`.`, `,`, `a`), empty names, or `StopProcessingRules=True` are extra signal. Note the `ClientIP`: a rule created through Outlook on the web from an IP that is not the user's usual ASN is the classic BEC fingerprint.

### 2. Forwarding to external addresses

```kql
let accepted = dynamic(["contoso.com", "contoso.onmicrosoft.com"]);   // your accepted domains
OfficeActivity
| where TimeGenerated > ago(30d) and OfficeWorkload == "Exchange"
| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule", "New-TransportRule", "Set-TransportRule")
| where Parameters has_any ("ForwardingSmtpAddress", "ForwardingAddress", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "RedirectMessageTo", "BlindCopyTo")
| extend Target = extract(@"(?i)(?:ForwardingSmtpAddress|ForwardTo|RedirectTo|ForwardAsAttachmentTo|RedirectMessageTo|BlindCopyTo)[^@]*@([A-Za-z0-9.-]+)", 1, Parameters)
| where isnotempty(Target) and not(Target in~ (accepted))
| project TimeGenerated, UserId, Operation, ClientIP, Target, Parameters
```

```spl
sourcetype="o365:management:activity" Workload=Exchange Operation IN ("Set-Mailbox","New-InboxRule","Set-InboxRule","New-TransportRule","Set-TransportRule")
| spath output=pname path="Parameters{}.Name" | spath output=pvalue path="Parameters{}.Value"
| eval params=mvzip(pname, pvalue, "=") | search params IN ("*Forward*","*Redirect*","*BlindCopyTo*")
| rex field=params "@(?<target_domain>[A-Za-z0-9.-]+)"
| where NOT target_domain IN ("contoso.com","contoso.onmicrosoft.com")
| table _time, UserId, Operation, ClientIP, target_domain, params
```

Also pull the current state, not only the change events: `Get-Mailbox -ResultSize Unlimited | Where ForwardingSmtpAddress -ne $null` and `Get-InboxRule` across mailboxes catch forwarding configured before your log retention began.

### 3. Delegations and permission grants

```kql
OfficeActivity
| where TimeGenerated > ago(30d) and OfficeWorkload == "Exchange"
| where Operation in ("Add-MailboxPermission", "Add-RecipientPermission", "Add-MailboxFolderPermission", "Set-MailboxFolderPermission", "Add-ADPermission")
| where Parameters has_any ("FullAccess", "SendAs", "Send-As", "Editor", "Owner", "Author")
| extend Grantee = extract(@"""Name"":\s*""(?:User|Trustee)"",\s*""Value"":\s*""([^""]+)""", 1, Parameters)
| summarize Grants = count(), Mailboxes = dcount(OfficeObjectId), Targets = make_set(OfficeObjectId, 10) by UserId, Grantee, Operation
| order by Grants desc
```

```spl
sourcetype="o365:management:activity" Workload=Exchange Operation IN ("Add-MailboxPermission","Add-RecipientPermission","Add-MailboxFolderPermission")
| spath output=pname path="Parameters{}.Name" | spath output=pvalue path="Parameters{}.Value"
| eval grantee=mvindex(pvalue, mvfind(pname,"^(User|Trustee)$")), right=mvindex(pvalue, mvfind(pname,"AccessRights"))
| stats count dc(ObjectId) as mailboxes values(ObjectId) as targets by UserId, grantee, right, Operation
| sort - count
```

A user granting themselves nothing but another account `FullAccess` on their own mailbox, or a help-desk account granting `SendAs` on a finance mailbox outside a ticket, is worth a call.

### 4. OAuth consent to mail scopes

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal")
| extend AppName = tostring(TargetResources[0].displayName),
         Scopes = tostring(parse_json(tostring(TargetResources[0].modifiedProperties)))
| where Scopes has_any ("Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings", "offline_access", "Files.ReadWrite.All", "Contacts.Read")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), IP = tostring(InitiatedBy.user.ipAddress)
| summarize Users = dcount(Actor), Actors = make_set(Actor, 10), First = min(TimeGenerated) by AppName, OperationName
| order by First desc
```

```spl
sourcetype="azure:aad:audit" operationName IN ("Consent to application","Add delegated permission grant","Add app role assignment to service principal")
| spath output=app path="targetResources{}.displayName"
| spath output=props path="targetResources{}.modifiedProperties{}.newValue"
| search props IN ("*Mail.Read*","*Mail.ReadWrite*","*Mail.Send*","*MailboxSettings*","*offline_access*")
| stats dc(initiatedBy.user.userPrincipalName) as users values(initiatedBy.user.userPrincipalName) as actors min(_time) as first by app, operationName
| sort first
```

Stack by application: apps consented by one or two users, with publisher "unverified" and a generic name (`Mail Sync`, `Secure Mail`, `eM Client` look-alikes), are the illicit ones. Compare with the Enterprise Applications blade for `createdDateTime` and reply URLs.

### 5. Risky sign-in followed by persistence

The highest-fidelity pattern is sequence, not any single event: an anomalous sign-in, then a rule, forwarding, delegation, consent or MFA method within an hour.

```kql
let window = 1h;
let persistence = OfficeActivity
    | where TimeGenerated > ago(14d) and Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "Add-MailboxPermission", "Add-RecipientPermission")
    | project PTime = TimeGenerated, UserId = tolower(UserId), Operation, PIP = ClientIP
  | union (AuditLogs
    | where TimeGenerated > ago(14d) and OperationName in ("User registered security info", "User registered all required security info", "Consent to application", "Update user")
    | extend UserId = tolower(tostring(TargetResources[0].userPrincipalName)), PIP = tostring(InitiatedBy.user.ipAddress)
    | project PTime = TimeGenerated, UserId, Operation = OperationName, PIP);
SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion), ASN = tostring(AutonomousSystemNumber),
         MFA = tostring(AuthenticationRequirement), Risk = RiskLevelDuringSignIn
| where Risk in ("medium", "high") or MFA == "singleFactorAuthentication"
| extend UserId = tolower(UserPrincipalName)
| join kind=inner persistence on UserId
| where PTime between (TimeGenerated .. (TimeGenerated + window))
| project SignIn = TimeGenerated, UserId, Country, ASN, IPAddress, MFA, Risk, Operation, PTime, PIP
| order by SignIn desc
```

```spl
(sourcetype="azure:aad:signin" status.errorCode=0 (riskLevelDuringSignIn IN ("medium","high") OR authenticationRequirement="singleFactorAuthentication")) OR (sourcetype="o365:management:activity" Operation IN ("New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission","Add-RecipientPermission"))
| eval user=lower(coalesce(userPrincipalName, UserId)), kind=if(sourcetype="azure:aad:signin","signin","persist")
| transaction user startswith=kind=signin endswith=kind=persist maxspan=1h
| where eventcount>=2
| table _time, user, duration, location.countryOrRegion, ipAddress, Operation, ClientIP
```

Drop the risk filter and run the join on *every* successful sign-in from a country or ASN not seen for that user in the previous 30 days; that catches the AiTM sessions Identity Protection scores as low risk.

### 6. AiTM and token replay

```kql
SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion), ASN = tostring(AutonomousSystemNumber), Session = tostring(SessionId)
| summarize Countries = dcount(Country), ASNs = dcount(ASN), IPs = make_set(IPAddress, 5), Agents = make_set(UserAgent, 3),
            Span = max(TimeGenerated) - min(TimeGenerated) by UserPrincipalName, Session
| where ASNs >= 2 and Span < 2h
| order by ASNs desc
```

Also look for successful sign-ins whose `AuthenticationDetails` carry no MFA satisfied claim for users covered by an MFA policy (`ConditionalAccessStatus == "notApplied"` from a new device), user agents such as `axios`, `python-requests`, `okhttp`, `Go-http-client` or stale browser versions on sessions that then access Exchange, and the Entra `Unfamiliar sign-in properties` detection followed by Exchange activity from the same IP.

### 7. MFA fatigue and MFA method changes

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType in ("500121", "50074", "50076", "500120")     // MFA denied / required / failed
| summarize Denials = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where Denials >= 5
| join kind=inner (SigninLogs | where ResultType == 0 | project UserPrincipalName, Success = TimeGenerated, SuccessIP = IPAddress) on UserPrincipalName
| where Success between (Last .. (Last + 1h))
| project UserPrincipalName, IPAddress, Denials, First, Last, Success, SuccessIP
```

```spl
sourcetype="azure:aad:signin" status.errorCode IN (500121, 50074, 50076, 500120)
| bin _time span=1h
| stats count as denials min(_time) as first max(_time) as last by userPrincipalName, ipAddress, _time
| where denials>=5
```

Then check `AuditLogs` for `User registered security info` / `Admin registered security info` and `User changed default security info` for the same users within the following day, and for `Update user` with `StrongAuthenticationPhoneAppDetail` changes.

### 8. Bulk mail access and finance reconnaissance

```kql
OfficeActivity
| where TimeGenerated > ago(14d) and Operation == "MailItemsAccessed"
| extend Items = toint(OperationCount), Sync = tostring(parse_json(OperationProperties)[0].Value), App = tostring(AppId), Agent = tostring(ClientInfoString)
| summarize Items = sum(Items), Sessions = dcount(SessionId), IPs = make_set(ClientIP, 5), Agents = make_set(Agent, 3) by UserId, App, bin(TimeGenerated, 1d)
| join kind=leftouter (OfficeActivity | where TimeGenerated between (ago(44d) .. ago(14d)) and Operation == "MailItemsAccessed"
    | summarize Baseline = sum(toint(OperationCount)) / 30 by UserId) on UserId
| where Items > 500 and Items > 5 * coalesce(Baseline, 20)
| order by Items desc
```

```spl
sourcetype="o365:management:activity" Operation=MailItemsAccessed
| bin _time span=1d
| stats sum(OperationCount) as items dc(SessionId) as sessions values(ClientIP) as ips values(ClientInfoString) as agents by UserId, AppId, _time
| eventstats avg(items) as avg_items by UserId
| where items>500 AND items>5*avg_items
| sort - items
```

Combine with `SearchQueryInitiatedExchange` (E5): queries containing `invoice`, `wire`, `payment`, `remittance`, `bank`, `IBAN`, `W-9`, `payroll`, `direct deposit`; and with `Send` events whose subject reuses an existing thread but adds a changed bank account. A `MailItemsAccessed` burst with `MailAccessType = Sync` from a new client is a full mailbox download for offline review.

## Triage

| Check | Interpretation |
|---|---|
| Rule created from an IP/ASN the user has never signed in from | Attacker-created; the user's own rules come from the corporate egress or home ISP |
| Rule name is punctuation or blank, moves to RSS/Archive, or deletes | Hiding behaviour; legitimate users name rules and file to real folders |
| Forwarding target domain | Free webmail (gmail, outlook.com, proton) or a look-alike of a supplier domain is a confirmed hit; archiving vendors are not |
| Consent app publisher | Unverified publisher, generic name, consent by one user, redirect URI on a non-corporate host = illicit consent grant |
| Sign-in device and user agent | AiTM shows as a new "browser" with no device compliance; the real user's device keeps signing in in parallel |
| `MailItemsAccessed` volume vs. 30-day baseline | 5x the daily norm from a new client is bulk collection |
| Sent items | Replies to finance threads with changed banking details or new "urgent" payment requests confirm fraud in progress |

## Common false positives

- Users forwarding to a personal address against policy (still a policy finding, not an intrusion)
- Migration, journaling and archiving services that set forwarding or `FullAccess` tenant-wide at onboarding
- Executives' assistants with legitimate `FullAccess`/`SendAs` delegations (baseline them once)
- Mobile mail clients and Outlook profile rebuilds generating large `MailItemsAccessed` sync counts on day one
- Travelling users who register a new authenticator after a phone change (verify through the help desk, not by assuming)
- Security teams running phishing simulations or mailbox exports (`SearchExport`)

## Escalate when

An anomalous sign-in is followed by any persistence object (rule, forwarding, delegation, consent, MFA method) for the same account, or any rule/forwarding that targets an external free-mail or look-alike domain. Treat it as fraud in progress: **revoke sessions and refresh tokens** (`Revoke-AzureADUserAllRefreshToken` / Entra "Revoke sessions"), reset the password, remove the rule, forwarding, delegation and consent, review sent items and `MailItemsAccessed` back to the first bad sign-in, and notify finance before the next payment run. Check whether the same ASN or user agent touched other mailboxes.

## Validate and operationalise

- Emulate (test tenant only): `Invoke-AtomicTest T1114.003` (Set-Mailbox forwarding), `T1564.008` (New-InboxRule hiding rule), `T1098.002` (Add-MailboxPermission); grant a sandbox app `Mail.Read` to generate the consent events; run an MFA push loop against a lab user to produce the `500121` series.
- Detection: [Suspicious Inbox Rule Hiding or Deleting Mail]({{ site.baseurl }}/research/sigma/T1564.008-suspicious-inbox-rule-hiding-mail.yml), [Mailbox Forwarding to External Address]({{ site.baseurl }}/research/sigma/T1114.003-mailbox-forwarding-to-external.yml); Defender for Office / Identity Protection alerts for "Suspicious inbox manipulation rule" and "Anomalous token" as corroboration, not replacement.
- Hardening: phishing-resistant MFA (FIDO2/passkeys) and Conditional Access with token protection and compliant-device requirement; block external auto-forwarding at the tenant (`Set-RemoteDomain Default -AutoForwardEnabled $false`); restrict user consent to verified publishers and low-risk scopes with admin consent workflow; disable legacy authentication (IMAP/POP/EWS basic); enable Purview Audit (Premium) for `MailItemsAccessed`; number matching and additional context in Authenticator; a second-approver process for banking-detail changes that does not run over email.

See also: [Cloud & Identity playbook]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) for password spray, privileged role and AWS credential hunts, [Phishing & initial execution]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) for the delivery side, and [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) for SharePoint and OneDrive bulk downloads.

{% include playbook-footer.html %}
