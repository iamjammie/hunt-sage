---
title: "Hunt Pack: Business Email Compromise & Cloud Identity Takeover"
permalink: /hunt/packs/bec-cloud-identity-takeover/
excerpt: "Chain the cloud identity, phishing and mailbox playbooks into one campaign that finds a taken-over account before the fraudulent payment goes out."
classes: wide
toc: true
toc_sticky: true
pack: true
playbooks: [initial-access-phishing, cloud-identity, business-email-compromise, data-exfiltration]
attack: [T1566.002, T1110.003, T1078.004, T1621, T1556.006, T1098.005, T1564.008, T1114.003, T1528, T1098.003, T1114.002, T1530, T1657]
duration: "1 week, 1-2 analysts with Entra ID and M365 audit access"
---

{% include pack-meta.html %}

The adversary never touches an endpoint. A finance user receives a link to a convincing sign-in page proxied by an adversary-in-the-middle kit; the user authenticates, satisfies MFA, and the attacker walks away with a valid session cookie. Where phishing fails, a slow password spray against the tenant finds one weak password, and a burst of MFA push prompts at 06:40 wears the user down until they tap *Approve*. Within minutes the attacker registers a new authenticator method so the session survives a password reset, creates an inbox rule that moves anything mentioning "invoice", "payment" or "remittance" to the RSS Feeds folder and marks it read, and consents a third-party "mail backup" app to `Mail.ReadWrite` and `offline_access` as a quieter form of persistence. Over the next ten days the mailbox is searched for open payment threads, a supplier thread is hijacked from a look-alike domain, and new bank details are sent to accounts payable. In some cases the same session is used to pull a few thousand files from SharePoint, or, if the user holds a privileged role, to add a second Global Administrator.

Run this pack when a sector or partner has reported BEC activity, after any AiTM or token-theft alert, when finance or legal flag a near-miss payment, or quarterly as assurance over the tenant's most exposed identities (finance, executives, HR, anyone who approves payments). It is also the right pack for the first week after an MFA policy change, when attackers probe for accounts the policy missed.

## Scoping checklist

- Which mailboxes can move money or approve payments? Get the list from finance and the ERP owner; those accounts are the hunt's centre.
- Which sign-in and audit sources exist, for how long, and with which fields (`SessionId`, `MfaDetail`, `ClientAppId`)? Fill in the [data source assessment]({{ site.baseurl }}/templates/#data-source-assessment) first.
- Has any BEC, AiTM or token-theft alert fired in the last 90 days? Start the timeline there rather than at the hunt window.
- Which third-party apps are sanctioned? Get the list from the identity team so day 2 does not spend hours on the known ones.
- Who in finance will verify payment threads by phone on day 4, and who in IR takes confirmed sessions on day 5?
- Write each hypothesis you will test on a [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card) with the H-id, so the report can show what was tested and what was not.

## Kill chain at a glance

| Phase | Adversary action | ATT&CK | What you would see (telemetry) | Hypotheses | Playbook |
|---|---|---|---|---|---|
| 1. Initial access | AiTM phishing link, QR-code phish, or password spray against the tenant | T1566.002, T1110.003 | `SigninLogs` failures for many accounts from one IP with one or two attempts each, then a success; email telemetry showing a link to a newly registered domain; `EmailUrlInfo` / proxy hits on the kit domain | H-047, H-002, H-005 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 1, [Phishing & initial execution]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) step 5 |
| 2. Session theft / MFA bypass | Token replay from attacker infrastructure; MFA fatigue push bombing | T1078.004, T1621 | Same `SessionId` or `CorrelationId` from two IPs and ASNs within minutes; sign-in with no MFA claim shortly after the user's MFA'd sign-in; ten or more MFA denials followed by one approval | H-086, H-089, H-085 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 2 |
| 3. Persistence on the identity | Registers a new authenticator or phone, changes recovery email | T1556.006, T1098.005 | `AuditLogs` "User registered security info" / "User registered all required security info" minutes after a risky sign-in, from the attacker IP | H-089 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 3, [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |
| 4. Mailbox persistence and hiding | Inbox rules that delete, move or mark read; external forwarding; transport rules | T1564.008, T1114.003 | `OfficeActivity` `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules` with `DeleteMessage`, `MoveToFolder`, `MarkAsRead`; `Set-Mailbox` with `ForwardingSmtpAddress`; rule created within an hour of a new-country sign-in | H-024 | [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |
| 5. Application persistence | Consent to a third-party OAuth app with mail scopes; service principal credentials added | T1528, T1098.003 | `AuditLogs` "Consent to application", "Add delegated permission grant", "Add service principal credentials"; permissions including `Mail.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`, `offline_access`; app with fewer than three consenting users | H-087, H-093 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 3 |
| 6. Collection | Mailbox search for payment threads; bulk mail sync via Graph, EWS or IMAP; SharePoint download burst | T1114.002, T1530 | `MailItemsAccessed` with high `OperationCount` from an unfamiliar `ClientAppId` or IP; `SearchQueryInitiated`; `FileDownloaded` / `FileSyncDownloadedFull` in the thousands for one user | H-066, H-092 | [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/), [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 6 |
| 7. Fraud | Supplier thread hijack, look-alike domain, changed bank details, internal "urgent payment" from the real mailbox | T1657 | Outbound mail to a look-alike supplier domain registered recently; `Send` / `SendAs` / `SendOnBehalf` events from an unusual IP; replies landing in a hidden folder | H-024, H-066 | [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) |
| 8. Escalation (optional) | Privileged role assignment, second admin account, conditional-access change | T1098.003 | `AuditLogs` "Add member to role" for Global Administrator or Privileged Role Administrator; "Update conditional access policy" by a non-identity-team account | H-088, H-091 | [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 4 |

## Telemetry you need before you start

Confirm each source has events for the whole hunt window before running a single query; a negative result on a source that is not being collected is a visibility finding, not a clean bill. See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) for the enablement details.

**Must-have**

- `entra-id`: `SigninLogs` (interactive) and `AADNonInteractiveUserSignInLogs`, with `SessionId`, `AuthenticationRequirement`, `MfaDetail`, `RiskLevelDuringSignIn`, `DeviceDetail`, `AutonomousSystemNumber`; `AuditLogs` for security-info registration, consents, role changes and conditional-access edits. Retention of at least 30 days to baseline per-user countries and ASNs.
- `m365-audit`: the Unified Audit Log (`OfficeActivity` in Sentinel, `sourcetype=o365:management:activity` in Splunk) with Exchange operations (`New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, `Add-RecipientPermission`, `New-TransportRule`), SharePoint `FileDownloaded` / `FileSyncDownloadedFull`, and `MailItemsAccessed` (requires Purview Audit Premium / E5 licensing, otherwise note the gap).
- `email`: message trace or the mail gateway's logs with sender, recipient domain, URL and attachment metadata, so step 1 and step 7 can see the kit domain and the look-alike supplier.

**Nice-to-have**

- Defender for Cloud Apps / `CloudAppEvents` for app-level session anomalies and OAuth app risk scores.
- Identity Protection risk detections (`AADUserRiskEvents`, `AADRiskyUsers`) to prioritise which accounts to baseline first.
- A list of finance, executive and payment-approver mailboxes from HR or the ERP system, so the hunt scopes to the accounts an attacker actually wants.
- DNS or proxy logs with user attribution, to catch the AiTM kit domain at click time rather than at sign-in time.

## Five-day hunt plan

| Day | Focus | Steps | Output |
|---|---|---|---|
| 1 | Access and session theft | Confirm telemetry per source and window. Run [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 1 (spray: many accounts, few attempts, one source) and step 2 (new country/ASN per user over 30 days; same session from two ASNs; sign-ins lacking an MFA claim after the MFA policy). Stack sign-ins by `AutonomousSystemNumber` and `UserAgent`, look at the long tail. | List of accounts with anomalous sign-ins; list of source IPs/ASNs to carry into every later step |
| 2 | Identity persistence | For every account flagged on day 1 and for the finance/executive list: `AuditLogs` security-info registrations within 24 hours of a flagged sign-in; new OAuth consents tenant-wide stacked by app and permission; role membership changes in 30 days; service-principal credential additions. Baseline consents against the previous 90 days. | Accounts with new MFA methods or consents to review; apps with mail or file scopes and low consent counts |
| 3 | Mailbox persistence | [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/): all inbox rules created or modified in 30 days, scored for hiding behaviour (delete, move to RSS/Archive/Conversation History, mark read, finance keywords); forwarding and transport rules to external domains; delegate and SendAs grants. Join rule creation time to the day-1 sign-in list. | Hidden-rule list with owner, creating IP and keywords; forwarding inventory with external destinations |
| 4 | Collection and fraud | `MailItemsAccessed` stacked by `ClientAppId` and IP per user, outliers against each user's 30-day median; `SearchQueryInitiated` for payment terms; SharePoint download bursts ([Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 6); outbound mail to domains registered in the last 60 days that resemble known suppliers. Ask accounts payable for bank-detail change requests in the window and reconcile. | Confirmed or cleared accounts; list of payment threads to verify with finance by phone |
| 5 | Report, detect, backlog | Write the [hunt report]({{ site.baseurl }}/templates/#hunt-report); hand confirmed sessions to IR with the [IR hand-off package]({{ site.baseurl }}/templates/#handoff-package-to-ir); turn the inbox-rule and forwarding queries into analytics rules; record per-user baselines and benign apps as allow-lists; log telemetry gaps (no `MailItemsAccessed`, short retention). | Report, detections in test, allow-list notes, backlog items for next quarter |

## Pivot map

- If you find a sign-in from a new ASN with no MFA claim → check `AuditLogs` for security-info registration by that user in the next 24 hours (cloud-identity step 3), then inbox rules created from the same IP (BEC playbook).
- If you find an inbox rule hiding finance keywords → pull every sign-in for that user in the preceding 72 hours, pivot on the creating `ClientIP` to find other mailboxes touched from it, and check `MailItemsAccessed` counts for the same session.
- If you find external forwarding → check whether the destination domain appears in outbound mail from any other user (shared attacker infrastructure), and whether a transport rule exists tenant-wide.
- If you find a consented app with mail scopes → list every user who consented, the app's publisher and reply URLs, then look for `MailItemsAccessed` with that `ClientAppId`; revoke and expire refresh tokens if confirmed.
- If you find a `MailItemsAccessed` burst from a new client → compare the IP and user agent with the day-1 anomalous sign-ins; a match across two sources is strong enough to escalate.
- If you find a look-alike supplier domain in outbound mail → search inbound mail for the same domain to see whether the hijack started on the supplier's side, and ask finance to freeze any pending payment to that supplier.
- If you find a role added to Global Administrator → treat as tenant compromise: review conditional-access and named-location changes, service-principal credentials and new app registrations in the same window; move to IR.
- If you find a SharePoint download burst → check whether the same session also accessed mail, and whether the files match the payment or HR themes the attacker was searching for; hand the file list to the data owner.
- If a password spray succeeded but no persistence was planted → the attacker may be queueing access for sale; reset, revoke sessions, and watch the account for 14 days.

## Detections to confirm are live

Confirm each rule is deployed, firing in the lab and tuned before relying on the hunt's negative results.

**Initial access and execution**
- [Office or Document Reader Application Spawns Script Interpreter or LOLBin]({{ site.baseurl }}/research/sigma/T1566.001-office-application-spawns-interpreter.yml) (covers the attachment variant when a phish lands on an endpoint)
- [Execution from Extracted Archive, Disk Image Contents or Outlook Attachment Cache]({{ site.baseurl }}/research/sigma/T1204.002-execution-from-mounted-image-or-archive.yml)

**Mailbox persistence and hiding**
- [Suspicious Inbox Rule Hiding Mail]({{ site.baseurl }}/research/sigma/T1564.008-suspicious-inbox-rule-hiding-mail.yml)
- [Mailbox Forwarding to External Address]({{ site.baseurl }}/research/sigma/T1114.003-mailbox-forwarding-to-external.yml)

**Exfiltration**
- [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml) (when a compromised identity is used from a managed endpoint to sync SharePoint data out)

Identity-side signals (AiTM session replay, MFA registration after risky sign-in, consent grants, role changes) are best delivered by the identity platform's own analytics and by the KQL/SPL in the playbooks; record which of those are enabled as part of the report.

## What good looks like

- Every finance, executive and payment-approver account has a documented 30-day country/ASN/device baseline, and sign-ins outside it have been triaged.
- All inbox rules, forwarding settings and transport rules created in the window are inventoried, and each hiding or forwarding rule is attributed to a user action or removed.
- OAuth apps with mail or file scopes are inventoried with publisher, consent count and first-seen date; unknown apps are blocked or reviewed by the identity team.
- MFA security-info changes following risky sign-ins are explained or reset.
- Pending supplier bank-detail changes in the window were verified by finance through a known-good channel.
- Hidden-rule, forwarding and consent queries are running as detections, with false positives from the hunt documented as allow-list entries.
- Visibility gaps are logged with an owner: `MailItemsAccessed` licensing, short sign-in retention, unmonitored legacy protocols.
- Confirmed compromises were handed to IR with sessions revoked, not merely passwords reset.

## Tabletop prompts

1. A finance user's mailbox has a rule moving "invoice" mail to RSS Feeds, created from an IP in a country they have never signed in from. Which five queries do you run in the next hour, and in what order?
2. Our conditional-access policy requires MFA for everyone. How would a successful AiTM session still appear in the sign-in logs, and what field would tell you the MFA was satisfied by a replayed token rather than a fresh prompt?
3. The consent-grant query returns 40 apps. How do you decide which three to investigate first without an external reputation feed?
4. We do not have `MailItemsAccessed` because of licensing. What is the next-best evidence that a mailbox was read, and what does the hunt report say about this gap?
5. A supplier emails from their real domain asking to change bank details, and the thread is genuine. What in the mailbox telemetry would show that the supplier, not us, is the compromised party, and who do we tell?

## Hardening that shortens the next hunt

1. Phishing-resistant MFA (FIDO2 or certificate-based) for finance, executives and all privileged roles; number matching and context in push prompts for everyone else, with a cap on prompts per hour.
2. Conditional access that requires compliant or hybrid-joined devices for mail and SharePoint, and token-protection / continuous access evaluation so a stolen cookie is useless off the device.
3. Block user consent to third-party apps; route requests through an admin consent workflow and alert on every grant.
4. Disable automatic external forwarding at the organisation level; alert on any inbox rule that forwards, deletes or moves finance-keyword mail.
5. Disable legacy authentication (IMAP, POP, SMTP AUTH, basic EWS) tenant-wide; it removes the spray surface and most token-less mass-sync paths.
6. Payment-process controls: out-of-band verification of every bank-detail change, dual approval above a threshold; these stop the fraud even when the hunt misses the compromise.
7. Enforce Purview Audit Premium (or equivalent) so `MailItemsAccessed` exists, and extend sign-in retention to 90 days.
8. Privileged Identity Management with time-bound activation and approval for Global Administrator; no standing admin on mail-enabled accounts.

## Related

- Learn: [Hypotheses & threat intelligence]({{ site.baseurl }}/learn/hypotheses-and-intelligence/), [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/), [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/) (baselining and first-seen are the core of this pack)
- Playbooks: [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/), [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/), [Phishing & initial execution]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/), [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/)
- Hypotheses: [Cloud & Identity section of the library]({{ site.baseurl }}/hunt/hypotheses/#cloud--identity)
- Templates: [Hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card), [Hunt report]({{ site.baseurl }}/templates/#hunt-report), [IR hand-off package]({{ site.baseurl }}/templates/#handoff-package-to-ir)
- Blog: [Threat hunting fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/), [Stacking and baselining: a worked example]({{ site.baseurl }}/blog/stacking-and-baselining-worked-example/)
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) for the identity and collection techniques this pack touches
