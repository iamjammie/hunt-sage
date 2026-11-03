---
title: "Hunt Pack: Insider & Departing-Employee Data Theft"
permalink: /hunt/packs/insider-data-theft/
excerpt: "A behaviour-and-volume hunt for data leaving with a legitimate user: share browsing, bulk download, staging, removable media, personal cloud and email, then cover-up."
classes: wide
toc: true
toc_sticky: true
pack: true
playbooks: [network-share-discovery, data-exfiltration, cloud-identity, business-email-compromise]
attack: [T1135, T1083, T1039, T1213.002, T1005, T1074.001, T1560.001, T1052.001, T1567.002, T1048.002, T1114.003, T1070.004, T1070.003]
duration: "1 week, 1 analyst plus named HR and legal contacts"
---

{% include pack-meta.html %}

Nobody breaks in. An engineer who has accepted an offer elsewhere, or a sales lead who has just been put on a performance plan, still holds every permission the job needed. Over two or three weeks the pattern shifts: the user browses SharePoint sites and file shares they have never opened, on evenings and at weekends; they download whole document libraries with the sync client; they zip project folders into a few large archives in a working directory; and the archives leave through a personal cloud-storage account, a USB drive, a personal webmail session or an auto-forward rule to a private address. In the last days the user deletes the archives, clears browser and shell history, and empties the recycle bin. The volumes are large but the access is legitimate, so nothing alerts; the only signals are deviation from the user's own history and from their peers'.

Run this pack when HR notifies security of a resignation, termination or performance process for a user with access to crown-jewel data, when a customer or competitor surfaces with material that looks like yours, when DLP produces a cluster of low-severity events for one user, or quarterly across high-value teams (R&D, finance, M&A, sales operations). Scope it to the named users or team from the HR trigger; a fleet-wide insider hunt without a trigger is surveillance, not hunting.

**Handle with care.** This pack hunts behaviour and volume, not intent. Before the hunt starts, agree the scope and the legal basis with HR and legal, record who may see the results, and keep attribution of motive out of the hunt report. A user downloading their own project history before leaving may be careless rather than malicious, and the same evidence is used in the formal process either way. Follow the guardrails in [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/#legal-ethical-and-operational-guardrails).

## Scoping checklist

- Named users or team from the HR trigger, the window (notice date minus 30 days to today) and the legal basis, agreed in writing with HR and legal.
- The crown-jewel data those users can reach: which file servers, SharePoint sites, repositories and databases, and who owns each.
- Which telemetry covers those systems and the users' endpoints, and for how long; record the gaps on the [data source assessment]({{ site.baseurl }}/templates/#data-source-assessment) before day 1 ends.
- A peer group for each user (same role, same team) so baselines compare like with like.
- Who receives the findings, in what form, and through which channel; the hunt team does not brief the user's manager directly.
- Each hypothesis to be tested written on a [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card), so the report lists what was and was not checked.

## Kill chain at a glance

| Phase | Insider action | ATT&CK | What you would see (telemetry) | Hypotheses | Playbook |
|---|---|---|---|---|---|
| 1. Reconnaissance | Browses shares, SharePoint sites and repositories outside the normal job scope, often out of hours | T1135, T1083, T1213.002 | 5140/5145 to shares the account has not touched in 90 days; SharePoint `PageViewed` / `FileAccessed` on new sites; `net view`, `Get-ChildItem -Recurse`, search-indexer style enumeration from a user shell | H-054, H-065 | [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/) |
| 2. Collection | Bulk read or download: sync client pulling whole libraries, mass `FileDownloaded`, thousands of 5145 reads on a file server | T1039, T1005, T1213.002 | `FileSyncDownloadedFull` and `FileDownloaded` counts far above the user's 30-day median; 5145 `ReadData` to more than 1,000 distinct files in an hour; EDR file reads of `.docx`, `.xlsx`, `.dwg`, `.sql`, source trees | H-065, H-092 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 4 and 6 |
| 3. Staging and archiving | Zips or rars project folders into a handful of large files in a working directory or the recycle bin | T1074.001, T1560.001 | `7z`, `WinRAR`, `tar`, `Compress-Archive` writing files over 200 MB to `%USERPROFILE%`, `Downloads`, `C:\Temp` (Sysmon 11, `DeviceFileEvents`); many files read, one written | H-064 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 1 |
| 4a. Exfil: removable media | Copies archives to USB or a phone over MTP | T1052.001 | Device arrival (System 6416, `DeviceEvents` `UsbDriveMounted`/`PnpDeviceConnected`) followed by file writes to a new drive letter; DLP removable-media events | H-007, H-064 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 5 |
| 4b. Exfil: personal cloud | Uploads to personal Google Drive, Dropbox, iCloud, Mega, WeTransfer or a sync client signed into a personal account | T1567.002 | Proxy/firewall uploads over 1 GB per day to consumer storage; browser or sync-client process network events to those domains; `rclone`, `MEGAsync` process creation | H-076, H-077 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 2 and 3 |
| 4c. Exfil: personal email | Forwards or attaches work mail to a personal address; auto-forward rule to a private domain | T1114.003, T1048.002 | `Set-InboxRule` with `ForwardTo` or `RedirectTo` to a consumer domain; outbound messages with attachments over 10 MB to the same personal address; webmail uploads in proxy logs | H-024, H-066 | [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/), [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) step 5 |
| 4d. Exfil: print and screenshot | Prints large documents, photographs screens | T1005 | Print spooler events (Microsoft-Windows-PrintService 307) with high page counts out of hours; is a visibility gap on most estates, record it | - | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| 5. Cover-up | Deletes archives and downloads, clears browser and shell history, empties recycle bin, wipes free space | T1070.004, T1070.003 | `DeviceFileEvents` `FileDeleted` bursts for the archives written in phase 3; `cipher /w`, `sdelete`, `Clear-History`; browser history database truncation; on Linux `history -c`, `unset HISTFILE` | H-100, H-064 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 1, [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 4 |

## Telemetry you need before you start

Confirm each source covers the scoped users and the full window (at least 30 days before the HR trigger, since collection often precedes the formal notice). See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/).

**Must-have**

- `m365-audit`: SharePoint and OneDrive operations (`FileDownloaded`, `FileSyncDownloadedFull`, `FileAccessed`, `PageViewed`, `SharingSet`, `AnonymousLinkCreated`) and Exchange operations (`Set-InboxRule`, `Set-Mailbox`, `Send`) for the scoped users; Unified Audit Log in Sentinel `OfficeActivity` or Splunk `sourcetype=o365:management:activity`.
- `windows-security` on file servers: object-access auditing for the shares that hold crown-jewel data, so 5145 carries `RelativeTargetName`, `AccessMask` and `SubjectUserName`; 5140 for share connections.
- `edr`: file events (create, rename, delete) with size, process creation with command line, removable-media events, and process network events (`DeviceFileEvents`, `DeviceProcessEvents`, `DeviceEvents`, `DeviceNetworkEvents`).
- `proxy` or `firewall` with user attribution and bytes-out per destination, so uploads to consumer storage can be measured per user per day.

**Nice-to-have**

- DLP or CASB events (removable media, upload to unsanctioned apps, sensitive-label matches) as a prioritisation feed rather than the source of truth.
- Source-control audit logs (clone, fork, download of archives) for engineering users.
- Print server logs (PrintService operational 307/805) and badge or VPN logs to put out-of-hours activity in context.
- A peer-group map from HR (team, role, location) so each user's volumes can be compared with people doing the same job, not with the whole company.

## Five-day hunt plan

| Day | Focus | Steps | Output |
|---|---|---|---|
| 1 | Scope, legal basis, baselines | Confirm scope and legal basis with HR and legal; record the named users, the window (trigger minus 30 days to today) and who receives the report. Build each user's 90-day baseline: shares and SharePoint sites touched, daily download counts and bytes, destinations by bytes-out, usual working hours. Build the same for their peer group. | Signed scope note; per-user and per-peer-group baselines in a worksheet |
| 2 | Reconnaissance and collection | [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/): first-seen shares and sites per user against the 90-day baseline; enumeration commands from user shells. [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 4 and 6: `FileDownloaded` / `FileSyncDownloadedFull` and 5145 distinct-file counts per day, flag days above three times the user's median and above the peer-group 95th percentile. | Per-user timeline of unusual access; list of libraries and shares touched for the data owner |
| 3 | Staging and exfil channels | Step 1 (archives over 200 MB written by user processes), step 2 (`rclone`, sync clients, `OriginalFileName` matches), step 3 (consumer-storage domains by bytes-out per user), step 5 (USB arrival followed by writes; outbound SSH/FTP), plus mailbox forwarding and large attachments to personal domains ([BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/)). Join archive write times to upload and USB events within the same hour. | Evidence table per user: what was staged, when, and through which channel it may have left |
| 4 | Cover-up, corroboration, triage | Deletion bursts matching day-3 archives; history clearing; recycle-bin emptying; `cipher /w` or `sdelete`. Corroborate every finding with a second source (file server plus proxy, SharePoint plus EDR). Triage with the data owner: is this material the user needed for their role in that period? Separate "unusual but explained" from "unexplained". | Findings graded by corroboration; clearly separated explained items |
| 5 | Report and hand-off | Write the [hunt report]({{ site.baseurl }}/templates/#hunt-report) in neutral language (what was accessed, moved and deleted; no inference of intent); hand to HR and legal through the agreed channel; preserve evidence (export logs, hash archives still present) if a formal process follows. Promote the volume-outlier and forwarding queries to detections scoped to leaver windows; record visibility gaps (print, personal webmail over TLS, phone tethering). | Report, preserved evidence set, detections for the leaver process, backlog |

## Pivot map

- If you find first-seen access to a share or site → pull the file names read there and the volume in the following 48 hours (step 2), then look for an archive written on the user's endpoint in the same window (step 3).
- If you find an archive over 200 MB → check USB arrival events, consumer-storage uploads and large outbound mail in the two hours after it was written; then look for its deletion later (phase 5).
- If you find consumer-storage uploads → identify the process (browser vs sync client) in EDR network events; a sync client signed into a personal account implies a folder pairing, so check which local folder it synchronises.
- If you find an inbox forwarding rule to a personal domain → inventory the rule's creation date against the HR timeline and search outbound mail for attachments to that domain in the previous 30 days.
- If you find a USB write burst → retrieve the device serial from 6416 / `DeviceEvents` and check whether the same device appeared on other hosts or for other users.
- If you find deletion bursts without matching staging → widen the staging search to renamed archives (`OriginalFileName`, magic bytes in EDR file events) and to cloud-side `FileDeleted` on the user's OneDrive.
- If you find nothing on the endpoint but SharePoint shows thousands of downloads → the sync client on an unmanaged personal device is the likely path; check `DeviceDetail` and `ClientIP` in the audit events, and whether conditional access allows unmanaged sync.
- If a peer shows the same pattern → the behaviour may be a team workflow (project archive at handover); confirm with the manager before escalating either user.
- If you find source-control archive downloads → check the repository's own audit log for clones from new IPs and for personal fork creation.

## Detections to confirm are live

Confirm each rule is deployed and tuned for the file servers and endpoints in scope.

**Reconnaissance**
- [Network Share Enumeration Tooling on the Command Line]({{ site.baseurl }}/research/sigma/T1135-share-enumeration-tooling-command-line.yml)
- [Honey Share Access]({{ site.baseurl }}/research/sigma/T1135-honey-share-access.yml) (a decoy share named for the crown-jewel data is one of the few high-fidelity insider signals)
- [SMB Session and Local Group Enumeration via IPC$ Named Pipes]({{ site.baseurl }}/research/sigma/T1018-session-enumeration-burst-smb.yml)

**Exfiltration**
- [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml)
- [Mailbox Forwarding to External Address]({{ site.baseurl }}/research/sigma/T1114.003-mailbox-forwarding-to-external.yml)
- [Suspicious Inbox Rule Hiding Mail]({{ site.baseurl }}/research/sigma/T1564.008-suspicious-inbox-rule-hiding-mail.yml)

**Cover-up**
- [Windows Event Log Cleared]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml) (rare for insiders, but a clearing event on a user workstation is always worth a look)

Volume and baseline signals (download outliers, first-seen shares, USB-then-upload sequences) are analytics rather than Sigma rules; the KQL and SPL in the playbooks are the starting point for scheduled searches scoped to leaver windows.

## What good looks like

- Scope, legal basis and recipients were agreed in writing before the first query ran, and the report contains observations only.
- Every scoped user has a 90-day baseline of shares, sites, volumes, destinations and hours, with the peer-group comparison recorded.
- Every volume outlier is either explained by the data owner or corroborated by a second source and handed over.
- Staging, exfil channel and cover-up events are linked on one timeline per user, with hashes and audit record ids preserved.
- The data owner has a list of what was accessed, so impact can be assessed without the hunt team guessing at sensitivity.
- Leaver-window detections (download outliers, forwarding rules, USB-then-upload) are scheduled and owned.
- Visibility gaps are logged with owners: print, personal webmail over TLS, unmanaged-device sync, phone tethering, source-control audit.
- False positives (project handovers, backup scripts, sanctioned archive exports) are documented so the next leaver hunt is faster.

## Tabletop prompts

1. HR tells you a lead engineer resigns on Friday. What do you ask HR and legal for before you run anything, and what is the first baseline you build?
2. A user downloaded 4,000 files from a SharePoint site last Saturday. Name three benign explanations and the query that distinguishes each from theft.
3. The file server has no object-access auditing enabled. What can you still establish about collection, and how does the report describe the gap?
4. You find an archive written and deleted on the same evening with no USB, upload or mail evidence. What channels are still possible, and which of them can you check?
5. A manager asks you for "everything the user did". What do you give them, what do you withhold, and why?

## Hardening that shortens the next hunt

1. A leaver and performance-process workflow in which HR triggers security automatically, and access is reduced to role-essential data as soon as notice is given.
2. Object-access auditing and a decoy share on every crown-jewel file server; label-based DLP on the SharePoint sites that hold the same data.
3. Block or read-only removable media by default, with exceptions logged; alert on any first-use of a USB mass-storage device on a scoped user's host.
4. Block consumer cloud storage and personal webmail uploads at the proxy for users with access to sensitive data; allow-list sanctioned tenants only.
5. Conditional access that blocks OneDrive and SharePoint sync from unmanaged devices.
6. Disable automatic external forwarding and alert on forwarding rules to consumer domains.
7. Download and sharing-link limits on sensitive sites (Defender for Cloud Apps session controls or equivalent), with alerts on mass download per user per hour.
8. Source-control archive-download and clone auditing, and offboarding that revokes tokens and SSH keys on the day of notice.

## Related

- Learn: [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/) (guardrails, roles), [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/) (baselining, peer-group comparison), [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/)
- Playbooks: [Network share & file discovery]({{ site.baseurl }}/hunt/playbooks/network-share-discovery/), [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/), [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/), [BEC & mailbox abuse]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/)
- Hypotheses: [Collection]({{ site.baseurl }}/hunt/hypotheses/#collection) and [Exfiltration]({{ site.baseurl }}/hunt/hypotheses/#exfiltration) sections of the library
- Templates: [Hunt report]({{ site.baseurl }}/templates/#hunt-report), [Data source assessment]({{ site.baseurl }}/templates/#data-source-assessment), [IR hand-off package]({{ site.baseurl }}/templates/#handoff-package-to-ir)
- Blog: [Stacking and baselining: a worked example]({{ site.baseurl }}/blog/stacking-and-baselining-worked-example/), [Threat hunting fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/)
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/)
