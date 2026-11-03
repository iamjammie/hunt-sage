---
title: "Playbook: Phishing & Initial Execution"
permalink: /hunt/playbooks/initial-access-phishing/
excerpt: "Hunt the modern delivery chain: HTML smuggling, ISO/LNK containers, OneNote and PDF lures, ClickFix pastes, and the first interpreter spawned from Office, a reader or a browser."
tactic: "Initial Access"
attack: [T1566.001, T1566.002, T1204.001, T1204.002, T1027.006]
difficulty: 2
timebox: "3-5 hours"
data: [email, edr, sysmon, proxy, windows-security]
---

{% include playbook-meta.html %}

**Data used:** Email telemetry (Defender for Office 365 `EmailEvents`/`EmailAttachmentInfo`/`EmailUrlInfo` or vendor equivalent); process creation with parent and command line (`DeviceProcessEvents`, Sysmon 1, 4688); Sysmon 15 (Zone.Identifier); proxy/DNS for the first beacon

## Background

Office blocks macros on internet-sourced files, so delivery has moved to anything that **lands a file without Mark-of-the-Web (MOTW)** or **gets the user to run something themselves**:

| Lure | What runs |
|---|---|
| HTML smuggling (T1027.006): `.html` attachment or link "downloads your document" | JavaScript rebuilds a ZIP/ISO in the browser; inner file often has no MOTW |
| ISO / IMG / VHD / VHDX "disk image" | Mounted to a new drive letter; contents historically lacked MOTW |
| LNK inside ZIP, with a PDF/Word icon | `cmd`/`powershell`/`mshta`/`rundll32` with a long hidden command line |
| OneNote `.one` with an "Open" button | Embedded HTA/WSF/BAT run by `onenote.exe` |
| PDF / macro-less Office (remote template, OLE package, `.xll`) | Reader or Office spawns a child or fetches a remote template |
| QR code | Phone browser; corporate telemetry is only the later credential use |
| ClickFix / fake CAPTCHA: "press Win+R, Ctrl+V, Enter" | `explorer.exe` → `powershell.exe`/`mshta.exe` with the pasted command; no attachment at all |

The common denominator is the **first process spawned by a user-facing application**. Start there.

## Hypothesis

> *If a user has executed a phish, a document reader, browser, mail client or `explorer.exe` will have spawned a script interpreter or LOLBin, often from a mounted image, a temp-extracted archive or the Outlook attachment cache, within minutes of an email with an attachment or URL arriving, followed by a first outbound connection to an unfamiliar domain.*

## Data required

- Process creation with **parent image, full command line and current directory** (EDR, Sysmon 1, or 4688 with *Audit Process Creation* and "Include command line")
- Sysmon 15 (`FileCreateStreamHash`) for MOTW: fires when `Zone.Identifier` is written to a downloaded file
- Email telemetry joinable to the endpoint by recipient and time
- Proxy / DNS with the originating process (`DeviceNetworkEvents`, Sysmon 3 / 22)
- The user-reported phishing mailbox

## Hunt steps

### 1. User-facing applications spawning interpreters and LOLBins

```kql
let parents = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe","msaccess.exe","onenote.exe",
                       "acrord32.exe","acrobat.exe","foxitreader.exe","msedge.exe","chrome.exe","firefox.exe"]);
let children = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe",
                        "regsvr32.exe","certutil.exe","bitsadmin.exe","msiexec.exe","schtasks.exe","curl.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (parents) and FileName in~ (children)
| where not (InitiatingProcessFileName in~ ("msedge.exe","chrome.exe") and ProcessCommandLine has "--type=")  // browser helpers
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath
```

```spl
index=sysmon EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\outlook.exe"
   OR ParentImage="*\\onenote.exe" OR ParentImage="*\\acrord32.exe" OR ParentImage="*\\acrobat.exe"
   OR ParentImage="*\\msedge.exe" OR ParentImage="*\\chrome.exe" OR ParentImage="*\\firefox.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe"
   OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\certutil.exe"
   OR Image="*\\bitsadmin.exe" OR Image="*\\msiexec.exe" OR Image="*\\schtasks.exe" OR Image="*\\curl.exe")
| table _time host User ParentImage Image CommandLine CurrentDirectory
```

With 4688 the parent is `ParentProcessName` (Windows 10 / 2016+); the Windows TA names it `Creator_Process_Name` and the command line `Process_Command_Line`.

### 2. Execution from a mounted image, extracted archive or the Outlook cache

Where a file *runs from* tells you how it arrived. Mounted images get a non-`C:` drive letter; Explorer extracts ZIPs to `%TEMP%\Temp1_<name>.zip\` (7-Zip/WinRAR: `\Temp\7z*`, `\Temp\Rar$*`); opened attachments land in `\INetCache\Content.Outlook\<8CHARS>\`.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and InitiatingProcessFileName =~ "explorer.exe"
| where FolderPath matches regex @"^[D-Zd-z]:\\"                                   // not the system drive; exclude known data drives
   or FolderPath has_any (".iso\\", ".img\\", ".vhd\\", ".vhdx\\", ".zip\\", "\\Temp\\7z", "\\Temp\\Rar$", "\\Content.Outlook\\")
   or ProcessCommandLine has_any (".iso\\", ".img\\", ".vhd\\", ".zip\\", "\\Content.Outlook\\")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe")
   or FileName has_any (".lnk", ".js", ".vbs", ".wsf", ".hta", ".bat", ".cmd", ".scr", ".pif")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```

In Splunk use `CurrentDirectory` and `Image` wildcards (`CurrentDirectory="*.iso\\*"`, `Image!="C:\\*"`) and `stats` by the drive letter extracted with `rex`. `\Device\CdRom0` appears in Sysmon image-load and file events for ISO mounts, not in command lines, so do not hunt it in `CommandLine`. `Microsoft-Windows-VHDMP-Operational` logs the mount itself if you collect it.

### 3. LNK and ClickFix: long, hidden PowerShell or mshta from Explorer

LNK payloads and Run-dialog pastes both produce `explorer.exe` → interpreter with a long command line and `-w hidden` / `-nop` / `-ep bypass`, or `mshta https://...`.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe","msiexec.exe")
| extend Len = strlen(ProcessCommandLine)
| where Len > 250
   or ProcessCommandLine matches regex @"(?i)\s-(w|win|windowstyle)\s+h(idden)?\b"
   or ProcessCommandLine has_any ("-nop", "-ep bypass", "-enc ", "iwr ", "irm ", "iex", "DownloadString", "FromBase64String")
   or (FileName in~ ("mshta.exe","msiexec.exe") and ProcessCommandLine has_any ("http://","https://"))
| project Timestamp, DeviceName, AccountName, FileName, Len, ProcessCommandLine
| order by Len desc
```

Splunk: same parent/child filter as step 1 with `ParentImage="*\\explorer.exe"`, then `eval len=len(CommandLine) | where len>250 OR match(CommandLine,"(?i)-w(indowstyle)?\s+h")`.

ClickFix tell: `HKCU\...\Explorer\RunMRU` (Sysmon 13 / `DeviceRegistryEvents`) gains a value containing `powershell` or `mshta` seconds before the process. Script content is covered in [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/); mshta/rundll32/regsvr32 follow-on in [LOLBin proxy execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/).

### 4. Mark-of-the-Web: what came from the internet and then ran?

Sysmon 15 fires when `Zone.Identifier` is written (ZoneId 3 = internet). Its `Contents` field carries `HostUrl` and `ReferrerUrl`: a `blob:` or `data:` HostUrl with an `https://` referrer is HTML smuggling. Defender exposes the same as `FileOriginUrl` / `FileOriginReferrerUrl` on `DeviceFileEvents`.

```kql
let downloads = DeviceFileEvents
| where Timestamp > ago(14d) and ActionType == "FileCreated" and isnotempty(FileOriginUrl)
| where FileName has_any (".zip",".iso",".img",".vhd",".vhdx",".one",".lnk",".html",".htm",".svg")
| project DlTime = Timestamp, DeviceName, DlFile = FileName, FileOriginUrl, FileOriginReferrerUrl;
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","msiexec.exe")
| join kind=inner downloads on DeviceName
| where Timestamp between (DlTime .. DlTime + 30m)
| project DlTime, Timestamp, DeviceName, DlFile, FileOriginUrl, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Splunk: `index=sysmon EventCode=15 TargetFilename="*:Zone.Identifier"` with `rex field=Contents "HostUrl=(?<hosturl>\S+)"`.

### 5. Join email telemetry to the endpoint

Start from delivered mail with risky attachment types, then look for child processes on the recipient's device within an hour.

```kql
let risky = dynamic(["iso","img","vhd","vhdx","zip","rar","7z","one","lnk","html","htm","svg","xll","js","wsf","vbs"]);
let mails = EmailAttachmentInfo
| where Timestamp > ago(7d) and FileType in~ (risky)
| join kind=inner (EmailEvents | where DeliveryAction == "Delivered") on NetworkMessageId
| project MailTime = Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Attachment = FileName;
mails
| join kind=inner (IdentityInfo | distinct AccountUpn, AccountName) on $left.RecipientEmailAddress == $right.AccountUpn
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("outlook.exe","explorer.exe","winword.exe","excel.exe","onenote.exe","msedge.exe","chrome.exe","acrord32.exe")
    | where FileName in~ ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","msiexec.exe")
  ) on AccountName
| where Timestamp between (MailTime .. MailTime + 1h)
| project MailTime, Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Attachment, DeviceName, FileName, ProcessCommandLine
```

For links, swap `EmailAttachmentInfo` for `EmailUrlInfo` and match `UrlDomain` against `UrlClickEvents` (Safe Links) or `DeviceNetworkEvents.RemoteUrl`.

```spl
index=email direction=inbound (attachment_type IN ("iso","img","zip","one","lnk","html") OR url=*)
| rename recipient as user | eval mail_time=_time
| fields user mail_time sender subject attachment_name
| join type=inner max=0 user [ search index=sysmon EventCode=1
      (ParentImage="*\\outlook.exe" OR ParentImage="*\\explorer.exe" OR ParentImage="*\\winword.exe" OR ParentImage="*\\msedge.exe")
      (Image="*\\powershell.exe" OR Image="*\\mshta.exe" OR Image="*\\wscript.exe" OR Image="*\\rundll32.exe" OR Image="*\\cmd.exe")
    | rex field=User "\\\\(?<user>[^\\\\]+)$" | eval proc_time=_time | fields user proc_time host Image CommandLine ]
| where proc_time>mail_time AND proc_time<mail_time+3600
| table mail_time proc_time user sender subject attachment_name host Image CommandLine
```

`index=email` is a placeholder: sourcetypes differ (Proofpoint `pps_messagelog`, Mimecast, `ms:o365:reporting:messagetrace`, Cisco ESA). Normalise `recipient`, `sender`, `subject`, `attachment_name`, `url` into the Email CIM model first, and keep a UPN-to-sAMAccountName lookup for the join key.

### 6. The first beacon

Pivot from the child process to `DeviceNetworkEvents` / Sysmon 3 where `InitiatingProcessFileName` is a script host or LOLBin and `InitiatingProcessParentFileName` is one of the step-1 parents: first-seen or newly registered domain, direct-to-IP, or a file host (Discord CDN, Dropbox, GitHub raw, Pastebin) fetched by `powershell.exe` rather than a browser. Continue with the [C2 beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) for periodicity analysis.

### 7. User-reported phish triage

For each report: extract sender, return-path, URLs and attachment hashes; search `EmailEvents` for the same `SenderFromAddress`, `Subject` or hash to scope the campaign; check Safe Links / proxy for clicks; run steps 1-3 against every recipient's device for the hour after delivery. Record the outcome per recipient (no click / clicked / executed / credentials entered).

## Triage

| Check | Interpretation |
|---|---|
| Parent is Office/reader/browser, child is an interpreter | A user opened something they were sent; confirm with the email join |
| Image on a non-`C:` drive with no install footprint, or in `Temp1_*.zip\` / `Content.Outlook\` | Ran straight out of a container or attachment cache = delivery artefact |
| Command line > 250 chars with `-w hidden`, base64 or `iwr`/`iex` | LNK or ClickFix payload; decode it first |
| Sysmon 15 shows `blob:`/`data:` HostUrl, or no Zone.Identifier where one is expected | HTML smuggling / MOTW bypass |
| Outbound connection from the child within 60 s to a new domain | Stage two fetched; treat the host as compromised |
| Same sender/subject to many recipients, several with step-1 hits | Campaign; scope by recipient list, not by host |

## Common false positives

- Signed internal line-of-business add-ins or templates spawning `cmd`/`powershell` (allow-list by exact command line)
- Developers running scripts from extracted source archives
- IT staff mounting ISOs for installs (the child is a signed installer, not an interpreter)
- Browser helper processes (`--type=`) and PDF readers launching the default browser
- Phishing-simulation platforms (allow-list their sender domains at the join, not at the endpoint)

## Escalate when

A user-facing application spawned an interpreter **and** the child made an outbound connection or wrote to a persistence location; any execution from a mounted image or LNK-in-ZIP with a hidden PowerShell command line; or a campaign reached more than a handful of mailboxes. Isolate the host, recover the full command line and payload, and search mail for the rest of the campaign before the next recipient clicks.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1204.002`, `T1566.001`, `T1027.006`, `T1218.005` in the lab; record the parent/child pair and Sysmon 15 each produces
- Detection: [Office application spawns interpreter]({{ site.baseurl }}/research/sigma/T1566.001-office-application-spawns-interpreter.yml), [Execution from mounted image or archive]({{ site.baseurl }}/research/sigma/T1204.002-execution-from-mounted-image-or-archive.yml), [Mshta remote or script]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml), [Rundll32 suspicious invocation]({{ site.baseurl }}/research/sigma/T1218.011-rundll32-suspicious-invocation.yml)
- Hardening: ASR rules (block Office child processes, block executable content from email/webmail, block JS/VBScript launching downloaded content, block obfuscated scripts); remove ISO/IMG/VHD mount associations for standard users; map `.js`, `.jse`, `.wsf`, `.hta`, `.vbs` to Notepad; strip HTML, ISO, LNK and OneNote attachments at the gateway; disable the Run dialog (`NoRun`) where not needed; Safe Links with time-of-click checks; phishing-resistant MFA.

See also: [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/), [LOLBin proxy execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/), [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/), [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/).

{% include playbook-footer.html %}
