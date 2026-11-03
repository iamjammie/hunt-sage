---
title: "Playbook: macOS Hunting"
permalink: /hunt/playbooks/macos-hunting/
excerpt: "LaunchAgent and LaunchDaemon drops, login items, AppleScript abuse, Gatekeeper bypass, Keychain theft and credential-phishing dialogs on Mac fleets."
tactic: "Persistence"
attack: [T1543.001, T1543.004, T1547.015, T1059.002, T1553.001, T1555.001, T1056.002, T1518.001, T1105, T1059.004]
difficulty: 2
timebox: "4-6 hours"
data: [edr, macos-unified-log, osquery]
---

{% include playbook-meta.html %}

**Data used:** EDR with Endpoint Security (ES) telemetry on macOS (Defender for Endpoint, Jamf Protect, CrowdStrike, SentinelOne): process, file, network events; unified log (`log show`); osquery tables `launchd`, `crontab`, `processes`, `listening_ports`, `es_process_events`, `file_events`

## Background

Mac fleets are usually the least-hunted part of an estate: fewer agents, fewer analysts who know the platform, and an assumption that Gatekeeper and notarisation keep things clean. Real-world macOS intrusions (AMOS and other stealers, XCSSET, JokerSpy, RustBucket and the DPRK job-lure families, and plain commodity adware droppers) rely on the same small set of behaviours:

- **Persistence** through a property list in `~/Library/LaunchAgents` (user), `/Library/LaunchAgents` or `/Library/LaunchDaemons` (root), loaded with `launchctl load` / `launchctl bootstrap`, or through **login items** (`backgrounditems.btm`, `osascript -e 'tell application "System Events" to make login item'`) and, less often, `cron` and `at`.
- **Execution** through `osascript` (AppleScript or JavaScript for Automation), `bash`/`zsh` one-liners, Python, and `curl | sh` style downloaders writing to `/tmp`, `/private/tmp`, `/Users/Shared` or `~/Library/Application Support/<random>`.
- **Defense evasion** by stripping the quarantine attribute (`xattr -d com.apple.quarantine`) so Gatekeeper never sees the file, by `spctl --master-disable`, or by abusing ad-hoc signed and unnotarised binaries dropped from a disk image.
- **Credential access** through fake password dialogs (`osascript -e 'display dialog ... with hidden answer'`) and Keychain reads (`security find-generic-password -ga`, `security dump-keychain -d`, direct reads of `~/Library/Keychains/login.keychain-db`), plus browser-store theft (Chrome `Login Data`, Firefox `logins.json`).
- **Discovery** of security tooling (`system_profiler SPApplicationsDataType`, `ps` for `falcon`, `MsMpEng`, `JamfProtect`, `SentinelAgent`) before deciding whether to continue.

Apple's Endpoint Security framework gives EDR vendors process, file and authentication events that are at least as good as Sysmon on Windows, so the hunt below assumes an EDR with macOS coverage. Where it does not exist, osquery and the unified log fill most of the gaps.

## Hypothesis

> *If a Mac in our fleet is compromised, we would see a LaunchAgent, LaunchDaemon or login item appear whose program lives in a user-writable path, created by a process that is not an installer or MDM agent, usually within minutes of a quarantine-attribute removal, an `osascript` dialog or a download to `/tmp`.*

## Data required

- **EDR on macOS**: process creation with full command line, file create/rename events, network connections, and (ideally) ES authentication and `xattr` events. In Defender for Endpoint the same `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents` tables apply; filter on `DeviceInfo` `OSPlatform == "macOS"`.
- **osquery** (via Fleet, Kolide, Jamf or standalone) with the `launchd`, `crontab`, `users`, `processes`, `listening_ports`, `authorized_keys`, `es_process_events` and `file_events` tables. Schedule the persistence tables at least hourly and ship the differential results.
- **Unified log** on the endpoint for triage, not for fleet hunting: `log show --last 2h --predicate 'process == "launchd" OR process == "xpcproxy"'`, and `log show --predicate 'subsystem == "com.apple.securityd"'` for Keychain access prompts.
- **MDM inventory** (Jamf, Kandji, Mosyle): the list of sanctioned LaunchDaemons and login items is your allow-list, so export it before you start.

Confirm the EDR is actually reporting `xattr`, `osascript` and `launchctl` executions from a test Mac before trusting negative results; some sensors suppress Apple-signed binaries by default.

## Hunt steps

### 1. LaunchAgent / LaunchDaemon plists created outside installers

Stack new plists by the process that wrote them. Installers, MDM agents and package managers create almost all legitimate ones; anything written by a shell, `osascript`, Python, a browser or a process running from `/tmp` or `/Users/Shared` goes to the top of the triage list.

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/Library/LaunchAgents/", "/Library/LaunchDaemons/") and FileName endswith ".plist"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName !in~ ("installer", "pkgd", "package_script_service", "jamf", "kandji-agent", "mosyled", "brew", "ruby", "softwareupdated")
| summarize Hosts = dcount(DeviceId), Plists = make_set(FileName, 10), Writers = make_set(InitiatingProcessFolderPath, 5), FirstSeen = min(Timestamp)
          by FileName, InitiatingProcessFileName
| order by Hosts asc, FirstSeen desc
```

```spl
index=edr sourcetype="mac:edr:file" (file_path="*/Library/LaunchAgents/*" OR file_path="*/Library/LaunchDaemons/*") file_name="*.plist" action IN (create, modify, rename)
| search NOT process_name IN (installer, pkgd, package_script_service, jamf, kandji-agent, mosyled, brew, softwareupdated)
| stats dc(host) as hosts values(process_path) as writers min(_time) as first_seen by file_name process_name
| sort hosts, -first_seen
```

Then look **inside** the rare plists (osquery below): a `ProgramArguments` entry pointing to `/tmp`, `/Users/Shared`, `~/Library/Application Support/<random>`, `/private/var/folders` or a hidden directory (`/.`), `RunAtLoad` true, `KeepAlive` true and a label that mimics Apple (`com.apple.*` in the user's LaunchAgents is never legitimate) are the markers.

```sql
-- osquery: launch items whose program is in a user-writable or temporary location
SELECT l.name, l.label, l.path, l.program, l.program_arguments, l.run_at_load, l.keep_alive, l.username
FROM launchd l
WHERE (l.path LIKE '/Library/LaunchDaemons/%' OR l.path LIKE '%/Library/LaunchAgents/%')
  AND (l.program_arguments LIKE '%/tmp/%' OR l.program_arguments LIKE '%/Users/Shared/%'
       OR l.program_arguments LIKE '%/private/var/folders/%' OR l.program_arguments LIKE '%/Application Support/%'
       OR l.program_arguments LIKE '%/.%' OR l.program_arguments LIKE '%python%' OR l.program_arguments LIKE '%osascript%'
       OR l.program_arguments LIKE '%curl%' OR l.program_arguments LIKE '%/bin/sh -c%' OR l.program_arguments LIKE '%/bin/bash -c%');
```

### 2. launchctl and login-item activity from the wrong parents

`launchctl load`, `launchctl bootstrap` and `launchctl enable` run by a shell whose ancestor is a browser, a mounted disk image, `osascript` or a process in `/tmp` is the moment persistence is armed. Login items are added through the System Events scripting dictionary or by writing `backgrounditems.btm` (macOS 13+ records this as a `BTM` event in the unified log and as `sfltool dumpbtm` output).

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "launchctl" and ProcessCommandLine has_any ("load", "bootstrap", "enable", "kickstart", "submit"))
   or (FileName =~ "osascript" and ProcessCommandLine has "login item")
   or ProcessCommandLine has "backgrounditems.btm"
| where InitiatingProcessFolderPath has_any ("/tmp/", "/private/tmp/", "/Volumes/", "/Users/Shared/", "/Downloads/", "/var/folders/")
   or InitiatingProcessFileName in~ ("osascript", "python3", "python", "curl", "Safari", "Google Chrome", "firefox", "Terminal")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```

```spl
index=edr sourcetype="mac:edr:process" ((process_name=launchctl process IN ("*load*","*bootstrap*","*enable*","*kickstart*")) OR (process_name=osascript process="*login item*") OR process="*backgrounditems.btm*")
| search parent_process_path IN ("/tmp/*","/private/tmp/*","/Volumes/*","/Users/Shared/*","*/Downloads/*","*/var/folders/*") OR parent_process_name IN (osascript, python3, python, curl, Safari, "Google Chrome", firefox)
| table _time host user process parent_process_name parent_process_path parent_process
```

Baseline first: list every `launchctl` parent seen in the last 30 days, allow-list the MDM and installer parents, then read what remains.

### 3. Quarantine attribute removal and Gatekeeper tampering

Legitimate users almost never run `xattr -d com.apple.quarantine`; droppers and "fix your Mac" instructions do it constantly. Treat `spctl --master-disable` / `--global-disable` and `defaults write com.apple.LaunchServices LSQuarantine -bool NO` the same way.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "xattr" and ProcessCommandLine has "com.apple.quarantine" and ProcessCommandLine has_any ("-d", "-c", "-r"))
   or (FileName =~ "spctl" and ProcessCommandLine has_any ("--master-disable", "--global-disable", "--disable"))
   or ProcessCommandLine has "LSQuarantine"
| summarize Count = count(), Targets = make_set(ProcessCommandLine, 10), Parents = make_set(InitiatingProcessFileName, 5) by DeviceName, AccountName, bin(Timestamp, 1d)
| order by Count desc
```

```spl
index=edr sourcetype="mac:edr:process" ((process_name=xattr process="*com.apple.quarantine*" process IN ("* -d*","* -c*","* -r*")) OR (process_name=spctl process IN ("*--master-disable*","*--global-disable*")) OR process="*LSQuarantine*")
| stats count values(process) as cmds values(parent_process_name) as parents by host user
| sort - count
```

Pivot: whatever file had its attribute stripped should be checked for signature (`codesign -dv --verbose=4`), notarisation (`spctl -a -vv`) and execution within the next few minutes.

### 4. osascript: credential dialogs and JXA execution

The classic stealer prompt is `osascript -e 'display dialog "macOS needs to update settings" default answer "" with hidden answer with icon caution'`. Any `display dialog` with `hidden answer` outside an MDM-signed script is a password-phishing attempt (T1056.002); `-l JavaScript`, `-e` with base64 or `do shell script` chains are execution (T1059.002).

```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName =~ "osascript"
| extend Dialog = ProcessCommandLine has "display dialog" and ProcessCommandLine has "hidden answer",
         Shell = ProcessCommandLine has "do shell script",
         JXA = ProcessCommandLine has "-l JavaScript",
         Encoded = ProcessCommandLine has_any ("base64", "echo ", "eval")
| where Dialog or Shell or JXA or Encoded
| project Timestamp, DeviceName, AccountName, Dialog, Shell, JXA, Encoded, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

```spl
index=edr sourcetype="mac:edr:process" process_name=osascript (process="*display dialog*hidden answer*" OR process="*do shell script*" OR process="*-l JavaScript*" OR process="*base64*")
| eval kind=case(match(process,"hidden answer"),"credential-dialog", match(process,"do shell script"),"shell", match(process,"-l JavaScript"),"jxa", true(),"other")
| stats count values(process) as cmds by host user kind parent_process_name
```

Also stack **script files** passed to `osascript` by path: anything under `/tmp`, `/Volumes`, `/Users/Shared` or inside an app bundle in `~/Downloads` is suspect. MDM scripts live in known paths (`/Library/Application Support/JAMF/tmp/`, `/Library/Kandji/`); allow-list those paths, not the binary.

### 5. Keychain and browser credential-store access

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "security" and ProcessCommandLine has_any ("dump-keychain", "find-generic-password", "find-internet-password", "export", "-ga", " -g "))
   or ProcessCommandLine has_any ("login.keychain-db", "/Library/Keychains/", "Login Data", "Cookies", "logins.json", "key4.db", "Local State")
| where InitiatingProcessFileName !in~ ("Google Chrome", "Google Chrome Helper", "firefox", "Safari", "com.apple.WebKit.Networking", "mds", "mdworker", "backupd", "Time Machine")
| summarize Count = count(), Cmds = make_set(ProcessCommandLine, 10) by DeviceName, AccountName, FileName, InitiatingProcessFileName
| order by Count desc
```

```spl
index=edr sourcetype="mac:edr:process" ((process_name=security process IN ("*dump-keychain*","*find-generic-password*","*find-internet-password*","* -ga*")) OR process IN ("*login.keychain-db*","*/Library/Keychains/*","*Login Data*","*logins.json*","*key4.db*"))
| search NOT parent_process_name IN ("Google Chrome*", firefox, Safari, mds, mdworker, backupd)
| stats count values(process) as cmds by host user process_name parent_process_name
```

Reads of `login.keychain-db` by anything other than `securityd` and the user's own apps, or `security` with `-g`/`-ga` (prints the password), are rarely benign. Combine with step 4: a credential dialog followed by `security` within minutes is the full stealer sequence.

### 6. Download-and-execute chains in temporary paths

```kql
let downloads = DeviceFileEvents
  | where Timestamp > ago(14d) and ActionType == "FileCreated"
  | where FolderPath has_any ("/tmp/", "/private/tmp/", "/Users/Shared/", "/var/folders/", "/Volumes/")
  | where InitiatingProcessFileName in~ ("curl", "wget", "python3", "python", "osascript", "sh", "bash", "zsh", "Safari", "Google Chrome", "firefox")
  | project DownloadTime = Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA256, Downloader = InitiatingProcessFileName;
let execs = DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where FolderPath has_any ("/tmp/", "/private/tmp/", "/Users/Shared/", "/var/folders/", "/Volumes/")
  | project ExecTime = Timestamp, DeviceId, FileName, FolderPath, ProcessCommandLine, AccountName;
downloads
| join kind=inner execs on DeviceId, FileName, FolderPath
| where ExecTime between (DownloadTime .. (DownloadTime + 10m))
| project DeviceName, AccountName, Downloader, FolderPath, FileName, SHA256, DownloadTime, ExecTime, ProcessCommandLine
```

```spl
index=edr sourcetype="mac:edr:process" process_path IN ("/tmp/*","/private/tmp/*","/Users/Shared/*","*/var/folders/*","/Volumes/*")
| stats earliest(_time) as first count dc(host) as hosts values(process) as cmds values(parent_process_name) as parents by process_hash
| where hosts<=3
| sort first
```

Add `chmod +x` and `chmod 755` on files in those paths as a second signal, and `curl -o`/`curl -s ... | sh` with a raw IP, a paste site or a newly registered domain as a third. Mounted disk images (`/Volumes/<name>/<App>.app/Contents/MacOS/...`) running Terminal, `osascript` or `bash` are the "right-click to open" installers stealers ship.

### 7. Security software discovery before action

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "system_profiler" and ProcessCommandLine has_any ("SPApplicationsDataType", "SPInstallHistoryDataType", "SPConfigurationProfileDataType"))
   or (FileName in~ ("ps", "pgrep", "launchctl") and ProcessCommandLine has_any ("falcon", "MsMpEng", "wdavdaemon", "JamfProtect", "SentinelAgent", "CrowdStrike", "LittleSnitch", "Lulu", "KnockKnock", "BlockBlock"))
   or (FileName =~ "sw_vers")
| summarize Count = count(), Cmds = make_set(ProcessCommandLine, 10) by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where InitiatingProcessFileName !in~ ("jamf", "kandji-agent", "osqueryd", "mosyled", "Terminal")
| order by Count desc
```

One `sw_vers` is nothing; `sw_vers` + `system_profiler SPApplicationsDataType` + a `ps` grep for EDR names inside a minute, from a non-MDM parent, is a stealer's pre-flight check.

### 8. Fleet-wide persistence stacking with osquery

Run differential queries on `launchd`, `crontab`, `users` and `authorized_keys`, then stack the results across the fleet. Items present on one or two Macs, with a program outside `/System`, `/usr`, `/Applications` or the MDM's own paths, are what you review.

```sql
-- osquery: cron and at jobs (rare on managed Macs)
SELECT c.command, c.path, c.event, u.username FROM crontab c LEFT JOIN users u ON c.path LIKE '%' || u.username || '%';

-- osquery: listening ports owned by processes in temporary paths
SELECT p.pid, p.name, p.path, lp.port, lp.address FROM listening_ports lp JOIN processes p USING (pid)
WHERE p.path LIKE '/tmp/%' OR p.path LIKE '/Users/Shared/%' OR p.path LIKE '/private/var/folders/%' OR p.path LIKE '%/Downloads/%';
```

Ship the output to the SIEM and apply the same long-tail logic as the Windows [persistence playbook]({{ site.baseurl }}/hunt/playbooks/persistence/).

## Triage

| Check | Interpretation |
|---|---|
| Who wrote the plist / login item? | Installer, MDM, `brew` = usually fine; shell, `osascript`, Python, browser, anything from `/tmp` or a `/Volumes` image = suspicious |
| Where does `ProgramArguments` point? | `/System`, `/usr`, `/Applications/<signed app>` = normal; user-writable, hidden or random-named path = bad |
| Signature and notarisation of the program | `codesign -dv --verbose=4` and `spctl -a -vv`; ad-hoc signed or unsigned binaries that persist are rarely legitimate |
| Label mimics Apple or a vendor? | `com.apple.*` in a user's LaunchAgents, or a typo of a real vendor label, is a deliberate disguise |
| Preceded by `xattr -d`, `osascript` dialog or a `/tmp` download? | The full dropper sequence; treat as compromise, not adware |
| Did `security` or a browser store get read afterwards? | Credential theft achieved; reset passwords and revoke sessions |
| Network connections from the persisted program? | Rare destination, raw IP or new domain = C2; see [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |

## Common false positives

- MDM agents, Homebrew, Docker Desktop, Zoom, Microsoft AutoUpdate, Adobe, Google Keystone and Dropbox install and update their own LaunchAgents and LaunchDaemons; allow-list by **label + program path + signer**, not by filename.
- Developers and IT staff use `xattr -d com.apple.quarantine` on tools they built or downloaded from GitHub; a one-off on a known developer Mac is noise, a fleet pattern from `Downloads` is not.
- Security tools themselves run `system_profiler` and query the Keychain; exclude their process paths explicitly.
- Automation frameworks (Jamf policies, Kandji blueprints, Munki) run `osascript` for user notifications; they never ask for a password with `hidden answer`.
- Backup software (Time Machine, Backblaze) reads Keychain files as part of full-disk backup.

## Escalate when

A LaunchAgent, LaunchDaemon or login item points to a user-writable path **and** any of: a quarantine-attribute removal, an `osascript` credential dialog, a Keychain or browser-store read, or outbound connections to a rare destination from the persisted program. Isolate the Mac via MDM or EDR, collect the plist, the program, `~/Library/Application Support` and the unified log (`sysdiagnose` or `log collect`), reset the user's passwords and revoke browser sessions, and sweep the fleet for the same label, hash and destination.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1543.001` and `T1543.004` (LaunchAgent / LaunchDaemon plist creation), `T1547.015` (login item via `osascript`), `T1059.002` (`osascript` execution), `T1553.001` (`xattr -d com.apple.quarantine`), `T1555.001` (`security dump-keychain`), `T1518.001` (security software discovery); run them on an isolated test Mac with the EDR and osquery agents installed and confirm each step above surfaces the test.
- Detection: [LaunchAgent plist written to a user-writable path]({{ site.baseurl }}/research/sigma/T1543.001-launch-agent-plist-in-user-writable-path.yml), [Suspicious osascript invocation]({{ site.baseurl }}/research/sigma/T1059.002-osascript-suspicious-invocation.yml). Add a scheduled analytic on `xattr -d com.apple.quarantine` from `Downloads` and a daily osquery differential on `launchd`.
- Hardening: MDM-enforced Gatekeeper with notarisation required and `spctl` locked; block or restrict `osascript` and `xattr` for standard users with a Jamf/Kandji restriction or a Santa/Google Santa allow-list; disable `at`; enable Apple's `backgrounditems` notifications (macOS 13+) so users see new login items; keep Macs on the current major release (TCC, BTM and notarisation improvements land there first); deploy osquery fleet-wide with the persistence tables scheduled.

See also: [Persistence playbook]({{ site.baseurl }}/hunt/playbooks/persistence/) for the Windows equivalents, [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) for the Unix shell and cron patterns, [Phishing & initial execution]({{ site.baseurl }}/hunt/playbooks/initial-access-phishing/) for the disk-image lures, and the [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) chapter for enabling endpoint coverage.

{% include playbook-footer.html %}
