---
title: "Playbook: DLL Search-Order Hijacking & Side-Loading"
permalink: /hunt/playbooks/dll-hijacking/
excerpt: "Use image-load telemetry to find signed binaries loading DLLs they should not: system DLL names outside System32, unsigned DLLs from user-writable paths, known sideload pairs and phantom DLLs."
tactic: "Persistence"
attack: [T1574.001, T1574.002]
difficulty: 3
timebox: "4-6 hours"
data: [sysmon, edr]
---

{% include playbook-meta.html %}

**Data used:** Sysmon 7 (ImageLoaded, Signed, SignatureStatus, OriginalFileName), Sysmon 11 (file create); Defender `DeviceImageLoadEvents`, `DeviceFileEvents`; EDR module-load telemetry

## Background

When a program calls `LoadLibrary("foo.dll")` without a full path, Windows searches a fixed sequence of directories: the application's own directory, then System32, the 16-bit system directory, the Windows directory, the current working directory and finally `PATH`. Two abuses follow:

- **Search-order hijacking (T1574.001)**: a DLL the program expects to find in System32 is planted earlier in the search order, usually next to the executable. If the binary runs elevated or at logon, the attacker's code inherits that context: persistence and privilege escalation in one step. A sub-case is **phantom DLL loading**, where a Windows component tries to load a DLL that does not exist on a default install (`WptsExtensions.dll` by the Task Scheduler service, `wlbsctrl.dll` by IKEEXT, `TSMSISrv.dll`/`TSVIPSrv.dll` by Terminal Services), so simply creating the file is enough.
- **Side-loading (T1574.002)**: the attacker ships their *own* copy of a legitimate signed executable together with a malicious DLL it is known to load (`version.dll`, `dbghelp.dll`, a vendor-specific plug-in DLL). The signed binary vouches for the process; the payload runs inside it. The [Hijack Libs](https://hijacklibs.net) project catalogues hundreds of such pairs; APT groups and commodity loaders (PlugX, QakBot-era loaders, numerous ransomware precursors) use them routinely.

Neither technique produces a new process of its own, so process-creation hunting misses both. You need **module-load telemetry**: Sysmon event 7, Defender `DeviceImageLoadEvents` or your EDR's equivalent. Sysmon 7 is high volume; configure it with include rules for the DLL names and paths below rather than logging everything.

## Hypothesis

> *If a DLL hijack or sideload is active, a trusted (usually signed) process will load a DLL whose name belongs in System32 but whose path does not, or will load an unsigned DLL from a user-writable location, and that DLL will have been written to disk shortly before the first load.*

## Data required

- **Sysmon 7** with fields `Image`, `ImageLoaded`, `Signed`, `Signature`, `SignatureStatus`, `OriginalFileName`, `Hashes`. Include rules for: `ImageLoaded` ending in the hijack-prone names listed in step 1; `ImageLoaded` under `\Users\`, `\ProgramData\`, `\Windows\Temp\`, `\Downloads\`; `Signed: false`
- **Sysmon 11** (FileCreate) for `*.dll` writes outside `C:\Windows\` and `C:\Program Files*\`
- **Defender for Endpoint**: `DeviceImageLoadEvents` (note: it samples module loads and omits many Microsoft-signed DLLs; treat absence as unknown, not as proof) and `DeviceFileEvents`
- A software inventory or 30 days of image-load history to serve as a baseline
- Field names vary: the Sysmon TA for Splunk exposes `ImageLoaded`, `Signed`, `SignatureStatus`; Defender uses `FolderPath` for the DLL path and `InitiatingProcessFolderPath` for the loader, with signer info only via `DeviceFileCertificateInfo`

## Hunt steps

### 1. System DLL names loaded from outside System32 / SysWOW64

This is the highest-yield query. Pick DLL names that Windows binaries resolve by name and that attackers favour because they are easy to proxy: `version.dll`, `wtsapi32.dll`, `dbghelp.dll`, `dbgcore.dll`, `cryptsp.dll`, `cryptbase.dll`, `userenv.dll`, `profapi.dll`, `winmm.dll`, `wininet.dll`, `secur32.dll`, `sspicli.dll`, `dwmapi.dll`, `uxtheme.dll`, `propsys.dll`, `iphlpapi.dll`, `netapi32.dll`, `mpr.dll`, `wlbsctrl.dll`, `wow64log.dll`, `msimg32.dll`, `oleacc.dll`, `winhttp.dll`, `cscapi.dll`, `dnsapi.dll`, `edputil.dll`, `WptsExtensions.dll`, `TSMSISrv.dll`, `TSVIPSrv.dll`. Legitimate copies live only in `System32`, `SysWOW64` and `WinSxS`.

```kql
let HijackNames = dynamic(["version.dll","wtsapi32.dll","dbghelp.dll","dbgcore.dll","cryptsp.dll","cryptbase.dll","userenv.dll","profapi.dll","winmm.dll","wininet.dll","secur32.dll","sspicli.dll","dwmapi.dll","uxtheme.dll","propsys.dll","iphlpapi.dll","netapi32.dll","mpr.dll","wlbsctrl.dll","wow64log.dll","msimg32.dll","oleacc.dll","winhttp.dll","cscapi.dll","dnsapi.dll","edputil.dll","wptsextensions.dll","tsmsisrv.dll","tsvipsrv.dll"]);
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where tolower(FileName) in (HijackNames)
| where FolderPath !startswith @"C:\Windows\System32\" and FolderPath !startswith @"C:\Windows\SysWOW64\" and FolderPath !startswith @"C:\Windows\WinSxS\"
| summarize Hosts = dcount(DeviceName), Loads = count(), FirstSeen = min(Timestamp), Loaders = make_set(InitiatingProcessFolderPath, 5), SHA1s = make_set(SHA1, 3) by FolderPath
| order by Hosts asc, FirstSeen desc
```

```spl
index=sysmon EventCode=7
| rex field=ImageLoaded "\\\\(?<dll>[^\\\\]+)$"
| search dll IN (version.dll, wtsapi32.dll, dbghelp.dll, dbgcore.dll, cryptsp.dll, cryptbase.dll, userenv.dll, profapi.dll, winmm.dll, wininet.dll, secur32.dll, sspicli.dll, dwmapi.dll, uxtheme.dll, propsys.dll, iphlpapi.dll, netapi32.dll, mpr.dll, wlbsctrl.dll, wow64log.dll, msimg32.dll, oleacc.dll, winhttp.dll, cscapi.dll, dnsapi.dll, edputil.dll, WptsExtensions.dll, TSMSISrv.dll, TSVIPSrv.dll)
  NOT ImageLoaded IN ("C:\\Windows\\System32\\*","C:\\Windows\\SysWOW64\\*","C:\\Windows\\WinSxS\\*")
| stats dc(host) as hosts count min(_time) as first_seen values(Image) as loaders values(Signed) as signed values(SignatureStatus) as sigstatus by ImageLoaded
| sort hosts, - first_seen
```

Expect hits from a handful of legitimate products that ship their own `dbghelp.dll` or `msimg32.dll` in `Program Files`. Record them as (path, SHA-256, signer) tuples and exclude by hash, not by directory; a sideload in `C:\Program Files\<vendor>\` is exactly what you are hunting.

### 2. Unsigned or badly signed DLL loaded by a signed process

A signed, trusted executable loading an unsigned DLL is unusual for Microsoft and most enterprise software (plug-in architectures, games and open-source tools are the exceptions). `SignatureStatus` other than `Valid` (`Unavailable`, `Expired`, `Revoked`, `Bad`) on the DLL is the field to pivot on.

```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FolderPath !startswith @"C:\Windows\" and FolderPath !startswith @"C:\Program Files"
| join kind=leftouter (DeviceFileCertificateInfo | where Timestamp > ago(30d) | distinct SHA1, IsTrusted, Signer) on SHA1
| where isempty(IsTrusted) or IsTrusted == false
| summarize Hosts = dcount(DeviceName), Loads = count(), Loaders = make_set(InitiatingProcessFileName, 5), Signer = any(Signer) by FolderPath, SHA1
| where Hosts <= 3
| order by Loads desc
```

```spl
index=sysmon EventCode=7 (Signed=false OR SignatureStatus!=Valid)
  NOT ImageLoaded IN ("C:\\Windows\\*","C:\\Program Files\\*","C:\\Program Files (x86)\\*")
| stats dc(host) as hosts count values(Image) as loaders values(SignatureStatus) as status earliest(_time) as first_seen by ImageLoaded, Hashes
| where hosts<=3
| sort - first_seen
```

The Defender join is best effort: `DeviceFileCertificateInfo` is populated only for files Defender has inspected. Sysmon's inline `Signed`/`SignatureStatus` is more reliable.

### 3. Loads from user-writable paths by binaries that live elsewhere

Side-loaded payloads are dropped where the user can write: `%LOCALAPPDATA%\Temp`, `Downloads`, `C:\Users\Public`, `C:\ProgramData\<random>`, `C:\Windows\Temp`, `C:\PerfLogs`, removable media. A DLL loaded from one of these by a process that is *not itself* in the same directory is the sideload shape (the signed exe may sit next to the DLL in a dropped folder, which step 4 handles).

```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\Downloads\", @"\Users\Public\", @"C:\ProgramData\", @"C:\Windows\Temp\", @"C:\PerfLogs\", @"\AppData\Roaming\")
| where InitiatingProcessFolderPath !has_any (@"\AppData\Local\Temp\", @"\Downloads\", @"\Users\Public\", @"C:\ProgramData\", @"C:\Windows\Temp\")
| where InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "install.exe", "dllhost.exe", "rundll32.exe")
| summarize Hosts = dcount(DeviceName), Loads = count(), Loaders = make_set(InitiatingProcessFolderPath, 5) by FolderPath, SHA1
| order by Hosts asc
```

```spl
index=sysmon EventCode=7
  (ImageLoaded="*\\AppData\\Local\\Temp\\*" OR ImageLoaded="*\\Downloads\\*" OR ImageLoaded="*\\Users\\Public\\*" OR ImageLoaded="C:\\ProgramData\\*" OR ImageLoaded="C:\\Windows\\Temp\\*" OR ImageLoaded="C:\\PerfLogs\\*")
  NOT Image IN ("*\\AppData\\Local\\Temp\\*","*\\Downloads\\*","*\\Users\\Public\\*","C:\\ProgramData\\*","C:\\Windows\\Temp\\*")
  NOT Image IN ("*\\msiexec.exe","*\\setup.exe","*\\install.exe","*\\dllhost.exe")
| stats dc(host) as hosts count values(Image) as loaders values(Signed) as signed by ImageLoaded, Hashes
| sort hosts
```

`rundll32.exe` and `regsvr32.exe` loading DLLs from these paths is covered by the [LOLBin proxy execution playbook]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/); exclude them here to keep the result set focused, but do not forget them.

### 4. Known sideload pairs: legitimate exe in the wrong place

Sideload kits copy a well-known signed executable into a dropped directory next to the DLL it resolves by name: Google Chrome and Microsoft OneDrive updaters, Citrix and Zoom components, Defender's `MpCmdRun.exe`, VLC, Notepad++, `WerFault.exe`, `dism.exe`, `consent.exe`. Hijack Libs lists each pair. Match on `OriginalFileName` (PE version resource, so renaming does not help the attacker) and flag copies running outside the vendor's install path, then show what they loaded from their own directory.

```kql
let KnownSideloadExes = dynamic(["GoogleUpdate.exe","OneDriveStandaloneUpdater.exe","OneDrive.exe","MpCmdRun.exe","WerFault.exe","vlc.exe","notepad++.exe","CitrixReceiverUpdater.exe","SelfService.exe","Zoom.exe","consent.exe","dism.exe","mmc.exe","Teams.exe","msdtc.exe","sqldumper.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d) and ProcessVersionInfoOriginalFileName in~ (KnownSideloadExes)
| where FolderPath !startswith @"C:\Program Files" and FolderPath !startswith @"C:\Windows\"
| where FolderPath !has @"\AppData\Local\Microsoft\" and FolderPath !has @"\AppData\Local\Google\Update\"
| join kind=inner (DeviceImageLoadEvents | where Timestamp > ago(7d) and FolderPath !startswith @"C:\Windows\"
    | project DeviceId, ProcessId = InitiatingProcessId, DllPath = FolderPath, DllSHA1 = SHA1) on DeviceId, ProcessId
| summarize Loads = count(), Dlls = make_set(DllPath, 10) by DeviceName, FolderPath, ProcessVersionInfoOriginalFileName, SHA1
```

```spl
index=sysmon EventCode=1 OriginalFileName IN ("GoogleUpdate.exe","OneDriveStandaloneUpdater.exe","OneDrive.exe","MpCmdRun.exe","WerFault.exe","vlc.exe","notepad++.exe","CitrixReceiverUpdater.exe","SelfService.exe","Zoom.exe","consent.exe","dism.exe","mmc.exe","Teams.exe","msdtc.exe","sqldumper.exe")
  NOT Image IN ("C:\\Program Files\\*","C:\\Program Files (x86)\\*","C:\\Windows\\*","*\\AppData\\Local\\Microsoft\\*","*\\AppData\\Local\\Google\\Update\\*")
| join type=inner ProcessGuid [ search index=sysmon EventCode=7 NOT ImageLoaded="C:\\Windows\\*" | rename Image as loader | fields ProcessGuid ImageLoaded Signed loader ]
| stats count values(ImageLoaded) as dlls values(Signed) as dll_signed by host, Image, OriginalFileName, Hashes
```

Sysmon 1 carries `OriginalFileName` by default; the join on `ProcessGuid` ties the suspicious copy to the DLLs it loaded. `Image` alone is unreliable because the attacker chooses the filename.

### 5. Rare ImageLoaded paths for core system processes

Phantom DLLs (`WptsExtensions.dll`, `wlbsctrl.dll`, `TSMSISrv.dll`, `TSVIPSrv.dll`, `wow64log.dll`) are already caught by step 1 because they never appear under System32. Beyond named lists, stack every non-Windows DLL path loaded by `svchost.exe`, `spoolsv.exe`, `explorer.exe`, `winlogon.exe` and `lsass.exe` across the fleet and read the tail.

```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("svchost.exe", "spoolsv.exe", "explorer.exe", "winlogon.exe", "lsass.exe", "taskhostw.exe", "SearchIndexer.exe")
| where FolderPath !startswith @"C:\Windows\System32\" and FolderPath !startswith @"C:\Windows\SysWOW64\" and FolderPath !startswith @"C:\Windows\WinSxS\" and FolderPath !startswith @"C:\Windows\assembly\"
| summarize Hosts = dcount(DeviceName), Loads = count(), FirstSeen = min(Timestamp) by FolderPath, InitiatingProcessFileName, SHA1
| where Hosts <= 2
| order by FirstSeen desc
```

```spl
index=sysmon EventCode=7 Image IN ("*\\svchost.exe","*\\spoolsv.exe","*\\explorer.exe","*\\winlogon.exe","*\\lsass.exe","*\\taskhostw.exe")
  NOT ImageLoaded IN ("C:\\Windows\\System32\\*","C:\\Windows\\SysWOW64\\*","C:\\Windows\\WinSxS\\*","C:\\Windows\\assembly\\*")
| stats dc(host) as hosts count earliest(_time) as first_seen by ImageLoaded, Image, Hashes
| where hosts<=2
| sort - first_seen
```

Print drivers (`spoolsv.exe`), shell extensions (`explorer.exe`) and credential providers (`winlogon.exe`/`lsass.exe`) load third-party DLLs legitimately; new entries in `C:\Windows\System32\spool\drivers\` or `C:\Program Files\` on two hosts are usually a deployment. One host, written yesterday, is a finding.

### 6. DLL written into an application directory, then loaded

Sysmon 11 shows the write; Sysmon 7 shows the load. A `.dll` created in a `Program Files` or `ProgramData` application folder by anything other than an installer (`msiexec.exe`, the vendor's updater, SCCM) and loaded within an hour by the application in that folder is a hijack in progress.

```kql
let dllWrites = DeviceFileEvents
  | where Timestamp > ago(7d) and ActionType in ("FileCreated", "FileModified", "FileRenamed") and FileName endswith ".dll"
  | where FolderPath startswith @"C:\Program Files" or FolderPath startswith @"C:\ProgramData\"
  | where InitiatingProcessFileName !in~ ("msiexec.exe", "TiWorker.exe", "ccmexec.exe", "svchost.exe", "OneDriveSetup.exe")
  | project WriteTime = Timestamp, DeviceId, DllPath = FolderPath, Writer = InitiatingProcessFileName, WriterCmd = InitiatingProcessCommandLine;
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| join kind=inner dllWrites on DeviceId, $left.FolderPath == $right.DllPath
| where Timestamp between (WriteTime .. (WriteTime + 1h))
| project WriteTime, LoadTime = Timestamp, DeviceName, DllPath, Writer, WriterCmd, Loader = InitiatingProcessFolderPath
```

```spl
index=sysmon (EventCode=11 OR EventCode=7) (TargetFilename="C:\\Program Files*\\*.dll" OR TargetFilename="C:\\ProgramData\\*.dll" OR ImageLoaded="C:\\Program Files*\\*.dll" OR ImageLoaded="C:\\ProgramData\\*.dll")
| eval dll=coalesce(TargetFilename, ImageLoaded)
| stats min(eval(if(EventCode=11,_time,null()))) as write_time min(eval(if(EventCode=7,_time,null()))) as load_time values(eval(if(EventCode=11,Image,null()))) as writer values(eval(if(EventCode=7,Image,null()))) as loader by host, dll
| where isnotnull(write_time) AND isnotnull(load_time) AND load_time>=write_time AND load_time-write_time<3600
| where NOT match(writer, "(?i)msiexec|TiWorker|CcmExec|OneDriveSetup")
| convert ctime(write_time) ctime(load_time)
```

## Triage

| Check | Interpretation |
|---|---|
| Prevalence of the DLL hash | One or two hosts = investigate; fleet-wide with a known signer = software |
| DLL signature vs. loader signature | Signed Microsoft loader + unsigned DLL from its own directory = sideload until proven otherwise |
| Exported functions | A `version.dll` of 20 KB that forwards all exports to the real one (`#pragma comment(linker,"/export:...=C:\\Windows\\System32\\version.dll...")`) is a proxy DLL |
| Who wrote it (Sysmon 11 / `DeviceFileEvents`) | Browser, archive utility, Office or a script wrote the DLL = delivered; installer = probably legitimate |
| Loader context | SYSTEM service or an auto-elevated binary = privilege escalation achieved |
| Network activity from the loader after the load | Legitimate updater talking to vendor CDN is fine; new outbound to a bare IP is C2 |

## Common false positives

- Vendors that ship private copies of `dbghelp.dll`, `msimg32.dll`, `winmm.dll` or `version.dll` with their application (debuggers, games, Steam, some Adobe and Autodesk products): exclude by hash and signer
- Python, Node, Electron and Java runtimes loading hundreds of unsigned DLLs from `%LOCALAPPDATA%` and `node_modules`; per-user developer tooling in `AppData\Local\Programs`
- Installers executing from `Downloads` or `Temp` and loading their own DLLs (the loader is in the same dropped directory, which is why step 3 excludes same-directory loads and step 4 scopes them to known sideload executables)

## Escalate when

- A hijack-prone system DLL name is loaded from any path outside `System32`/`SysWOW64`/`WinSxS` on fewer than three hosts and the DLL is unsigned or signed by an unexpected party
- A known sideload executable runs from `Downloads`, `Temp`, `ProgramData` or `Public` with a same-directory DLL
- Any phantom DLL (`WptsExtensions.dll`, `wlbsctrl.dll`, `TSMSISrv.dll`, `TSVIPSrv.dll`) exists or loads
- A DLL is written into an application folder by a non-installer process and loaded by a SYSTEM service within the hour
- The loading process goes on to make network connections, spawn a shell, or access LSASS (see [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/))

Acquire the DLL and loader, check the DLL's exports and imports, and sweep the fleet for the DLL hash and the dropped directory name.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1574.001` (creates a hijackable `amsi.dll`/`wlbsctrl.dll` scenario) and `Invoke-AtomicTest T1574.002` (sideloads a benign DLL through a signed binary). Confirm Sysmon 7 and `DeviceImageLoadEvents` both record the load with the expected `Signed`/`SignatureStatus` values before trusting the queries.
- Detection: [System DLL loaded from unusual path]({{ site.baseurl }}/research/sigma/T1574.001-system-dll-loaded-from-unusual-path.yml), [DLL side-load from user-writable path]({{ site.baseurl }}/research/sigma/T1574.002-dll-sideload-from-user-writable-path.yml). Keep the rare-path stacking (steps 5 and 6) as scheduled hunts.
- Hardening: `SafeDllSearchMode` enabled (default since XP SP2; verify the registry value `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1`); set `CWDIllegalInDllSearch` (`HKLM\...\Session Manager\CWDIllegalInDllSearch = 0xFFFFFFFF`) to remove the current directory from the search path; application control (WDAC or AppLocker **with DLL rules enabled**) so unsigned DLLs cannot load from user-writable locations; fix weak NTFS permissions on service and `Program Files` directories; remove or restrict the services that look for phantom DLLs (IKEEXT, unused Terminal Services components); use `SetDefaultDllDirectories`/`LOAD_LIBRARY_SEARCH_SYSTEM32` in in-house code.

See also: [Persistence playbook]({{ site.baseurl }}/hunt/playbooks/persistence/) · [LOLBin proxy execution]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/) · [Defense evasion]({{ site.baseurl }}/hunt/playbooks/defense-evasion/) · [Sysmon cheat sheet]({{ site.baseurl }}/cheatsheets/sysmon/) · [Hijack Libs](https://hijacklibs.net).

{% include playbook-footer.html %}
