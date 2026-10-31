---
title: "Sysmon Event IDs for Hunters"
excerpt: "What each Sysmon event gives you and the techniques it exposes."
---

Sysmon (Microsoft Sysinternals) logs to `Microsoft-Windows-Sysmon/Operational`. Start from a maintained community configuration (for example SwiftOnSecurity's `sysmon-config` or Olaf Hartong's `sysmon-modular`) and tune for your environment. See [Labs]({{ site.baseurl }}/labs/).

| ID | Event | Key fields | Hunting use / techniques |
|---|---|---|---|
| **1** | Process creation | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `OriginalFileName`, `IntegrityLevel`, `ProcessGuid` | The core: execution chains, LOLBins, renamed binaries (T1059, T1218, T1036) |
| **2** | File creation time changed | `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` | Timestomping (T1070.006) |
| **3** | Network connection | `Image`, `DestinationIp/Hostname/Port`, `Initiated` | C2, exfil, lateral (T1071, T1021); *high volume: filter* |
| **4** | Sysmon state changed | | Service stopped = tamper (T1562) |
| **5** | Process terminated | | Short-lived tooling |
| **6** | Driver loaded | `ImageLoaded`, `Signed`, `SignatureStatus` | BYOVD, rootkits (T1068, T1014) |
| **7** | Image (DLL) loaded | `ImageLoaded`, `Image`, `Signed` | DLL hijacking/side-loading (T1574); *very high volume* |
| **8** | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartFunction` | Injection (T1055) |
| **9** | RawAccessRead | `Device` | Disk read bypassing file ACLs (NTDS.dit, T1003.003) |
| **10** | Process access | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` | LSASS dumping (T1003.001), injection |
| **11** | File created | `TargetFilename`, `Image` | Payload drops, staging, ransom notes (T1105, T1074) |
| **12** | Registry object created/deleted | `TargetObject`, `EventType` | Persistence setup |
| **13** | Registry value set | `TargetObject`, `Details` | Run keys (T1547.001), COM hijack (T1546.015), Defender exclusions |
| **14** | Registry key/value renamed | | Evasion |
| **15** | FileCreateStreamHash | `TargetFilename`, `Contents` | Alternate data streams; Mark-of-the-Web (T1564.004) |
| **16** | Sysmon config changed | | Tamper (T1562) |
| **17 / 18** | Pipe created / connected | `PipeName`, `Image` | C2 named pipes (Cobalt Strike), PsExec-like, lateral movement |
| **19 / 20 / 21** | WMI filter / consumer / binding | `Operation`, `Name`, `Query`, `Destination` | WMI persistence (T1546.003) |
| **22** | DNS query | `QueryName`, `QueryResults`, `Image` | C2, DGA, tunneling, process-attributed DNS (T1071.004) |
| **23 / 26** | File delete (archived / logged) | `TargetFilename`, `Image` | Cleanup (T1070.004); ransomware wipe |
| **24** | Clipboard change | | Rare; data theft |
| **25** | Process tampering | `Type` (Image is replaced / Image is locked for access) | Hollowing, Doppelgänging, herpaderping (T1055) |
| **27** | File block executable | | Policy enforcement |
| **28** | File block shredding | | Policy enforcement |
| **29** | File executable detected | | New PE files written to disk |
| **255** | Sysmon error | | Health |

## Useful field conventions

- **`ProcessGuid`**: unique per process instance; use it (not PID) to build process trees.
- **`LogonGuid` / `LogonId`**: join to Security 4624.
- **`OriginalFileName`**: from PE resources; survives renaming (e.g. `rclone.exe` renamed to `svchost.exe`).
- **`Hashes`**: pivot with SHA256/IMPHASH; check prevalence across the fleet.
- **`CallTrace`** (event 10): `UNKNOWN(...)` frames often mean injected or reflectively loaded code.
- **`GrantedAccess`** (event 10): `0x1010` (`VM_READ|QUERY_LIMITED`), `0x1410`, `0x1438`, `0x143A`, `0x1FFFFF` (all access); typical credential-dump masks against `lsass.exe`.

## Quick SPL / KQL examples

```spl
index=sysmon EventCode=1 | stats dc(host) as hosts by ParentImage Image | where hosts<3 | sort hosts
index=sysmon EventCode=17 OR EventCode=18 | stats count by PipeName Image | sort count
index=sysmon EventCode=22 | rare limit=20 QueryName
```

```kql
// Sysmon ingested via Windows Event Forwarding -> Event table
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend Cmd = extract(@"CommandLine: (.*)", 1, RenderedDescription)
```

## Config tips

- Prefer **include-based rules** for noisy events (3, 7, 11, 22), and **exclude-based** for process creation (log nearly everything).
- Log **ImageLoad (7)** only for specific, high-value DLLs or paths, or you will drown.
- Version-control the config; tag the version in a registry key or rule name so you know which hosts run which rules.
- Monitor for Sysmon stopping (event 4, service 7036) and config changes (16).
