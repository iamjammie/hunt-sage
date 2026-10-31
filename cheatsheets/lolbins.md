---
title: "LOLBins Quick Reference"
permalink: /cheatsheets/lolbins/
excerpt: "Commonly abused Windows binaries: what they are used for and which arguments give them away."
---

> Full catalogue: **[LOLBAS](https://lolbas-project.github.io/)**. Linux: **[GTFOBins](https://gtfobins.github.io/)**. Drivers: **[LOLDrivers](https://www.loldrivers.io/)**. macOS: **[LOOBins](https://www.loobins.io/)**.

Detection principle: **binary + arguments + parent + network + user**. The binary alone is rarely enough.

| Binary | Abuse | Suspicious argument patterns | MITRE |
|---|---|---|---|
| `certutil.exe` | Download, encode/decode | `-urlcache -split -f http...`, `-decode`, `-encode`, `-verifyctl` | T1105, T1140 |
| `bitsadmin.exe` | Download, persistence | `/transfer`, `/addfile`, `/SetNotifyCmdLine` | T1197 |
| `mshta.exe` | Run HTA/script | `http(s)://`, `javascript:`, `vbscript:` | T1218.005 |
| `rundll32.exe` | Run DLL/script | `javascript:`, `comsvcs.dll, MiniDump`, DLL in `Temp`/`AppData`, no-arg spawn | T1218.011, T1003.001 |
| `regsvr32.exe` | Squiblydoo | `/s /n /u /i:http://... scrobj.dll` | T1218.010 |
| `msiexec.exe` | Run remote MSI | `/q /i http://...` | T1218.007 |
| `wmic.exe` | Remote exec, recon, XSL | `/node:`, `process call create`, `/format:http...`, `shadowcopy delete` | T1047, T1220 |
| `powershell.exe` | Everything | `-enc`, `-nop -w hidden`, `IEX`, `DownloadString` | T1059.001 |
| `cmd.exe` | Command chaining | `/c` with `&`, `^` obfuscation, long cmdlines | T1059.003 |
| `wscript.exe` / `cscript.exe` | Script host | `.js`, `.vbs`, `.wsf` from `AppData`/`Temp`/`Downloads` | T1059.005/.007 |
| `schtasks.exe` | Persistence / remote exec | `/create ... /s <host>`, `/ru SYSTEM`, user-path actions | T1053.005 |
| `sc.exe` | Service creation / tamper | `create ... binPath=`, `config ... start= disabled`, remote `\\host` | T1543.003, T1562.001 |
| `reg.exe` | Persistence, dump hives | `add ...\Run`, `save HKLM\SAM|SYSTEM|SECURITY`, `export` | T1547.001, T1003.002 |
| `net.exe` / `net1.exe` | Recon, accounts | `user /add`, `localgroup administrators /add`, `use \\host\ipc$`, `group "domain admins" /domain` | T1136, T1087, T1021.002 |
| `nltest.exe` | Domain recon | `/dclist:`, `/domain_trusts` | T1482 |
| `dsquery.exe`, `adfind.exe` | AD enumeration | `* -filter`, `-f "(objectcategory=...)"` | T1087.002 |
| `whoami.exe` | Recon | `/all`, `/priv`, `/groups` | T1033 |
| `tasklist.exe` / `taskkill.exe` | Recon / kill AV | `/fi`, `/im defender...` | T1057, T1562 |
| `vssadmin.exe` / `diskshadow.exe` / `wbadmin.exe` / `bcdedit.exe` | Impact / NTDS access | `delete shadows`, `recoveryenabled no`, `create shadow` | T1490, T1003.003 |
| `ntdsutil.exe` | Dump AD DB | `"ac i ntds" "ifm" "create full"` | T1003.003 |
| `esentutl.exe` | Copy locked files | `/y /vss` | T1003.003 |
| `msbuild.exe` | Compile & run inline C# | `.csproj`/`.xml` in user path; network connections from msbuild | T1127.001 |
| `installutil.exe`, `regasm.exe`, `regsvcs.exe` | .NET proxy execution | `/U` with DLL from user path | T1218.004/.009 |
| `cmstp.exe` | INF execution, UAC bypass | `/s /ns` with `.inf` from user path | T1218.003 |
| `forfiles.exe`, `pcalua.exe`, `SyncAppvPublishingServer.exe` | Indirect command execution | `/c cmd`, `-a` path, `-p` | T1202 |
| `control.exe` | CPL execution | `.cpl` from user path | T1218.002 |
| `odbcconf.exe` | DLL load | `/a {REGSVR dll}` | T1218.008 |
| `expand.exe`, `extrac32.exe`, `makecab.exe` | Copy/compress files | cab to/from UNC, ADS paths | T1105, T1560 |
| `curl.exe`, `tar.exe`, `ssh.exe` (built-in) | Transfer, tunneling | `curl -o`, `ssh -R/-L/-D` tunnels | T1105, T1572 |
| `ftp.exe` | Scripted transfer | `-s:script.txt` | T1048 |
| `findstr.exe` | Download from UNC / search creds | `/V /L ... \\host\share` | T1105 |
| `print.exe`, `xcopy.exe`, `robocopy.exe` | Copy files, staging | Copies to admin shares | T1570, T1074 |
| `dnscmd.exe` | DNS server plug-in DLL | `/config /serverlevelplugindll` | T1543.003 |
| `eventvwr.exe`, `fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe` | UAC bypass via registry hijack | Preceding `HKCU\Software\Classes\...\command` write | T1548.002 |

## Detection helpers

- Use PE **`OriginalFileName`** to catch renamed copies.
- Check **path**: these live in `System32`/`SysWOW64`; copies in `Users`, `Temp` or `ProgramData` are rarely legit.
- **Parent matters**: Office, browser, mail client, `wmiprvse.exe`, `w3wp.exe`, `services.exe`, `wsmprovhost.exe` as parents of the above are high-signal.
- **Network**: `rundll32`, `regsvr32`, `mshta`, `msbuild`, `certutil` making outbound connections is unusual.
- **Command-line obfuscation**: carets (`c^e^r^t^u^t^i^l`), mixed case, env var substring tricks, `%COMSPEC%`, excessive length, `-` vs `/` vs `–` (en dash) switches. Sigma `|windash` handles switch variants.

Related: [LOLBin proxy execution playbook]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/).
