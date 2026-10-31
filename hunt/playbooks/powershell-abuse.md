---
title: "Playbook: PowerShell Abuse"
permalink: /hunt/playbooks/powershell-abuse/
excerpt: "Encoded commands, download cradles, unusual parents and script-block content: the highest-yield first hunt."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1059.001 (PowerShell), T1027 (Obfuscation), T1105 (Ingress tool transfer), T1562.001 (impair defenses via downgrade/AMSI bypass) |
| **Tactics** | Execution, Defense Evasion |
| **Data** | Process creation with command line (Sysmon 1 / 4688 / EDR); PowerShell Script Block Logging (4104) |
| **Time-box** | 2-4 hours |
| **Difficulty** | ★☆☆ |

## Hypothesis

> *If an adversary is using PowerShell for execution, we will see PowerShell launched with encoded/obfuscated arguments, from unusual parent processes, or fetching remote content, and Script Block Logs will contain download, reflection or AMSI-bypass content.*

## Data required (verify first)

- [ ] Process creation includes **command line** for PowerShell
- [ ] **Script Block Logging** enabled (`Microsoft-Windows-PowerShell/Operational`, Event 4104) on servers *and* workstations
- [ ] Hosts reporting in last 24 h (see [coverage query]({{ site.baseurl }}/learn/data-and-telemetry/#data-quality-checklist))

## Hunt steps

### 1. Encoded commands

```kql
// Defender Advanced Hunting
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe","powershell_ise.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(e|ec|en|enc|enco[a-z]*)\s+[A-Za-z0-9+/=]{30,}"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| regex CommandLine="(?i)\s-(e|ec|en|enc|enco\w*)\s+[A-Za-z0-9+/=]{30,}"
| stats count values(CommandLine) as cmds by host, User, ParentImage
| sort - count
```

**Decode the payload.** PowerShell encodes as UTF-16LE then base64:

```bash
echo '<base64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

### 2. Stack by parent process

Legitimate PowerShell is launched by a few parents (explorer, terminal, management agents, scheduled tasks). Everything else is interesting.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName in~ ("powershell.exe","pwsh.exe")
| summarize Launches = count(), Hosts = dcount(DeviceName) by InitiatingProcessFileName
| order by Hosts asc
```

**Priority parents:** `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `wmiprvse.exe`, `w3wp.exe`, `sqlservr.exe`, `java.exe`, `javaw.exe`, `rundll32.exe`, `regsvr32.exe`.

### 3. Download cradles and evasion switches

```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString","DownloadFile","DownloadData","Net.WebClient",
                                    "Invoke-WebRequest","Invoke-RestMethod","Start-BitsTransfer",
                                    "iwr ","irm ","IEX","Invoke-Expression")
   or ProcessCommandLine matches regex @"(?i)-(w|windowstyle)\s+h(idden)?\b.*-(nop|noprofile)|-ep\s+bypass|-exec(utionpolicy)?\s+bypass"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### 4. Script Block content (4104)

Command-line hunts miss scripts run from files or the pipeline; 4104 records the **deobfuscated** code.

```kql
// Sentinel with Windows event collection
Event
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where RenderedDescription has_any ("AmsiUtils","amsiInitFailed","Invoke-Mimikatz","System.Reflection.Assembly",
                                     "FromBase64String","VirtualAlloc","Add-Type -TypeDefinition",
                                     "Net.Sockets.TCPClient","Invoke-Shellcode","Get-GPPPassword")
| project TimeGenerated, Computer, RenderedDescription
```

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*VirtualAlloc*"
   OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*Net.Sockets.TCPClient*")
| stats count values(ScriptBlockText) as sample by host
```

Tip: 4104 scripts are chunked across multiple events (`MessageNumber`/`MessageTotal`, same `ScriptBlockId`). Reassemble before judging.

### 5. PowerShell v2 downgrade

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe") and ProcessCommandLine matches regex @"(?i)-v(ersion)?\s+2"
```

## Triage

| Question | Why |
|---|---|
| Who/what launched it? | Office or web-server parent = very suspicious |
| Account type and time of day? | Service account at 03:00 vs. admin during change window |
| What did the decoded script *do*? | Download, inject, enumerate, persist? |
| Did the host make an outbound connection within 60 s? | Confirms staging/C2 |
| Seen on other hosts (hash of decoded content / cradle URL)? | Scope |

## Common false positives

- Software deployment and management tools (SCCM, Intune, Ansible, vendor agents) using `-EncodedCommand`
- Monitoring agents; build servers; admins' own tooling

Handle by **allow-listing exact parent + command-line hash or signed script path**, not by account alone.

## Escalate to IR when

- Encoded/obfuscated PowerShell launched by Office, browser, script host or a server application, **or**
- Decoded content downloads and executes remote code, loads shellcode, dumps credentials, **or**
- Same payload on more than one host.

## Validate (lab)

```powershell
# Atomic Red Team: see labs/emulate-and-detect
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

Confirm your hunt queries and the [Sigma rule]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) both catch it.

## Operationalise

- Detection: [PowerShell encoded command]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml), [Defender tampering]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml)
- Hardening: PowerShell **Constrained Language Mode** via WDAC/AppLocker on non-admin hosts; remove PowerShell v2 (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`); enable AMSI-integrated AV; forward 4104 centrally
- Logging: Script Block Logging, Module Logging, Transcription (to a protected share)

## References

- MITRE ATT&CK T1059.001, <https://attack.mitre.org/techniques/T1059/001/>
- Microsoft: *about_Logging_Windows*
- Related post: [Threat Hunting 101]({{ site.baseurl }}/blog/threat-hunting-fundamentals/)
