---
title: "Playbook: LOLBin Proxy Execution"
permalink: /hunt/playbooks/lolbin-proxy-execution/
excerpt: "Signed Windows binaries abused to download, decode and execute: certutil, mshta, rundll32, regsvr32, bitsadmin and friends."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1218.* (System Binary Proxy Execution), T1140 (Deobfuscate/Decode), T1105 (Ingress Tool Transfer), T1197 (BITS Jobs) |
| **Tactics** | Defense Evasion, Execution, Command & Control |
| **Data** | Process creation with command line and parent; network connections by process (Sysmon 3 / EDR); file creation (Sysmon 11) |
| **Time-box** | 3-5 hours |
| **Difficulty** | ★★☆ |

## Hypothesis

> *If an adversary is living off the land, trusted Windows binaries will be used in ways they rarely are legitimately: fetching remote content, executing scripts from the internet, loading DLLs from user-writable paths, or being invoked by Office/script hosts.*

Reference catalogue: [LOLBAS](https://lolbas-project.github.io/). Quick summary in our [LOLBin cheat sheet]({{ site.baseurl }}/cheatsheets/lolbins.pdf).

## Hunt steps

### 1. Certutil downloads and encoding

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName =~ "CertUtil.exe"      // catches renamed copies
| where ProcessCommandLine has_any ("-urlcache","-verifyctl","-encode","-decode","-split") 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### 2. Mshta, regsvr32, rundll32, wscript/cscript with remote or odd inputs

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http","https","javascript:","vbscript:"))
   or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("/i:http","scrobj.dll","/s /u"))
   or (FileName =~ "rundll32.exe" and ProcessCommandLine has_any ("javascript:","\\AppData\\","\\Temp\\","\\Users\\Public\\","comsvcs.dll"))
   or (FileName in~ ("wscript.exe","cscript.exe") and ProcessCommandLine has_any ("\\AppData\\","\\Temp\\","\\Downloads\\","http"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

`rundll32 ... comsvcs.dll, MiniDump` is also a credential-dumping method; see the [LSASS playbook]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/).

### 3. BITS jobs and other downloaders

```kql
DeviceProcessEvents
| where FileName in~ ("bitsadmin.exe") and ProcessCommandLine has_any ("/transfer","/addfile","/SetNotifyCmdLine")
   or (FileName in~ ("curl.exe","wget.exe") and ProcessCommandLine has_any ("-o ","--output","-O ") and ProcessCommandLine has "http")
```

### 4. Which signed binaries make outbound connections? (stack)

Many LOLBins should rarely touch the internet.

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d) and RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe",
                                       "msbuild.exe","installutil.exe","regasm.exe","regsvcs.exe","wmic.exe","cmstp.exe")
| summarize Conns = count(), Hosts = dcount(DeviceName), Dests = make_set(RemoteUrl, 10)
          by InitiatingProcessFileName
```

```spl
index=sysmon EventCode=3 Initiated=true NOT (DestinationIp=10.0.0.0/8 OR DestinationIp=172.16.0.0/12 OR DestinationIp=192.168.0.0/16)
  (Image="*\\mshta.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\certutil.exe" OR Image="*\\msbuild.exe")
| stats count dc(host) as hosts values(DestinationHostname) as dests by Image
```

### 5. Renamed / relocated system binaries (masquerading)

```kql
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName in~ ("CertUtil.exe","rundll32.exe","regsvr32.exe","mshta.exe","cmd.exe","powershell.exe")
| where FileName !~ ProcessVersionInfoOriginalFileName
   or not(FolderPath startswith @"c:\windows\system32" or FolderPath startswith @"c:\windows\syswow64")
```

## Triage

1. **Parent chain**: Office / browser / email client → LOLBin is the classic phishing pattern.
2. **Arguments**: remote URLs, paths in `AppData`/`Temp`/`Public`, script protocols.
3. **Network**: what did it contact? First seen? Reputation, newly registered domain?
4. **File writes**: what did it drop, and what executed it next? (Sysmon 11 → Sysmon 1)
5. **User/role fit**: does this user ever run these tools?

## Common false positives

- PKI admins using `certutil` for certificate operations
- Installers and legacy line-of-business apps using `regsvr32` / `rundll32` with local paths
- Developers using `msbuild` or `curl`

## Escalate when

A LOLBin retrieves remote content and a new executable/script then runs or persists, especially when the parent is Office, a browser or a script host.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1218.005` (mshta), `T1218.010` (regsvr32), `T1218.011` (rundll32), `T1140` (certutil), `T1197` (BITS).
- Detection: [CertUtil abuse]({{ site.baseurl }}/research/sigma/T1140-certutil-encode-lolbin.yml), [Mshta]({{ site.baseurl }}/research/sigma/T1218.005-mshta-remote-or-script.yml), [BITSAdmin]({{ site.baseurl }}/research/sigma/T1197-bitsadmin-transfer.yml)
- Hardening: WDAC/AppLocker block lists (Microsoft recommended block rules), ASR rules (block Office child processes, block executable content from email), egress filtering for server subnets.
