---
title: "Hunting Query Index (KQL & SPL)"
permalink: /hunt/query-index/
excerpt: "The 29 most reusable hunting query patterns, each in KQL (Microsoft Sentinel / Defender) and SPL (Splunk) side by side: process, authentication, network, persistence, file and cloud patterns plus the building blocks they are made from."
toc: true
toc_sticky: true
---

Most hunts are built from a small number of query shapes. This page collects the ones that come up again and again, each written twice: KQL for Microsoft Sentinel and Defender advanced hunting, SPL for Splunk. Copy the shape, swap the table and the key, tune the thresholds.

**Field names vary by connector, add-on and parser version.** `TargetUserName` in Sentinel's `SecurityEvent` is `Account_Name` (often multivalue) in the Splunk Windows TA and `user` in CIM; `Image` in the Sysmon TA is `FolderPath` plus `FileName` in Defender. Every query here is a starting point that has to be checked against your schema and your allow-lists before you trust its silence. Thresholds (`Hosts <= 3`, `CoV < 0.35`, `Km > 500`) are deliberately conservative starting points: widen them when the long tail is empty, tighten them when it is a page long.

Syntax references: [KQL cheat sheet]({{ site.baseurl }}/cheatsheets/kql/) and [Splunk SPL cheat sheet]({{ site.baseurl }}/cheatsheets/splunk-spl/). The analytical reasoning behind each shape (search, stack, baseline, timing, sequence) is in [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/); the hypotheses they test are in the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/).

Assumed sources:

| Platform | Tables / indexes used here | Requires |
|---|---|---|
| Sentinel / Defender | `SecurityEvent`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, `DnsEvents`, `CommonSecurityLog`, `SigninLogs`, `AuditLogs`, `AWSCloudTrail` | Security Events connector with command line auditing; MDE integration; DNS Analytics; CEF proxy; Entra ID and AWS connectors |
| Splunk | `index=wineventlog` (Windows TA), `index=sysmon` (Sysmon TA), `index=proxy`, `index=dns` (Zeek), `index=zeek`, `index=azuread` (Microsoft Cloud Services add-on), `index=aws` (AWS add-on) | CIM-compliant TAs; URL Toolbox for entropy; `tstats` over the `Endpoint`, `Authentication` and `Web` data models where noted |

<div class="hs-filter" data-hs-filter="sections" data-placeholder="Filter query patterns: first-seen, beacon, stacking, 4624..."></div>

## Process & command line

### 1. Rare parent/child process pairs

Stack every (parent, child) pair across the fleet over 30 days and read the pairs seen on one or two hosts. Attack tooling almost always produces a pair the rest of the estate never makes.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| extend Parent = tolower(InitiatingProcessFileName), Child = tolower(FileName)
| summarize Hosts = dcount(DeviceName), Count = count(), FirstSeen = min(Timestamp),
            Example = any(ProcessCommandLine) by Parent, Child
| where Hosts <= 2
| order by Hosts asc, Count asc
```

```spl
index=sysmon EventCode=1 earliest=-30d
| rex field=ParentImage "(?<parent>[^\\\\]+)$"
| rex field=Image "(?<child>[^\\\\]+)$"
| eval parent=lower(parent), child=lower(child)
| stats dc(host) as hosts count min(_time) as first_seen values(CommandLine) as example by parent child
| where hosts<=2
| sort hosts count
```

Read `Example` before judging: `winword.exe → cmd.exe` on one host is a lead; `setup.exe → msiexec.exe` on one host is Tuesday.

### 2. Unusually long command lines

Obfuscation, embedded scripts and base64 blobs make command lines long. Length alone is a weak signal; length plus a non-developer host plus a scripting parent is a good one.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| extend CmdLen = strlen(ProcessCommandLine)
| where CmdLen > 1000
| summarize Count = count(), Hosts = dcount(DeviceName), MaxLen = max(CmdLen),
            Example = any(ProcessCommandLine) by FileName, InitiatingProcessFileName
| order by Hosts asc, MaxLen desc
```

```spl
index=sysmon EventCode=1 earliest=-7d
| eval cmdlen=len(CommandLine)
| where cmdlen>1000
| stats count dc(host) as hosts max(cmdlen) as maxlen values(CommandLine) as example by Image ParentImage
| sort hosts, -maxlen
```

### 3. Encoded PowerShell commands

Catches every abbreviation of `-EncodedCommand` and decodes the payload for triage. PowerShell encodes UTF-16LE, so the decoded string carries null bytes that have to be stripped.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe") or ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")
| extend Encoded = extract(@"(?i)\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| where isnotempty(Encoded)
| extend Decoded = replace_regex(base64_decode_tostring(Encoded), @"\x00", "")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, Decoded, ProcessCommandLine
| order by Timestamp desc
```

```spl
index=sysmon EventCode=1 earliest=-7d (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR OriginalFileName="PowerShell.EXE")
| rex field=CommandLine "(?i)\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+(?<b64>[A-Za-z0-9+/=]{20,})"
| where isnotnull(b64)
| table _time host User ParentImage b64 CommandLine
```

Splunk has no native base64 eval function; decode `b64` with the Decrypt or CyberChef app (`| decrypt field=b64 b64 emit('decoded')`) or offline. Pair with 4104 script block logs, which already hold the decoded script, via the [PowerShell abuse playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/).

### 4. LOLBin stacking

Living-off-the-land binaries are everywhere, so hunt the *arguments*, normalised so that GUIDs and numbers collapse, and keep only the argument shapes seen on a few hosts.

```kql
let lolbins = dynamic(["mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "msbuild.exe", "installutil.exe",
                       "regasm.exe", "regsvcs.exe", "cmstp.exe", "wmic.exe", "bitsadmin.exe", "msiexec.exe", "forfiles.exe", "mavinject.exe"]);
DeviceProcessEvents
| where Timestamp > ago(30d) and FileName in~ (lolbins)
| extend Normalised = replace_regex(tolower(ProcessCommandLine), @"[0-9a-f]{8}-[0-9a-f-]{27}|\d+", "N")
| summarize Hosts = dcount(DeviceName), Count = count(), Parents = make_set(InitiatingProcessFileName, 5),
            Example = any(ProcessCommandLine) by FileName, Normalised
| where Hosts <= 3
| order by FileName asc, Hosts asc
```

```spl
index=sysmon EventCode=1 earliest=-30d
  (Image="*\\mshta.exe" OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\certutil.exe" OR Image="*\\msbuild.exe"
   OR Image="*\\installutil.exe" OR Image="*\\regasm.exe" OR Image="*\\regsvcs.exe" OR Image="*\\cmstp.exe" OR Image="*\\wmic.exe"
   OR Image="*\\bitsadmin.exe" OR Image="*\\msiexec.exe" OR Image="*\\forfiles.exe" OR Image="*\\mavinject.exe")
| eval normalised=replace(lower(CommandLine),"[0-9a-f]{8}-[0-9a-f-]{27}|\d+","N")
| stats dc(host) as hosts count values(ParentImage) as parents values(CommandLine) as example by Image normalised
| where hosts<=3
| sort Image hosts
```

Match the names with `OriginalFileName` / `ProcessVersionInfoOriginalFileName` as well to catch renamed copies; see the [LOLBin playbook]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/).

### 5. Processes executing from unusual paths

User-writable and temporary locations are where droppers land. Stack by file name and hash; the allow-list grows fast (Teams, OneDrive, updaters), so keep it in a watchlist or lookup rather than in the query.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath matches regex @"(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)|Users\\Public|ProgramData|Windows\\Temp|PerfLogs|\$Recycle\.Bin)\\"
| where not(FolderPath has_any (@"\AppData\Local\Microsoft\Teams\", @"\AppData\Local\Microsoft\OneDrive\"))   // seed allow-list; move to a watchlist
| summarize Hosts = dcount(DeviceName), Count = count(), Company = make_set(ProcessVersionInfoCompanyName, 3),
            Paths = make_set(FolderPath, 3) by FileName, SHA256
| where Hosts <= 3
| order by Hosts asc
```

```spl
index=sysmon EventCode=1 earliest=-7d
  (Image="C:\\Users\\*\\AppData\\*" OR Image="C:\\Users\\*\\Downloads\\*" OR Image="C:\\Users\\*\\Desktop\\*" OR Image="C:\\Users\\Public\\*"
   OR Image="C:\\ProgramData\\*" OR Image="C:\\Windows\\Temp\\*" OR Image="C:\\PerfLogs\\*" OR Image="*\\$Recycle.Bin\\*")
  NOT Image="*\\AppData\\Local\\Microsoft\\Teams\\*" NOT Image="*\\AppData\\Local\\Microsoft\\OneDrive\\*"
| rex field=Image "(?<filename>[^\\\\]+)$"
| stats dc(host) as hosts count values(Company) as company values(Image) as paths by filename Hashes
| where hosts<=3
| sort hosts
```

The Sysmon TA's `Hashes` field is a single `SHA256=...,MD5=...` string; extract the one you want with `rex` if you need to pivot on it.

## Authentication

### 6. First-time logon of a user to a host

The single most useful lateral-movement query: (user, host) pairs that appear today and did not appear in the previous 30 days.

```kql
let lookback = 30d; let recent = 1d;
let known = SecurityEvent
| where TimeGenerated between (ago(lookback) .. ago(recent)) and EventID == 4624 and LogonType in (2, 3, 10)
| where not(TargetUserName endswith "$")
| distinct TargetUserName, Computer;
SecurityEvent
| where TimeGenerated > ago(recent) and EventID == 4624 and LogonType in (2, 3, 10)
| where not(TargetUserName endswith "$") and TargetUserName !in ("ANONYMOUS LOGON", "SYSTEM")
| join kind=leftanti known on TargetUserName, Computer
| summarize Logons = count(), Sources = make_set(IpAddress, 5), FirstSeen = min(TimeGenerated) by TargetUserName, Computer, LogonType
| order by Logons asc
```

```spl
index=wineventlog EventCode=4624 (Logon_Type=2 OR Logon_Type=3 OR Logon_Type=10) earliest=-30d
| eval Account_Name=mvindex(Account_Name,-1)
| search Account_Name!="*$" Account_Name!="ANONYMOUS LOGON" Account_Name!="SYSTEM"
| stats min(_time) as first_seen max(_time) as last_seen count values(Source_Network_Address) as sources by Account_Name ComputerName Logon_Type
| where first_seen>=relative_time(now(),"-1d")
| sort first_seen
```

In the Windows TA, 4624 carries two `Account_Name` values (subject and target); `mvindex(..., -1)` takes the target. Use `DeviceLogonEvents` with `AccountName, DeviceName` for the Defender equivalent. Full triage in the [lateral movement playbook]({{ site.baseurl }}/hunt/playbooks/lateral-movement/).

### 7. Logon type stacking per account

A pivot of logon types per account shows which accounts are interactive, which are service-like, and which just changed character.

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4624 and not(TargetUserName endswith "$")
| summarize Count = count() by TargetUserName, LogonType
| evaluate pivot(LogonType, sum(Count), TargetUserName)
```

```spl
index=wineventlog EventCode=4624 earliest=-30d
| eval Account_Name=mvindex(Account_Name,-1)
| search Account_Name!="*$"
| chart count over Account_Name by Logon_Type
| addtotals
| sort - Total
```

Columns are the logon types: 2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 new credentials (`runas /netonly`, pass-the-hash tools), 10 remote interactive, 11 cached. A `svc_` account with a value in column 10 is pattern 10 below.

### 8. Many distinct hosts per account in a short window

```kql
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624 and LogonType in (3, 10)
| where not(TargetUserName endswith "$") and TargetUserName != "ANONYMOUS LOGON"
| summarize Hosts = dcount(Computer), HostList = make_set(Computer, 20), Sources = dcount(IpAddress)
          by TargetUserName, bin(TimeGenerated, 1h)
| where Hosts >= 10
| order by Hosts desc
```

```spl
index=wineventlog EventCode=4624 (Logon_Type=3 OR Logon_Type=10) earliest=-24h
| eval Account_Name=mvindex(Account_Name,-1)
| search Account_Name!="*$" Account_Name!="ANONYMOUS LOGON"
| bin _time span=1h
| stats dc(ComputerName) as hosts values(ComputerName) as targets dc(Source_Network_Address) as sources by Account_Name _time
| where hosts>=10
| sort - hosts
```

Expect scanners, backup and monitoring accounts in the top rows; document them, then look at the human accounts that remain.

### 9. NTLM where Kerberos is expected

Domain accounts authenticating to domain-joined servers should use Kerberos. NTLM appears when the target is addressed by IP, when a tool injects a hash, or when a protocol downgrade is forced. NTLMv1 is a finding on its own.

```kql
SecurityEvent
| where TimeGenerated > ago(7d) and EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM" and not(TargetUserName endswith "$")
| where TargetUserName != "ANONYMOUS LOGON" and IpAddress !in ("-", "127.0.0.1", "::1")
| summarize Logons = count(), Hosts = dcount(Computer), HostList = make_set(Computer, 10), LmPackage = make_set(LmPackageName, 2)
          by TargetUserName, IpAddress, TargetDomainName
| order by Hosts desc
```

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM earliest=-7d
| eval Account_Name=mvindex(Account_Name,-1)
| search Account_Name!="*$" Account_Name!="ANONYMOUS LOGON" Source_Network_Address!="-" Source_Network_Address!="127.0.0.1"
| stats count dc(ComputerName) as hosts values(ComputerName) as host_list values(Package_Name__NTLM_only_) as lm_package by Account_Name Source_Network_Address
| sort - hosts
```

Narrow to domain accounts (`TargetDomainName` equals your domain) to exclude local-account NTLM, which is normal. Combine with pattern 8 for the pass-the-hash signature described in the [pass-the-hash blog post]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/).

### 10. Service account used interactively

Accounts whose 90-day history is exclusively service, batch or network logons, that produce an interactive (2), RDP (10) or cached (11) logon in the last day.

```kql
let svc = SecurityEvent
| where TimeGenerated between (ago(90d) .. ago(1d)) and EventID == 4624 and not(TargetUserName endswith "$")
| summarize Types = make_set(LogonType) by TargetUserName
| where (set_has_element(Types, 4) or set_has_element(Types, 5) or TargetUserName startswith "svc")
| where not(set_has_element(Types, 2)) and not(set_has_element(Types, 10)) and not(set_has_element(Types, 11))
| project TargetUserName;
SecurityEvent
| where TimeGenerated > ago(1d) and EventID == 4624 and LogonType in (2, 10, 11)
| where TargetUserName in (svc)
| project TimeGenerated, TargetUserName, Computer, LogonType, IpAddress, WorkstationName, LogonProcessName
```

```spl
index=wineventlog EventCode=4624 earliest=-90d
| eval Account_Name=mvindex(Account_Name,-1)
| search Account_Name!="*$"
| eval interactive=if(Logon_Type=2 OR Logon_Type=10 OR Logon_Type=11,1,0), service=if(Logon_Type=4 OR Logon_Type=5,1,0)
| eval recent_interactive=if(interactive=1 AND _time>=relative_time(now(),"-1d"),1,0)
| stats sum(interactive) as interactive_total sum(service) as service_total sum(recent_interactive) as recent_interactive
        values(eval(if(recent_interactive=1,ComputerName,null()))) as new_hosts by Account_Name
| where (service_total>0 OR like(Account_Name,"svc%")) AND recent_interactive>0 AND interactive_total=recent_interactive
```

## Network

### 11. Beaconing: interval and jitter analysis

Sort by source and destination, take the time gap to the previous connection, and look for low variance (coefficient of variation). Jitter raises the CoV, so run a second pass ranking by count with a looser CoV.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| extend PrevT = prev(Timestamp), PrevDev = prev(DeviceName), PrevIP = prev(RemoteIP)
| where PrevDev == DeviceName and PrevIP == RemoteIP
| extend Gap = datetime_diff('second', Timestamp, PrevT)
| summarize Conns = count(), AvgGap = avg(Gap), StdGap = stdev(Gap), Procs = make_set(InitiatingProcessFileName, 5), Url = any(RemoteUrl)
          by DeviceName, RemoteIP, RemotePort
| where Conns >= 30 and AvgGap between (10 .. 3600)
| extend CoV = StdGap / AvgGap
| where CoV < 0.35
| order by CoV asc
```

```spl
index=proxy earliest=-24h
| sort 0 src dest _time
| streamstats current=f last(_time) as prev by src dest
| eval gap=_time-prev
| stats count avg(gap) as avg_gap stdev(gap) as sd values(http_user_agent) as ua by src dest dest_port
| eval cov=sd/avg_gap
| where count>=30 AND avg_gap>=10 AND avg_gap<=3600 AND cov<0.35
| sort cov
```

`sort 0` removes Splunk's 10,000-row sort limit; on large indexes restrict to servers or a subnet first. Allow-list by (process, destination, interval), never by destination alone. Full workflow in the [C2 beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/).

### 12. Rare or new external destinations

Destinations contacted today by one or two hosts and by nobody in the previous 30 days.

```kql
let lookback = 30d; let recent = 1d;
let known = DeviceNetworkEvents
| where Timestamp between (ago(lookback) .. ago(recent)) and RemoteIPType == "Public"
| extend Dest = iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)
| distinct Dest;
DeviceNetworkEvents
| where Timestamp > ago(recent) and RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| extend Dest = iff(isempty(RemoteUrl), RemoteIP, RemoteUrl)
| join kind=leftanti known on Dest
| summarize Hosts = dcount(DeviceName), Conns = count(), Procs = make_set(InitiatingProcessFileName, 5),
            Ports = make_set(RemotePort, 5), FirstSeen = min(Timestamp) by Dest
| where Hosts <= 2
| order by Conns desc
```

```spl
index=proxy earliest=-30d
| eval period=if(_time>=relative_time(now(),"-1d"),"recent","baseline")
| stats count(eval(period="baseline")) as baseline count(eval(period="recent")) as recent dc(src) as hosts
        values(src) as host_list values(http_user_agent) as ua by dest
| where baseline=0 AND recent>0 AND hosts<=2
| sort - recent
```

For speed on large proxy indexes use `tstats` over the `Web` data model (`| tstats count dc(Web.src) as hosts from datamodel=Web where earliest=-30d by Web.dest _time span=1d`) and apply the same baseline/recent split.

### 13. Long-lived connections

Interactive tunnels and SOCKS proxies hold connections open for hours with balanced byte counts. EDR connection events carry no duration, so in Defender count the hours of the day in which a (host, destination) pair is active; in Zeek use `duration` directly.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| summarize HoursActive = dcount(bin(Timestamp, 1h)), Conns = count(), Procs = make_set(InitiatingProcessFileName, 3)
          by DeviceName, RemoteIP, RemotePort
| where HoursActive >= 20
| order by HoursActive desc, Conns asc
```

```spl
index=zeek sourcetype=zeek_conn earliest=-24h
| search NOT (id.resp_h=10.0.0.0/8 OR id.resp_h=172.16.0.0/12 OR id.resp_h=192.168.0.0/16)
| where duration>14400
| eval ratio=orig_bytes/(resp_bytes+1), mb_out=round(orig_bytes/1048576,1), mb_in=round(resp_bytes/1048576,1)
| table _time id.orig_h id.resp_h id.resp_p service duration mb_out mb_in ratio
| sort - duration
```

Few connections over many hours is the tunnel shape; hundreds of connections over many hours is a beacon or a sync client (pattern 11).

### 14. DNS: long subdomains and character entropy

Tunnelling and DGA labels are long and use many distinct characters. KQL has no entropy function; the ratio of distinct characters to label length is a usable stand-in. Splunk has `ut_shannon` from URL Toolbox.

```kql
DnsEvents
| where TimeGenerated > ago(1d) and SubType == "LookupQuery" and isnotempty(Name)
| extend Labels = split(Name, ".")
| where array_length(Labels) >= 3
| extend Parent = strcat_array(array_slice(Labels, -2, -1), "."), Sub = tostring(Labels[0])
| extend SubLen = strlen(Sub),
         UniqChars = array_length(set_union(extract_all(@"(.)", Sub), dynamic([]))),
         Digits = countof(Sub, @"\d", "regex")
| extend CharRatio = todouble(UniqChars) / SubLen
| summarize Queries = count(), UniqueSubs = dcount(Name), AvgSubLen = avg(SubLen), AvgCharRatio = avg(CharRatio),
            AvgDigits = avg(Digits), Types = make_set(QueryType, 5) by ClientIP, Parent
| where (UniqueSubs > 200 and AvgSubLen > 20) or (AvgSubLen > 40 and AvgCharRatio > 0.6)
| order by UniqueSubs desc
```

```spl
index=dns sourcetype=zeek_dns earliest=-24h
| eval list="mozilla"
| `ut_parse_extended(query, list)`
| `ut_shannon(ut_subdomain)`
| eval sublen=len(ut_subdomain)
| stats count dc(query) as uniq avg(sublen) as avg_sublen avg(ut_shannon) as avg_entropy values(qtype_name) as types by id.orig_h ut_domain
| where (uniq>200 AND avg_sublen>20) OR (avg_sublen>40 AND avg_entropy>3.5)
| sort - uniq
```

The two-label `Parent` split in KQL breaks on `co.uk`-style suffixes; URL Toolbox's `ut_domain` uses the public suffix list. Expect CDNs, anti-virus cloud lookups and some SaaS telemetry at the top; they are stable and can be allow-listed by parent.

### 15. Rare user agents

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d) and isnotempty(RequestClientApplication)
| summarize Hosts = dcount(SourceIP), Requests = count(), Dests = make_set(DestinationHostName, 5) by UserAgent = RequestClientApplication
| extend LibraryDefault = UserAgent matches regex @"(?i)^(python-requests|Go-http-client|curl|Wget|Java/|okhttp|libwww|PowerShell|WinHttp)"
| where Hosts <= 2 or LibraryDefault
| order by LibraryDefault desc, Requests desc
```

```spl
index=proxy earliest=-7d http_user_agent=*
| stats dc(src) as hosts count values(dest) as dests by http_user_agent
| eval library_default=if(match(http_user_agent,"(?i)^(python-requests|Go-http-client|curl|Wget|Java/|okhttp|libwww|PowerShell|WinHttp)"),1,0)
| where hosts<=2 OR library_default=1
| sort - library_default, - count
```

Rare does not mean bad (an engineer's `curl`), but a library default from a server that never scripts, going to a destination from pattern 12, does.

## Persistence

### 16. New services stacked by rarity

Defender records the `ImagePath` write under `HKLM\SYSTEM\CurrentControlSet\Services`; Splunk uses System log 7045. Normalise the image path and keep the ones seen on few hosts.

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d) and ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" and RegistryValueName == "ImagePath"
| extend Service = extract(@"\\Services\\([^\\]+)", 1, RegistryKey), Image = tolower(RegistryValueData)
| extend ImageNorm = replace_regex(Image, @"[0-9a-f]{8}-[0-9a-f-]{27}|\d+", "N")
| summarize Hosts = dcount(DeviceName), Count = count(), Services = make_set(Service, 5),
            Writers = make_set(InitiatingProcessFileName, 3), Example = any(Image) by ImageNorm
| where Hosts <= 3
| extend Suspicious = ImageNorm matches regex @"(appdata|\\temp\\|programdata|users\\public|powershell|cmd\.exe|rundll32|admin\$)"
| order by Suspicious desc, Hosts asc
```

```spl
index=wineventlog source="WinEventLog:System" EventCode=7045 earliest=-30d
| eval image_norm=replace(lower(Service_File_Name),"[0-9a-f]{8}-[0-9a-f-]{27}|\d+","N")
| stats dc(host) as hosts count values(Service_Name) as services values(Service_Account) as accounts values(Service_File_Name) as example by image_norm
| where hosts<=3
| eval suspicious=if(match(image_norm,"(appdata|\\\\temp\\\\|programdata|users\\\\public|powershell|cmd\.exe|rundll32|admin\$)"),1,0)
| sort - suspicious, hosts
```

Kernel drivers (`Service_Type` 1, `Type=kernel mode driver`) from odd paths are the BYOVD case; see the [persistence playbook]({{ site.baseurl }}/hunt/playbooks/persistence/).

### 17. Scheduled tasks stacked by action

Requires *Audit Other Object Access Events* for 4698. Stack on the task's command and arguments, not its name: names are random, actions repeat.

```kql
SecurityEvent
| where TimeGenerated > ago(30d) and EventID == 4698
| extend Command = extract(@"<Command>(.*?)</Command>", 1, TaskContent),
         Arguments = extract(@"<Arguments>(.*?)</Arguments>", 1, TaskContent)
| extend Action = tolower(strcat(Command, " ", Arguments))
| extend ActionNorm = replace_regex(Action, @"[0-9a-f]{8}-[0-9a-f-]{27}|\d+", "N")
| summarize Hosts = dcount(Computer), Count = count(), Tasks = make_set(TaskName, 5),
            Creators = make_set(SubjectUserName, 3), Example = any(Action) by ActionNorm
| where Hosts <= 3
| order by Hosts asc
```

```spl
index=wineventlog EventCode=4698 earliest=-30d
| rex field=Message "(?s)<Command>(?<cmd>.*?)</Command>\s*(<Arguments>(?<args>.*?)</Arguments>)?"
| eval action=lower(cmd." ".coalesce(args,""))
| eval action_norm=replace(action,"[0-9a-f]{8}-[0-9a-f-]{27}|\d+","N")
| stats dc(host) as hosts count values(Task_Name) as tasks values(Account_Name) as creators values(action) as example by action_norm
| where hosts<=3
| sort hosts
```

In Defender, `DeviceEvents | where ActionType == "ScheduledTaskCreated"` carries the task XML in `AdditionalFields` and needs no audit policy.

### 18. Run keys and logon-time registry persistence

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d) and ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Winlogon\Shell", @"\Winlogon\Userinit",
                            @"\CurrentVersion\Policies\Explorer\Run", @"\Image File Execution Options")
| extend Value = tolower(replace_regex(RegistryValueData, @"[0-9a-f]{8}-[0-9a-f-]{27}", "GUID"))
| summarize Hosts = dcount(DeviceName), Count = count(), Writers = make_set(InitiatingProcessFileName, 3),
            Keys = make_set(RegistryKey, 3) by RegistryValueName, Value
| where Hosts <= 3
| extend Suspicious = Value matches regex @"(appdata|\\temp\\|users\\public|powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32|https?:)"
| order by Suspicious desc, Hosts asc
```

```spl
index=sysmon EventCode=13 earliest=-30d
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Winlogon\\Shell" OR TargetObject="*\\Winlogon\\Userinit"
   OR TargetObject="*\\Policies\\Explorer\\Run*" OR TargetObject="*Image File Execution Options*")
| rex field=TargetObject "(?<value_name>[^\\\\]+)$"
| eval value=lower(replace(Details,"[0-9a-f]{8}-[0-9a-f-]{27}","GUID"))
| stats dc(host) as hosts count values(Image) as writers values(TargetObject) as keys by value_name value
| where hosts<=3
| eval suspicious=if(match(value,"(appdata|\\\\temp\\\\|users\\\\public|powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32|https?:)"),1,0)
| sort - suspicious, hosts
```

## Files

### 19. New executables in user-writable paths

```kql
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType in ("FileCreated", "FileRenamed")
| where FileName matches regex @"(?i)\.(exe|dll|scr|ps1|vbs|js|hta|bat|cmd|msi|cpl|sys)$"
| where FolderPath matches regex @"(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents|Pictures|Music|Videos)|Users\\Public|ProgramData|Windows\\Temp|PerfLogs|\$Recycle\.Bin)\\"
| where not(InitiatingProcessFileName in~ ("msiexec.exe", "OneDrive.exe", "Teams.exe", "MsMpEng.exe"))   // seed allow-list; tune
| summarize Hosts = dcount(DeviceName), Count = count(), Writers = make_set(InitiatingProcessFileName, 3),
            Paths = make_set(FolderPath, 3), FirstSeen = min(Timestamp) by FileName, SHA256
| where Hosts <= 3
| order by FirstSeen desc
```

```spl
index=sysmon EventCode=11 earliest=-7d
  (TargetFilename="C:\\Users\\*\\AppData\\*" OR TargetFilename="C:\\Users\\*\\Downloads\\*" OR TargetFilename="C:\\Users\\*\\Desktop\\*"
   OR TargetFilename="C:\\Users\\Public\\*" OR TargetFilename="C:\\ProgramData\\*" OR TargetFilename="C:\\Windows\\Temp\\*" OR TargetFilename="C:\\PerfLogs\\*")
  NOT Image="*\\msiexec.exe" NOT Image="*\\OneDrive.exe" NOT Image="*\\Teams.exe" NOT Image="*\\MsMpEng.exe"
| regex TargetFilename="(?i)\.(exe|dll|scr|ps1|vbs|js|hta|bat|cmd|msi|cpl|sys)$"
| rex field=TargetFilename "(?<filename>[^\\\\]+)$"
| stats dc(host) as hosts count values(Image) as writers values(TargetFilename) as paths min(_time) as first_seen by filename
| where hosts<=3
| sort - first_seen
```

Sysmon 11 has no hash; pivot the file name into Sysmon 1 (execution) or Sysmon 15 (pattern 20) to get one.

### 20. Mark-of-the-Web (Zone.Identifier) files that were executed

Files downloaded from the internet carry a `Zone.Identifier` alternate data stream. Defender exposes the origin as `FileOriginUrl`; Sysmon logs the stream creation as event 15. Joining to execution tells you what the user ran after downloading.

```kql
let motw = DeviceFileEvents
| where Timestamp > ago(7d) and isnotempty(FileOriginUrl)
| where FileName matches regex @"(?i)\.(exe|dll|iso|img|lnk|hta|js|vbs|ps1|msi|scr|cpl|zip|7z|rar)$"
| project FileCreated = Timestamp, DeviceName, FileName, FolderPath, SHA256, FileOriginUrl, FileOriginReferrerUrl, Downloader = InitiatingProcessFileName;
motw
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | project Executed = Timestamp, DeviceName, SHA256, ProcessCommandLine, InitiatingProcessFileName
  ) on DeviceName, SHA256
| where Executed between (FileCreated .. (FileCreated + 1d))
| project Executed, DeviceName, FileName, FolderPath, FileOriginUrl, Downloader, InitiatingProcessFileName, ProcessCommandLine
| order by Executed desc
```

```spl
index=sysmon EventCode=15 TargetFilename="*:Zone.Identifier" Contents="*ZoneId=3*" earliest=-7d
| rex field=Contents "HostUrl=(?<origin>\S+)"
| rex field=TargetFilename "^(?<file>.*):Zone\.Identifier$"
| regex file="(?i)\.(exe|dll|iso|img|lnk|hta|js|vbs|ps1|msi|scr|cpl|zip|7z|rar)$"
| stats values(origin) as origin values(Image) as downloader min(_time) as downloaded by host file
| join type=inner host file
    [ search index=sysmon EventCode=1 earliest=-7d | rename Image as file | stats min(_time) as executed values(CommandLine) as cmd by host file ]
| where executed>=downloaded
| sort - executed
| convert ctime(downloaded) ctime(executed)
```

The Splunk subsearch is capped at 50,000 rows by default; scope to a host group or shorten the window on busy estates. Archives (`zip`, `iso`, `img`) will not execute themselves, so also look for files created *inside* them (pattern 19 with the archive as the writer).

## Cloud & identity

### 21. Impossible travel (distance over time between sign-ins)

Consecutive successful sign-ins by one user from different IPs, more than 500 km apart, less than an hour apart. VPN egress points and mobile carriers produce false positives; a country-pair allow-list handles most of them.

```kql
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| extend Lat = toreal(LocationDetails.geoCoordinates.latitude), Lon = toreal(LocationDetails.geoCoordinates.longitude),
         Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Lat)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName), PrevLat = prev(Lat), PrevLon = prev(Lon), PrevTime = prev(TimeGenerated),
         PrevIP = prev(IPAddress), PrevCountry = prev(Country)
| where PrevUser == UserPrincipalName and IPAddress != PrevIP
| extend Km = geo_distance_2points(PrevLon, PrevLat, Lon, Lat) / 1000.0, Hours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0
| where Km > 500 and Hours < 1
| project TimeGenerated, UserPrincipalName, PrevIP, IPAddress, PrevCountry, Country, Km, Hours, AppDisplayName, ClientAppUsed
```

```spl
index=azuread sourcetype="azure:aad:signin" status.errorCode=0 earliest=-24h
| rename location.geoCoordinates.latitude as lat, location.geoCoordinates.longitude as lon, location.countryOrRegion as country
| where isnotnull(lat)
| sort 0 userPrincipalName _time
| streamstats current=f last(lat) as plat last(lon) as plon last(_time) as ptime last(ipAddress) as pip last(country) as pcountry by userPrincipalName
| eval dlat=(lat-plat)*pi()/180, dlon=(lon-plon)*pi()/180
| eval a=pow(sin(dlat/2),2)+cos(plat*pi()/180)*cos(lat*pi()/180)*pow(sin(dlon/2),2)
| eval km=6371*2*atan2(sqrt(a),sqrt(1-a)), hours=(_time-ptime)/3600
| where km>500 AND hours<1 AND ipAddress!=pip
| table _time userPrincipalName pip ipAddress pcountry country km hours appDisplayName
```

### 22. Sign-in from a country the user has never used

```kql
let known = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d)) and ResultType == "0"
| distinct UserPrincipalName, Location;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| join kind=leftanti known on UserPrincipalName, Location
| summarize SignIns = count(), IPs = make_set(IPAddress, 5), Apps = make_set(AppDisplayName, 5),
            CA = make_set(ConditionalAccessStatus, 2) by UserPrincipalName, Location
| order by SignIns asc
```

```spl
index=azuread sourcetype="azure:aad:signin" status.errorCode=0 earliest=-30d
| rename location.countryOrRegion as country
| eval period=if(_time>=relative_time(now(),"-1d"),"recent","baseline")
| stats count(eval(period="baseline")) as baseline count(eval(period="recent")) as recent values(ipAddress) as ips values(appDisplayName) as apps by userPrincipalName country
| where baseline=0 AND recent>0
| sort recent
```

Prioritise rows where the new country also lacks an MFA claim, uses a legacy or non-browser `ClientAppUsed`, or coincides with pattern 23 or 24 for the same user. The [cloud & identity playbook]({{ site.baseurl }}/hunt/playbooks/cloud-identity/) has the triage.

### 23. OAuth consent grants

Consent to an application that few users have consented to, or that asks for mailbox, file or directory scopes, is the illicit-consent-grant pattern.

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)
| mv-expand Prop = TargetResources[0].modifiedProperties
| where Prop.displayName in ("ConsentAction.Permissions", "DelegatedPermissionGrant.Scope")
| extend Permissions = tostring(Prop.newValue)
| summarize Consents = count(), Users = dcount(Actor), UserList = make_set(Actor, 5), Perms = make_set(Permissions, 5) by App
| where Users <= 2 or tostring(Perms) has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "offline_access", "MailboxSettings", "Directory.ReadWrite")
| order by Users asc
```

```spl
index=azuread sourcetype="azure:aad:audit" (operationName="Consent to application" OR operationName="Add delegated permission grant") earliest=-30d
| spath output=actor path=initiatedBy.user.userPrincipalName
| spath output=app path=targetResources{0}.displayName
| spath output=perms path=targetResources{0}.modifiedProperties{}.newValue
| stats count dc(actor) as users values(actor) as user_list values(perms) as perms by app
| where users<=2 OR match(perms,"Mail\.Read|Files\.ReadWrite\.All|offline_access|MailboxSettings|Directory\.ReadWrite")
| sort users
```

### 24. Privileged role assignments (Entra ID)

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add member to role", "Add eligible member to role", "Add scoped member to role", "Add member to role in PIM requested (permanent)")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| mv-expand Prop = TargetResources[0].modifiedProperties
| where Prop.displayName == "Role.DisplayName"
| extend Role = trim('"', tostring(Prop.newValue)), Target = tostring(TargetResources[0].userPrincipalName)
| where Role in ("Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
                 "Application Administrator", "Cloud Application Administrator", "Exchange Administrator", "Security Administrator")
| project TimeGenerated, Actor, Target, Role, OperationName, Result
| order by TimeGenerated desc
```

```spl
index=azuread sourcetype="azure:aad:audit" operationName="Add*member to role*" earliest=-30d
| spath output=actor path=initiatedBy.user.userPrincipalName
| spath output=target path=targetResources{0}.userPrincipalName
| spath output=props path=targetResources{0}.modifiedProperties{}
| mvexpand props
| spath input=props output=prop_name path=displayName
| spath input=props output=role path=newValue
| where prop_name="Role.DisplayName"
| eval role=trim(role,"\"")
| search role IN ("Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator","Application Administrator","Cloud Application Administrator","Exchange Administrator","Security Administrator")
| table _time actor target role operationName result
```

Baseline the `Actor` column against the previous 90 days: a provisioning service principal assigning roles daily is normal; a user account doing it once is the row to read.

### 25. Privilege grants and key creation (AWS CloudTrail)

Sensitive IAM calls made by a principal that has not made that call in the previous 30 days.

```kql
let lookback = 30d; let recent = 1d;
let sensitive = dynamic(["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "CreateAccessKey",
                         "CreateLoginProfile", "UpdateAssumeRolePolicy", "AddUserToGroup", "CreateUser", "CreateRole"]);
let baseline = AWSCloudTrail
| where TimeGenerated between (ago(lookback) .. ago(recent)) and EventName in (sensitive)
| distinct UserIdentityArn, EventName;
AWSCloudTrail
| where TimeGenerated > ago(recent) and EventName in (sensitive)
| join kind=leftanti baseline on UserIdentityArn, EventName
| extend Policy = tostring(parse_json(RequestParameters).policyArn), TargetUser = tostring(parse_json(RequestParameters).userName)
| project TimeGenerated, UserIdentityArn, UserIdentityType, EventName, SourceIpAddress, UserAgent, Policy, TargetUser, AWSRegion
| order by TimeGenerated desc
```

```spl
index=aws sourcetype="aws:cloudtrail" earliest=-30d
  eventName IN (AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, CreateAccessKey, CreateLoginProfile, UpdateAssumeRolePolicy, AddUserToGroup, CreateUser, CreateRole)
| eval period=if(_time>=relative_time(now(),"-1d"),"recent","baseline")
| stats count(eval(period="baseline")) as baseline count(eval(period="recent")) as recent values(sourceIPAddress) as src values(userAgent) as ua
        values(requestParameters.policyArn) as policy values(requestParameters.userName) as target_user by userIdentity.arn eventName
| where baseline=0 AND recent>0
| sort - recent
```

Add `StopLogging`, `DeleteTrail`, `PutEventSelectors` and `DeleteFlowLogs` to the list for the defence-evasion variant; any hit there is worth a phone call.

## Building blocks

The patterns above are compositions of four shapes. Learn these and you can write the rest on demand.

### 26. Rarity / stacking skeleton

Group by the thing you care about, count hosts, users and events, record first and last seen, and read from the bottom of the distribution.

```kql
// Swap the table, the window and the Key.
DeviceProcessEvents                                             // table
| where Timestamp > ago(30d)                                    // window
| extend Key = tolower(ProcessCommandLine)                      // the thing you are stacking
| summarize Hosts = dcount(DeviceName), Users = dcount(AccountName), Count = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Example = any(DeviceName) by Key
| extend Rarity = case(Hosts == 1 and Count <= 3, "very rare", Hosts <= 3, "rare", Hosts <= 10, "uncommon", "common")
| where Rarity != "common"
| order by Hosts asc, Count asc
```

```spl
index=sysmon EventCode=1 earliest=-30d
| eval key=lower(CommandLine)
| stats dc(host) as hosts dc(User) as users count min(_time) as first_seen max(_time) as last_seen values(host) as example by key
| eval rarity=case(hosts=1 AND count<=3,"very rare", hosts<=3,"rare", hosts<=10,"uncommon", true(),"common")
| where rarity!="common"
| sort hosts count
```

Normalise the key before stacking (lower-case, collapse GUIDs, numbers and user names to tokens) or every unique temp path becomes its own row. Rarity is relative to fleet size: on 200 hosts `Hosts <= 3` is 1.5 %; on 20,000 it is noise, so raise it.

### 27. Baseline comparison (last 30 days vs last day)

Two periods, one key, three outcomes: *new* (absent from baseline), *surge* (present but far above its daily average), *normal*.

```kql
let lookback = 30d; let recent = 1d;
let baseline = DeviceProcessEvents
| where Timestamp between (ago(lookback) .. ago(recent))
| summarize BaselineHosts = dcount(DeviceName), BaselineCount = count() by Key = tolower(FileName);
DeviceProcessEvents
| where Timestamp > ago(recent)
| summarize RecentHosts = dcount(DeviceName), RecentCount = count(), Example = any(FolderPath) by Key = tolower(FileName)
| join kind=leftouter baseline on Key
| extend BaselineHosts = coalesce(BaselineHosts, 0), BaselineCount = coalesce(BaselineCount, 0)
| extend Status = case(BaselineCount == 0, "new", RecentCount > 5 * BaselineCount / 29.0, "surge", "normal")
| where Status != "normal"
| project Key, Status, RecentHosts, RecentCount, BaselineHosts, BaselineCount, Example
| order by Status asc, RecentCount desc
```

```spl
index=sysmon EventCode=1 earliest=-30d
| rex field=Image "(?<key>[^\\\\]+)$"
| eval key=lower(key), period=if(_time>=relative_time(now(),"-1d"),"recent","baseline")
| stats dc(host) as hosts count by key period
| eval recent_count=if(period="recent",count,0), baseline_count=if(period="baseline",count,0),
       recent_hosts=if(period="recent",hosts,0), baseline_hosts=if(period="baseline",hosts,0)
| stats sum(recent_count) as recent_count sum(baseline_count) as baseline_count max(recent_hosts) as recent_hosts max(baseline_hosts) as baseline_hosts by key
| eval status=case(baseline_count=0 AND recent_count>0,"new", recent_count>5*baseline_count/29,"surge", true(),"normal")
| where status!="normal"
| sort status, -recent_count
```

Make the baseline longer than any business cycle you care about (month-end jobs need 35+ days) and store it as a summary table or lookup so the daily run is cheap.

### 28. First-seen pattern

The first occurrence of a key in the window, with the context of that first occurrence. `arg_min` returns the row with the minimum timestamp; in SPL `min(_time)` plus `earliest()` does the same.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| summarize arg_min(Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName),
            Hosts = dcount(DeviceName), Count = count() by SHA256, FileName
| where Timestamp > ago(1d)          // first appearance in the 30-day window was within the last day
| order by Timestamp desc
```

```spl
index=sysmon EventCode=1 earliest=-30d
| stats min(_time) as first_seen max(_time) as last_seen dc(host) as hosts count
        earliest(host) as first_host earliest(User) as first_user earliest(CommandLine) as first_cmd by Hashes Image
| where first_seen>=relative_time(now(),"-1d")
| sort - first_seen
| convert ctime(first_seen) ctime(last_seen)
```

First-seen is only meaningful when the window is longer than your retention of "normal": a 7-day window makes every fortnightly job look new.

### 29. Joining process to network

Which processes from suspicious paths made external connections, and to where. Join on device plus process identity; in Defender use the process ID *and* its creation time to survive PID reuse, in Sysmon use `ProcessGuid`, which events 1 and 3 share.

```kql
let suspicious = DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath has_any (@"\AppData\", @"\Temp\", @"\Downloads\", @"\Users\Public\")
| project ProcessCreationTime = Timestamp, DeviceId, DeviceName, ProcessId, FileName, ProcessCommandLine, SHA256;
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| project Timestamp, DeviceId, InitiatingProcessId, InitiatingProcessCreationTime, RemoteIP, RemotePort, RemoteUrl
| join kind=inner suspicious on DeviceId, $left.InitiatingProcessId == $right.ProcessId, $left.InitiatingProcessCreationTime == $right.ProcessCreationTime
| summarize Conns = count(), Dests = make_set(strcat(RemoteIP, ":", RemotePort), 10), Urls = make_set(RemoteUrl, 5)
          by DeviceName, FileName, ProcessCommandLine, SHA256, ProcessCreationTime
| order by Conns desc
```

```spl
index=sysmon (EventCode=1 OR EventCode=3) earliest=-24h
| stats values(eval(if(EventCode=1,Image,null()))) as image values(eval(if(EventCode=1,CommandLine,null()))) as cmd
        values(eval(if(EventCode=3,DestinationIp.":".DestinationPort,null()))) as dests dc(eval(if(EventCode=3,DestinationIp,null()))) as dest_count
        by host ProcessGuid
| where isnotnull(image) AND dest_count>0
| regex image="(?i)\\\\(AppData|Temp|Downloads|Users\\\\Public)\\\\"
| sort - dest_count
```

The `stats ... by ProcessGuid` form avoids `join` and its subsearch limits; it is the idiom to reach for whenever two Sysmon event types share a key. The same shape links Sysmon 1 to 11 (what did the process write), 1 to 10 (what did it open) and 1 to 13 (what did it persist).

## Using the index

- Start every hunt from the [hypothesis]({{ site.baseurl }}/hunt/hypotheses/), pick the pattern that tests it, then open the playbook for the triage and false-positive notes.
- Save tuned versions as functions (KQL) or macros (SPL) with your allow-lists baked in, and version them with the hunt report.
- A query that returns nothing proves nothing until you have confirmed the table is populated for the hosts in scope (see the coverage checks in [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/)).

See also: [Hunt playbooks]({{ site.baseurl }}/hunt/), [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/), [Sigma rules]({{ site.baseurl }}/research/sigma/).
