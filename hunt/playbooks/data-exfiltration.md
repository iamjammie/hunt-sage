---
title: "Playbook: Data Exfiltration"
permalink: /hunt/playbooks/data-exfiltration/
excerpt: "Staging, archiving and egress: rclone/MEGA/WinSCP, cloud-storage uploads, unusual volume and protocol abuse."
tactic: "Exfiltration"
attack: [T1074, T1560, T1041, T1048, T1567.002, T1537, T1020]
difficulty: 3
timebox: "1-2 days"
data: [edr, proxy, firewall, dns, zeek]
---

{% include playbook-meta.html %}

**Data used:** EDR process/file/network; proxy logs with bytes-out; firewall/NetFlow; DNS; cloud storage access logs; DLP

## Hypothesis

> *Before exfiltrating, adversaries stage and compress data on a staging host and then push it out via an encrypted channel, often to a cloud storage service or via a purpose-built sync tool. We'd see (1) archives created in unusual places, (2) tools like rclone/WinSCP/MEGAsync, and (3) outbound byte counts far above the host's baseline.*

## Hunt steps

### 1. Archiving and staging

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("7z.exe","7za.exe","rar.exe","winrar.exe","zip.exe") 
         and ProcessCommandLine has_any (" a ","-p","-hp","-v"))                 // add / password / split volumes
   or (FileName =~ "tar.exe" and ProcessCommandLine has " -c")
   or ProcessCommandLine has_any ("Compress-Archive","System.IO.Compression.ZipFile")
| where ProcessCommandLine has_any ("\\Users\\","\\Share","\\\\","\\ProgramData\\","\\Temp\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

Large archives in `C:\ProgramData`, `C:\Windows\Temp`, `C:\Users\Public`, `$Recycle.Bin` or on servers is high-signal. Find big new files:

```kql
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType == "FileCreated"
| where FileName endswith_cs ".zip" or FileName endswith_cs ".7z" or FileName endswith_cs ".rar" or FileName endswith_cs ".tar" or FileName endswith_cs ".gz"
| where FolderPath has_any (@"\ProgramData\", @"\Temp\", @"\Users\Public\", @"\$Recycle.Bin\")
```

### 2. Exfil tools

```kql
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName in~ ("rclone.exe","MEGAsync.exe","megacmd.exe","WinSCP.com","winscp.exe","pscp.exe","plink.exe","curl.exe","FileZilla.exe")
   or ProcessCommandLine has_any ("rclone","--transfers","--multi-thread-streams","mega.nz","anonfiles","transfer.sh","ftp -s:","scp ","sftp ")
| where ProcessCommandLine has_any ("copy","sync","move","put","upload","-T","--upload-file","mega","s3:","sftp:","webdav")
```

Rclone often runs with `--config` pointing to a temp file, and flags like `--no-check-certificate`, `--ignore-existing`, `--auto-confirm`, and remote types `mega:`, `s3:`, `sftp:`, `webdav:`.

### 3. Cloud storage destinations

Stack proxy or DNS logs for rarely-seen-in-business storage domains (consumer MEGA, file.io, transfer.sh, anonfiles clones, pastebin-likes, personal OneDrive/Dropbox/Google Drive on managed devices, Telegram/Discord webhooks).

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d) and DeviceAction in ("Allow","allowed","Permit")
| where DestinationHostName has_any ("mega.nz","mega.io","anonfiles","file.io","transfer.sh","temp.sh","gofile.io","pastebin.com","discord.com/api/webhooks","api.telegram.org")
| summarize Hits = count(), BytesOut = sum(SentBytes) by SourceIP, DestinationHostName
| order by BytesOut desc
```

(Field names vary by firewall/proxy CEF mapping.)

### 4. Volume anomalies (baseline-and-outlier)

```kql
// Daily bytes sent to public IPs per host; flag > mean + 3*stddev of that host's history
let daily = CommonSecurityLog
  | where TimeGenerated > ago(45d) and ipv4_is_private(DestinationIP) == false
  | summarize BytesOut = sum(SentBytes) by SourceIP, Day = bin(TimeGenerated, 1d);
daily
| summarize Mean = avg(BytesOut), Std = stdev(BytesOut), Last = arg_max(Day, BytesOut) by SourceIP
| extend Z = (Last_BytesOut - Mean) / Std
| where Z > 3 and Last_BytesOut > 500000000        // > ~500 MB
```

```spl
index=firewall action=allowed NOT dest_ip=10.0.0.0/8 NOT dest_ip=172.16.0.0/12 NOT dest_ip=192.168.0.0/16
| bin _time span=1d
| stats sum(bytes_out) as out by src_ip _time
| eventstats avg(out) as mu stdev(out) as sigma by src_ip
| where out > mu+3*sigma AND out > 500000000
```

### 5. Protocol misuse

- **DNS**: see [C2 / DNS tunneling]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/)
- **ICMP**: payload size/rate anomalies (large echo packets)
- **FTP/SFTP/SSH/SCP** from servers that never initiate them
- **SMTP/webmail** with large attachments from unusual senders; mailbox rules that forward externally (T1114.003), see [cloud playbook]({{ site.baseurl }}/hunt/playbooks/cloud-identity/)

### 6. Cloud-side exfil (T1537, T1530)

Bucket policy or ACL changes making data public, cross-account snapshot sharing (EBS/RDS), new external SAS tokens, mass `GetObject` / `Download` by one principal. Details in [Cloud & identity]({{ site.baseurl }}/hunt/playbooks/cloud-identity/).

### 7. Automated exfiltration (T1020)

Hands-off exfil looks like a machine, not a person: the same host pushes a similar byte volume to the same destination at a regular interval, uploads fire seconds after a burst of file modifications, or a scheduled task / cron job carries `curl`, `rclone`, `aws s3 cp`, `scp` or `Invoke-WebRequest -Method Post` in its command line.

```kql
// Regular, same-size transfers to one external destination: low variance in interval and bytes
CommonSecurityLog
| where TimeGenerated > ago(14d) and ipv4_is_private(DestinationIP) == false and SentBytes > 1000000
| order by SourceIP, DestinationIP, TimeGenerated asc
| extend Gap = datetime_diff("minute", TimeGenerated, prev(TimeGenerated)), SamePair = SourceIP == prev(SourceIP) and DestinationIP == prev(DestinationIP)
| where SamePair
| summarize Transfers = count(), AvgGap = avg(Gap), GapStd = stdev(Gap), AvgBytes = avg(SentBytes), BytesStd = stdev(SentBytes) by SourceIP, DestinationIP
| where Transfers >= 7 and GapStd < AvgGap * 0.15 and BytesStd < AvgBytes * 0.25
```

```spl
index=edr (sourcetype="XmlWinEventLog:Security" EventCode=4698) OR (sourcetype=linux_cron OR source="/var/log/cron")
| rex field=_raw "(?i)(?<cmd>(curl|rclone|aws s3 cp|aws s3 sync|scp |sftp |Invoke-WebRequest|Invoke-RestMethod)[^\"<]{0,200})"
| where isnotnull(cmd)
| stats count values(cmd) as cmds earliest(_time) as first by host user
```

Join a hit with the volume step above: a scheduled job plus a regular upload cadence from the same host is automated exfil until proven to be a backup, and backups have change tickets.

## Triage

| Question | Why |
|---|---|
| What data was in the archive/path? | Sensitivity drives severity |
| Where did it go (domain, ASN, account)? | Attacker infra vs. approved SaaS |
| Who and what process? | User-driven vs. tool-driven |
| Time relative to credential theft / lateral movement? | Confirms campaign context |
| Was there a prior large read from file shares? | The collection step |

## Common false positives

Backups and cloud sync clients, software distribution, developer uploads, authorised use of approved SaaS. Allow-list by **tool + destination + account**.

## Escalate when

Archives with sensitive content are created on a server and uploaded to a non-approved destination, or sync tools are present on hosts where they have no business purpose. Preserve proxy/flow logs immediately and notify legal/privacy leads per your breach process.

## Validate and operationalise

- Emulate: `Invoke-AtomicTest T1560.001`, `T1048`, `T1567.002` using test endpoints you control.
- Detection: [rclone usage]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml)
- Hardening: egress allow-listing, DLP on endpoints/email/web, block unsanctioned cloud storage at proxy, restrict `rclone`/`MEGAsync` via WDAC/AppLocker, enforce egress byte-count alerts for servers.

{% include playbook-footer.html %}
