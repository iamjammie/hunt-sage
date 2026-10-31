---
title: "Playbook: Web Shells"
permalink: /hunt/playbooks/web-shells/
excerpt: "Find persistence and command execution via web servers: process lineage, new script files, and access-log anomalies."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1505.003 (Web Shell), T1190 (Exploit Public-Facing Application), T1059 |
| **Tactics** | Initial Access, Persistence |
| **Data** | EDR/Sysmon process creation and file creation on web servers; IIS/Apache/nginx access logs; WAF; Zeek `http` |
| **Time-box** | 3-5 hours |
| **Difficulty** | ★★☆ |

## Hypothesis

> *If an attacker has planted a web shell, the web server process (`w3wp.exe`, `httpd`, `nginx`, `java`, `php-fpm`) will spawn command interpreters or reconnaissance tools; new script files will appear in web roots outside deployment windows; and a small set of URLs will have unusual access patterns (few clients, POST-heavy, odd user agents).*

## Hunt steps

### 1. Web server process lineage (best signal)

Web servers rarely spawn shells.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","tomcat9.exe","java.exe","php-cgi.exe","php.exe","sqlservr.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","ipconfig.exe","systeminfo.exe",
                      "certutil.exe","bitsadmin.exe","nltest.exe","tasklist.exe","wmic.exe","curl.exe","wget.exe","arp.exe","netstat.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
```

```spl
index=sysmon EventCode=1 (ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\tomcat*.exe" OR ParentImage="*\\java.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\certutil.exe")
| table _time host ParentImage ParentCommandLine Image CommandLine User
```

On Linux: parent `apache2|httpd|nginx|php-fpm|java|tomcat` → child `sh|bash|dash|python|perl|nc|curl|wget|id|whoami` (auditd `execve` or eBPF-based EDR).

### 2. New or modified script files in web roots

```kql
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (@"\inetpub\wwwroot", @"\wwwroot\", @"\webapps\", @"\htdocs\", "/var/www/")
| where FileName endswith_cs ".aspx" or FileName endswith_cs ".ashx" or FileName endswith_cs ".asmx" or FileName endswith_cs ".jsp" or FileName endswith_cs ".jspx" or FileName endswith_cs ".php" or FileName endswith_cs ".cfm"
| where InitiatingProcessFileName !in~ ("msdeploy.exe","msbuild.exe","git.exe","w3wp.exe")   // exclude your deployment mechanism
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

Files created by the web server process itself (`w3wp.exe` writing `.aspx`) are suspicious in most apps (upload handlers excepted). Compare web roots to source control/deployment manifests: **any file not in the known-good build is a lead**.

```bash
# Linux: recently changed script files in web root
find /var/www -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' \) -mtime -14 -ls
# Common web shell string indicators (leads, not proof)
grep -RIlE 'eval\(\s*(base64_decode|gzinflate|\$_(POST|REQUEST|GET))|assert\(\s*\$_|system\(\s*\$_|passthru\(|shell_exec\(|Runtime\.getRuntime\(\)\.exec|Request\.Form\[|ProcessStartInfo' /var/www 2>/dev/null
```

### 3. Access log analytics (IIS/Apache/nginx)

Web shells are requested by few IPs, with consistent POSTs, for files that were not part of the application.

```kql
W3CIISLog
| where TimeGenerated > ago(14d) and csMethod == "POST" and scStatus == 200
| where csUriStem endswith ".aspx" or csUriStem endswith ".ashx"
| summarize Hits = count(), Clients = dcount(cIP), FirstSeen = min(TimeGenerated), UAs = dcount(csUserAgentHeader) by csUriStem
| where Clients <= 3 and Hits >= 5
| order by FirstSeen desc
```

```spl
index=web sourcetype=iis method=POST status=200 (uri_path="*.aspx" OR uri_path="*.ashx" OR uri_path="*.jsp" OR uri_path="*.php")
| stats count dc(clientip) as clients min(_time) as first max(_time) as last values(useragent) as ua by uri_path
| where clients<=3 AND count>=5
| convert ctime(first) ctime(last)
```

Stack rare URIs per server; check for URIs requested but absent from the application’s sitemap; look for parameters named `cmd`, `exec`, `c`, `pass`, `z0`; unusually long query strings; `application/x-www-form-urlencoded` base64 blobs; POSTs with 200 response to image/CSS-named files (`.jpg.aspx`).

### 4. Exploitation precursors

For edge/web CVEs, look in the days *before* the shell appears for exploit patterns: path traversal (`../`, `%2e%2e`), unusual `Content-Type`, deserialization gadgets, SSRF endpoints, `/autodiscover/` abuse (Exchange), template injection strings. Correlate by source IP.

## Triage

- Review file content (do not execute). Hash it; search fleet-wide.
- Which process lineage and which account? (IIS app pool identities are usually low-priv but may have modify rights or SeImpersonate → potato escalation.)
- What did the shell do next: discovery, credential theft, tunnel (reGeorg, Neo-reGeorg, chisel, ngrok), staging?
- Preserve: web root copy, access logs, memory if feasible, before cleanup.

## Common false positives

Admin panels and CMS plugins that legitimately write PHP; deployment pipelines; apps running scripted tasks via `cmd.exe`; monitoring scripts.

## Escalate when

Any interpreter/recon child of a web server not explained by the application, or an unexplained script file in a web root. **Treat the server as compromised** and review adjacent hosts reachable from it.

## Validate and operationalise

- Emulate with a benign test page that runs `whoami` under a lab IIS/Apache site (never expose the lab to the internet).
- Detection: [Web server spawning shell]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml)
- Hardening: read-only web roots and file-integrity monitoring; deny write/execute to app pool identities; WAF; patch edge services; segment DMZ from internal networks; egress filtering for web servers.
