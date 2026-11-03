---
title: "Hunt Pack: Linux Server Intrusion"
permalink: /hunt/packs/linux-server-intrusion/
excerpt: "From exposed SSH or a vulnerable web app to reverse shell, persistence, cryptomining or staging, SSH pivoting and log tampering, with a Kubernetes branch for pod footholds."
classes: wide
toc: true
toc_sticky: true
pack: true
playbooks: [linux-hunting, web-shells, c2-beaconing, data-exfiltration, kubernetes-containers]
attack: [T1190, T1110.001, T1021.004, T1059.004, T1505.003, T1548.003, T1552.001, T1053.003, T1543.002, T1098.004, T1496, T1074.001, T1048, T1070.002, T1070.003, T1609, T1611]
duration: "1 week, 1-2 analysts with auditd/EDR and Zeek access; add a day for the Kubernetes branch"
---

{% include pack-meta.html %}

The attacker finds a Linux server that faces the internet: SSH with password authentication still enabled on a forgotten jump box, or a web application with an unpatched deserialisation bug. Brute force or exploitation gives a shell as the service account; a one-liner reverse shell calls back to a VPS on a high port. Within the hour the attacker runs `id`, `sudo -l`, `cat /etc/passwd`, reads application configs and `.bash_history` for credentials, and finds a mis-set `sudo` rule or a readable private key. Persistence follows: a public key appended to `authorized_keys`, a cron entry fetching a script from the VPS, or a `systemd` unit pretending to be a logging agent. Depending on the actor, the host either starts mining cryptocurrency at 100 % CPU or becomes a staging point where database dumps are archived in `/dev/shm` and pushed out over SSH or HTTPS. The harvested keys open SSH sessions to neighbouring hosts. Before leaving, the attacker clears `~/.bash_history`, truncates `wtmp` and stops auditd. Where the foothold is a container, the same story starts with `kubectl exec` or a vulnerable pod, pivots through the service-account token to the API server, and attempts a privileged pod for host escape.

Run this pack after a critical vulnerability in an internet-facing Linux service, when a cryptomining or outbound-scanning alert hits a server, when a cloud provider sends an abuse notice, or quarterly across the DMZ, build infrastructure and Kubernetes clusters. It is also the right assurance exercise after a key-based SSH rollout or an auditd deployment, to prove the new telemetry actually shows the behaviours below.

## Scoping checklist

- An inventory of internet-facing Linux services (from the firewall's NAT and the cloud provider's public IPs, not from the CMDB alone), with owner and patch level.
- Which hosts have auditd or EDR, which have only Zeek or flow logs, and which have nothing; record it on the [data source assessment]({{ site.baseurl }}/templates/#data-source-assessment) and treat the last group as findings.
- The configuration-management agent and build pipeline identities, so their writes to cron, systemd and `authorized_keys` can be excluded on day 2.
- The server segment's egress policy and known external destinations (package mirrors, update services, SaaS APIs) for the day-3 baselines.
- For the Kubernetes branch: which clusters, which namespaces are production, and which identities are allowed to `exec`.
- Each hypothesis to be tested written on a [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card) with its H-id.

## Kill chain at a glance

| Phase | Adversary action | ATT&CK | What you would see (telemetry) | Hypotheses | Playbook |
|---|---|---|---|---|---|
| 1. Initial access | SSH password brute force; exploitation of an exposed web application | T1110.001, T1190 | `sshd` failures for many usernames from one source then an accept (`auth.log`, journald, 4625-equivalents in EDR); web worker (`httpd`, `nginx`, `tomcat`, `java`, `node`) spawning `sh`, `bash`, `whoami`, `id` | H-003, H-004, H-101 | [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) step 1, [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 2 |
| 2. Execution and callback | Reverse shell or dropper: `bash -i >& /dev/tcp/...`, `nc -e`, `python -c 'import pty'`, `curl` piped to `sh` | T1059.004, T1105 | auditd `EXECVE` with those arguments; shell whose parent is a web server, database or `cron`; new outbound connection to a high port from a server that normally only answers | H-096, H-099 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 1 |
| 3. Discovery and privilege escalation | `sudo -l`, `uname -a`, `cat /etc/passwd`, reading configs and histories; SUID abuse or sudo misconfiguration | T1548.003, T1552.001, T1082 | Bursts of recon commands in one session; `sudo` by `www-data`, `tomcat`, `postgres`; SUID binaries created or modified outside package transactions; reads of `.env`, `wp-config.php`, `.aws/credentials`, `id_rsa` | H-097, H-052 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 5 |
| 4. Persistence | `authorized_keys` append, cron entry, `systemd` unit, `rc.local`, profile script, `ld.so.preload` | T1098.004, T1053.003, T1543.002, T1574.006 | auditd `PATH` records for writes to `~/.ssh/authorized_keys`, `/etc/cron.*`, `/var/spool/cron`, `/etc/systemd/system`, `/etc/ld.so.preload` by a process other than the configuration-management agent; unit or cron commands containing `curl`, `wget`, `base64 -d`, `/tmp`, `/dev/shm` | H-094, H-095, H-098 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 3 |
| 5a. Impact: cryptomining | Miner dropped to `/tmp` or `/dev/shm`, pinned CPU, Stratum or pool connections | T1496 | Process from a writable path with sustained CPU; outbound connections to pool ports (3333, 4444, 5555, 7777, 14444) or domains with `pool`, `xmr`, `monero`; `nice`/`renice`, `ulimit` changes, kills of competing miners | H-099, H-070 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 6, [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) step 2 |
| 5b. Impact: staging and exfil | `mysqldump`, `pg_dump`, `tar czf` into `/dev/shm` or `/var/tmp`; `scp`, `curl -T`, `rclone` out | T1074.001, T1560.001, T1048 | Dump and archive commands by service accounts; archives over 200 MB in writable paths; outbound SSH/HTTPS from a server whose egress baseline is near zero, bytes-out far exceeding bytes-in | H-064, H-078 | [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 1 and 5 |
| 6. Command and control | Beacon from the implant or a SOCKS tunnel (`ssh -R`, `chisel`, `socat`) | T1071.001, T1572 | Regular-interval connections to one external destination; long-lived balanced sessions; Zeek `conn.log` service `ssh` to a public IP from a server | H-069, H-073 | [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) step 1 and 6 |
| 7. Lateral movement | SSH to neighbours with harvested keys or reused passwords | T1021.004 | One host opening SSH to more than ten internal hosts in an hour; accepted logons for accounts from a source IP never seen for that host; `ssh-agent` forwarding chains | H-101, H-057 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 2 |
| 8. Defense evasion | History clearing, log truncation, auditd stopped, timestomping | T1070.002, T1070.003, T1562.012 | `history -c`, `unset HISTFILE`, `HISTSIZE=0`; truncation of `auth.log`, `wtmp`, `btmp`, `lastlog`; `auditctl -e 0`, `systemctl stop auditd`; `touch -r` on dropped files | H-100 | [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 4 |
| K. Kubernetes branch | `kubectl exec` into a pod, service-account token read, API enumeration, privileged pod for host escape | T1609, T1552.007, T1613, T1611 | Audit log `pods/exec` from a non-CI identity; `secrets` list bursts; `create` of pods with `privileged`, `hostPID` or `hostPath`; shell spawned inside a container that does not normally run one | H-096, H-099 | [Kubernetes & containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/) |

## Telemetry you need before you start

Check that each source exists for every server in scope and for the full window; servers added outside the build pipeline are exactly the ones that lack auditd. See [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/).

**Must-have**

- `linux-auditd` (or an EDR with equivalent coverage): `EXECVE` with full arguments, `PATH` records for writes to `/etc`, `~/.ssh`, cron and systemd paths, `USER_AUTH`/`USER_LOGIN`, and `SYSCALL` for `init_module`/`finit_module`; auditd rules at least as broad as the starter set in the [Linux logs & auditd cheat sheet]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/). Plus `auth.log`/`secure` or journald `sshd` entries with source IP, username and method (password vs publickey).
- `edr` on servers: process creation with parent lineage, file events for writable paths, process network events (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents` on Defender for Endpoint for Linux; equivalent tables elsewhere).
- `zeek` or firewall flow logs at the DMZ and server-segment boundaries: `conn.log` (duration, bytes, service), `ssh.log`, `http.log`, `dns.log`, so callbacks, tunnels and SSH fan-out are visible even on hosts with no agent.
- Web server access and error logs (`iis` key covers Apache/nginx/Tomcat here) with full request URI, status and user agent, for the exploitation precursors.

**Nice-to-have**

- File integrity monitoring on `/etc`, `/usr/bin`, `/usr/sbin`, web roots and `~/.ssh` for every account.
- Package-manager logs (`dpkg.log`, `yum.log`/`dnf` history) to separate legitimate SUID and binary changes from attacker drops.
- Host metrics (CPU per process) to corroborate cryptomining without relying on network indicators.
- `kubernetes-audit`: API server audit logs at `RequestResponse` level for `pods/exec`, `secrets`, `clusterrolebindings` and pod creation; container runtime or Falco-style syscall alerts for shells inside containers.
- Cloud control-plane logs (`aws-cloudtrail`, Azure Activity) for IMDS credential use from a compromised instance.

## Five-day hunt plan

| Day | Focus | Steps | Output |
|---|---|---|---|
| 1 | Perimeter and execution | Inventory internet-facing Linux services (SSH, web, VPN, database ports) and confirm telemetry per host. [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) step 1 (web worker spawning shells) and step 4 (exploitation precursors in access logs). [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) step 1 (reverse-shell indicators, interpreters with unusual parents) and step 2 (SSH failure bursts then success; password logons where keys are policy). Stack parent/child pairs across the server fleet. | Hosts with shell-from-service lineage; SSH sources with spray-then-success; a list of hosts missing auditd or EDR |
| 2 | Privilege escalation and persistence | Step 5 (`sudo` by service accounts, SUID changes outside package transactions, credential-file reads); step 3 (`authorized_keys` writes by non-CM processes, cron and systemd units with download or writable-path commands, `ld.so.preload`). Baseline every unit and cron entry against the fleet: anything present on fewer than three hosts gets read. | Persistence inventory per host with first-seen dates; privileged service-account activity to explain |
| 3 | Impact and command and control | Step 6 and [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) step 1, 2 and 6 for the server segment: processes from writable paths with sustained CPU; outbound connections to pool ports or new external destinations contacted by one server; regular-interval connections; long balanced sessions (tunnels). [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) step 1 and 5: dump and archive commands, archives in `/dev/shm` or `/var/tmp`, outbound SSH/HTTPS from servers with near-zero egress baselines. | Miner or staging candidates; external destinations and intervals to block or investigate |
| 4 | Lateral movement, evasion, Kubernetes branch | Step 2 again for SSH fan-out (hosts opening SSH to more than ten peers; first-seen source-to-host pairs); step 4 for history clearing, log truncation and auditd stops, correlated with the day-1 to day-3 timelines. If clusters are in scope, [Kubernetes & containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/): `pods/exec` by non-CI identities, secrets bursts, privileged or hostPath pod creation, shells spawned in containers. | Pivot graph (which host reached which); evasion events tied to sessions; cluster findings |
| 5 | Report, detect, backlog | Write the [hunt report]({{ site.baseurl }}/templates/#hunt-report); hand compromised hosts to IR with the [IR hand-off package]({{ site.baseurl }}/templates/#handoff-package-to-ir) and preserved `/dev/shm`, cron, unit and key artefacts; promote the reverse-shell, `authorized_keys`, cron-with-download and SSH fan-out queries to detections; record which hosts lack auditd and which cron or unit entries are benign fleet-wide. | Report, detections in test, allow-list of benign units and cron entries, telemetry backlog |

## Pivot map

- If you find a web worker spawning a shell → pull that worker's file writes in the previous hour (web shell drop, [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/) step 2), then every child process and outbound connection of the shell's session.
- If you find a reverse-shell command line → look up the destination in Zeek `conn.log` across the fleet (which other hosts talk to it), then check cron, systemd and `authorized_keys` writes on the same host in the following 24 hours.
- If you find an `authorized_keys` write by a non-CM process → extract the key comment and fingerprint, search `sshd` accepts for that fingerprint on every host, and treat matches as the lateral-movement graph.
- If you find a cron or unit entry fetching from a URL → fetch nothing yourself; record the domain or IP, search DNS and proxy logs for other resolvers of it, and check whether the fetched path exists in `/tmp` or `/dev/shm` on the host.
- If you find a miner → check how it arrived (phase 1 or 2) rather than stopping at the process; miners are often the second tenant on a host sold on after initial access.
- If you find archives in `/dev/shm` or `/var/tmp` → identify the dump command that produced them and the database or path they came from, then look for outbound transfers of similar size in the following hours.
- If you find SSH fan-out from one host → that host is a pivot: run the full day-1 to day-3 sequence on it, and on the first three destinations with accepted logons.
- If you find `auditctl -e 0` or truncated `wtmp` → the host's own logs are unreliable from that time; rebuild the timeline from Zeek, the SSH logs of neighbouring hosts and the EDR cloud copy.
- If you find `pods/exec` into a production pod by a human identity → check the service-account token that pod holds, API calls made with it afterwards (`secrets`, `pods` create), and whether a privileged pod appeared on the same node.
- If a cluster shows a privileged or hostPath pod created → the node is in scope as a Linux host: run phase 3 and 4 against it, and check IMDS credential use from the node in cloud logs.

## Detections to confirm are live

Confirm each rule is deployed on the server fleet (many Sigma deployments cover workstations only) and firing in the lab.

**Initial access and execution**
- [Web Server Process Spawning Shell or Recon Tool]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml)
- [Linux Reverse Shell Command Line]({{ site.baseurl }}/research/sigma/T1059.004-linux-reverse-shell.yml)

**Kubernetes branch**
- [Kubernetes Exec into Container]({{ site.baseurl }}/research/sigma/T1609-kubernetes-exec-into-container.yml)
- [Privileged or hostPath Pod Created]({{ site.baseurl }}/research/sigma/T1611-privileged-or-hostpath-pod-created.yml)

**Exfiltration**
- [Rclone Usage Consistent with Data Exfiltration]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml) (rclone is as common on Linux staging hosts as on Windows)

Persistence (`authorized_keys`, cron and systemd writes), SSH fan-out, miner and tunnel signals are delivered by auditd and flow analytics; the KQL and SPL in the [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/) and [C2 beaconing]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) playbooks are the scheduled-search starting points. Record in the report which of them are running.

## What good looks like

- Every internet-facing Linux host is in the inventory with its auditd/EDR and flow coverage confirmed; hosts without coverage are listed as findings.
- Shell-from-service lineage, reverse-shell indicators and spray-then-success SSH logons have been triaged for the window, with each remaining case explained or escalated.
- A fleet-wide inventory of cron entries, `systemd` units, `authorized_keys` and `ld.so.preload` exists with first-seen dates; rare entries have been read and classified.
- Service accounts using `sudo` and SUID changes outside package transactions are explained or escalated.
- Server egress baselines exist (destinations, bytes, intervals), and the outliers have been resolved.
- For clusters: `pods/exec` by human identities, privileged pod creation and secrets bursts are inventoried and explained.
- Reverse-shell, `authorized_keys`, cron-with-download and SSH fan-out detections are running against the server fleet with documented false positives.
- Compromised hosts went to IR with volatile artefacts (`/dev/shm`, process list, network table) preserved before rebuild.

## Tabletop prompts

1. A cloud provider reports outbound scanning from one of our web servers. The host has no EDR and auditd was never installed. What can you establish from the network and from neighbouring hosts, and in what order?
2. `authorized_keys` on a database server contains a key nobody recognises. How do you find every host that key has ever opened, and what do you do before removing it?
3. A cron entry downloads and runs a script from an IP every ten minutes. Why should you not fetch the script yourself, and what do you collect instead?
4. CPU on three build agents is pinned by a process in `/tmp`. Is this the incident or the symptom, and which phase do you go back to?
5. A developer ran `kubectl exec` into a production pod to "check a config". What telemetry distinguishes that from an attacker with a stolen kubeconfig, and what policy change would remove the ambiguity?

## Hardening that shortens the next hunt

1. Key-only SSH with password authentication disabled, `PermitRootLogin no`, SSH behind a bastion or VPN; this removes phase 1a and makes every password logon a finding.
2. Auditd (or EDR) on every Linux host as part of the build image, with the rule set covering `EXECVE`, key and cron paths, module loads and auditd configuration changes; alert on auditd stop.
3. Web application workers running as dedicated, unprivileged accounts with `sudo` denied and `noexec` on `/tmp`, `/dev/shm` and `/var/tmp`.
4. Centralised, append-only log shipping (journald remote, syslog to the SIEM within seconds) so local truncation loses nothing.
5. Egress filtering for servers: deny-by-default outbound with explicit allow-lists; servers that cannot call home cannot beacon, mine or exfiltrate.
6. Configuration management owning `authorized_keys`, cron and systemd units, with drift detection; any change outside it is a detection.
7. Patch SLAs for internet-facing services measured in days, with virtual patching or a WAF in front of applications that cannot be patched quickly.
8. For Kubernetes: Pod Security Admission at `restricted` for application namespaces, no human `exec` in production without break-glass approval, short-lived service-account tokens with `automountServiceAccountToken: false` by default, and audit logging at `RequestResponse` level shipped off-cluster.

## Related

- Learn: [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/), [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/), [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/), [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/)
- Playbooks: [Linux hunting]({{ site.baseurl }}/hunt/playbooks/linux-hunting/), [Web shells]({{ site.baseurl }}/hunt/playbooks/web-shells/), [C2 beaconing & DNS tunneling]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/), [Data exfiltration]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/), [Kubernetes & containers]({{ site.baseurl }}/hunt/playbooks/kubernetes-containers/)
- Hypotheses: [Linux section of the library]({{ site.baseurl }}/hunt/hypotheses/#linux)
- Cheat sheets: [Linux logs & auditd]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/), [Network & DNS (Zeek)]({{ site.baseurl }}/cheatsheets/network-zeek/)
- Labs: [Emulate and detect]({{ site.baseurl }}/labs/emulate-and-detect/) for the Linux Atomic tests that validate these queries
- Templates: [Hunt report]({{ site.baseurl }}/templates/#hunt-report), [IR hand-off package]({{ site.baseurl }}/templates/#handoff-package-to-ir)
- Blog: [Hunting C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/), [Hunting persistence]({{ site.baseurl }}/blog/hunting-persistence/), [Threat hunting fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/)
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/)
