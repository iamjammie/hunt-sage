---
title: "Linux Logs & auditd for Hunters"
excerpt: "Where evidence lives on Linux, a starter auditd ruleset, and triage one-liners."
---

## Where to look

| Evidence | Debian/Ubuntu | RHEL/CentOS/Fedora | Notes |
|---|---|---|---|
| Authentication, sudo, SSH | `/var/log/auth.log` | `/var/log/secure` | `Accepted`/`Failed password`, `publickey`, `sudo:` |
| General system | `/var/log/syslog` | `/var/log/messages` | |
| Journal (systemd) | `journalctl` | `journalctl` | `journalctl -u ssh`, `_COMM=sudo`, `--since "2 hours ago"` |
| Logins | `last`, `lastb`, `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | same | Binary: use `last -f` |
| Audit | `/var/log/audit/audit.log` | same | auditd; `ausearch`, `aureport` |
| Cron | `/var/log/syslog` (CRON) | `/var/log/cron` | |
| Package changes | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `/var/log/dnf.log`, `rpm -qa --last` | New tools/backdoored packages |
| Web servers | `/var/log/apache2/`, `/var/log/nginx/` | `/var/log/httpd/`, `/var/log/nginx/` | Web shells |
| Shell history | `~/.bash_history`, `~/.zsh_history` | same | Often cleared; absence is a signal |
| Kernel | `dmesg`, `/var/log/kern.log` | | Module loads, USB |
| Containers | `docker logs`, `/var/lib/docker/containers/*/*-json.log`, K8s audit | | |

## Starter auditd rules (`/etc/audit/rules.d/hunt.rules`)

```text
# Process execution (64-bit and 32-bit)
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Persistence and identity files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_keys
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k ld_preload
-w /etc/ld.so.conf.d/ -p wa -k ld_preload

# Kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules

# Network connect (noisy: scope to hunts or use eBPF EDR)
-a always,exit -F arch=b64 -S connect -F a2=16 -k net_connect

# Privilege escalation
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setresuid -F auid>=1000 -F auid!=-1 -k priv_esc

# Time tampering
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time

# Make configuration immutable until reboot (last line)
-e 2
```

Load: `augenrules --load`; verify: `auditctl -l`. Search: `ausearch -k exec -ts today -i`; summaries: `aureport -x --summary`. Consider the community ruleset **Neo23x0/auditd** as a base.

## Triage one-liners

```bash
# Who is logged in / recent logins
w; last -ai | head -30; lastb | head -30
# Processes: tree, deleted binaries, executing from tmp
ps -ef --forest
ls -l /proc/*/exe 2>/dev/null | grep -E 'deleted|/tmp/|/dev/shm/'
# Network: listeners and connections with processes
ss -tulpn; ss -tanp | grep ESTAB
# Persistence
crontab -l; ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
systemctl list-unit-files --state=enabled | head -50
find / -xdev -name authorized_keys -ls 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null
# Accounts
awk -F: '$3==0 {print}' /etc/passwd          # UID 0
grep -vE 'nologin|false' /etc/passwd          # users with shells
# SUID / world-writable
find / -xdev -perm -4000 -type f -ls 2>/dev/null
# Recently modified files
find / -xdev -type f -mtime -2 -not -path '/proc/*' -not -path '/sys/*' -ls 2>/dev/null | head -100
# Auth: top failed sources
grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
```

## SSH log patterns

```text
Accepted publickey for alice from 203.0.113.9 port 51234 ssh2: RSA SHA256:...   # key fingerprint = identity
Accepted password for root from ...                                           # password root login: investigate
Failed password for invalid user admin from ...                               # spray / brute force
Connection closed by authenticating user ... [preauth]                        # scanning
```

Hunt on **fingerprints**: map fingerprints to owners; unknown fingerprint = new key.

## Suspicious execution patterns (leads)

| Pattern | Why |
|---|---|
| `curl|wget ... | sh|bash` | Pipe-to-shell staging |
| `base64 -d | sh`, `echo ... | base64 -d | bash` | Obfuscated execution |
| Execution from `/tmp`, `/var/tmp`, `/dev/shm` | Writable staging areas |
| `chmod +x` then run on same path | Dropper |
| `nohup`, `setsid`, `&` with network tooling | Backgrounded implant |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | TTY upgrade after shell |
| `find ... -perm -4000`, `linpeas`, `pspy`, `LinEnum` | Enumeration |
| `iptables -F`, `systemctl stop auditd/rsyslog`, `service ... stop` | Evasion |
| `export HISTFILE=/dev/null`, `unset HISTFILE`, `history -c` | History evasion |
| `nsenter`, `docker run --privileged -v /:/host`, `/var/run/docker.sock` | Container escape |

## Pull Linux into your hunt platform

- **osquery** tables: `processes`, `listening_ports`, `crontab`, `authorized_keys`, `startup_items`, `suid_bin`, `kernel_modules`, `shell_history`
- **Velociraptor**: `Linux.Sys.Pslist`, `Linux.Sys.Crontab`, `Linux.Ssh.AuthorizedKeys`, `Linux.Detection.BruteForce`
- **Auditd → SIEM** via Filebeat auditd module, Splunk TA for Linux, or the Azure Monitor Agent with Syslog DCRs
