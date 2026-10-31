---
title: "Detection Engineering Notes: Technique → Telemetry → Detection → Test"
permalink: /research/mitre-detection-engineering/
excerpt: "A working notebook mapping ATT&CK techniques to telemetry, concrete detection logic and test cases."
---

Companion to [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/) (theory) and the [hunt playbooks]({{ site.baseurl }}/hunt/) (practice).

## Mapping method

For each technique record:

1. **Behaviour**: what the adversary must do on the system
2. **Telemetry**: the log/event that records it, and what must be enabled
3. **Detection logic**: atomic, threshold, sequence, rarity or baseline
4. **Test**: how to generate it safely
5. **False positives and tuning**

## Worked mappings

| Technique | Telemetry | Detection logic | Test | Rule / playbook |
|---|---|---|---|---|
| **T1059.001** PowerShell | Sysmon 1 / 4688 (command line); 4104 | Encoded/obfuscated args; unusual parent; download cradles in 4104 | `Invoke-AtomicTest T1059.001` | [Rule]({{ site.baseurl }}/research/sigma/T1059.001-powershell-encoded-command.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) |
| **T1059.003** Windows Command Shell | Process creation with command line | `cmd.exe /c` with lateral-movement tools or from web servers/Office; long obfuscated lines | Atomic T1059.003 | [Web-server child rule]({{ site.baseurl }}/research/sigma/T1505.003-webserver-spawns-shell.yml) |
| **T1003.001** LSASS memory | Sysmon 10 | Non-system opener with read masks (0x1010/0x1410/...); `CallTrace` with dbghelp/dbgcore | Atomic T1003.001 | [Rule]({{ site.baseurl }}/research/sigma/T1003.001-lsass-access-suspicious.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) |
| **T1558.003** Kerberoasting | DC 4769 | RC4 + user SPN + many distinct SPNs per source in minutes; honey SPN | Atomic T1558.003 | [Rule]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/kerberoasting/) |
| **T1003.006** DCSync | DC 4662 + 4624 | Replication GUIDs from non-DC; correlate source IP | Mimikatz/Impacket in lab | [Rule]({{ site.baseurl }}/research/sigma/T1003.006-dcsync-replication.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/dcsync/) |
| **T1550.002** Pass-the-hash | 4624 | Type 3 NTLM with KeyLength 0; fan-out | Mimikatz `sekurlsa::pth` | [Rule]({{ site.baseurl }}/research/sigma/T1550.002-pass-the-hash.yml) |
| **T1543.003 / T1569.002** Service creation / PsExec | System 7045 / Security 4697; 5145 | Image path in ADMIN$/temp/cmd; `PSEXESVC` | PsExec in lab | [Rule]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml) |
| **T1053.005** Scheduled task | 4698; Sysmon 1 | `schtasks /create` with user-path or interpreter action | Atomic T1053.005 | [Rule]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) |
| **T1547.001** Run keys | Sysmon 13 | Value data in user path / interpreter | Atomic T1547.001 | [Rule]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml) |
| **T1546.003** WMI subscription | Sysmon 19-21; WMI-Activity 5861 | Any new consumer outside mgmt tools | Atomic T1546.003 | [Rule]({{ site.baseurl }}/research/sigma/T1546.003-wmi-event-subscription.yml) |
| **T1070.001** Clear logs | 1102 / 104 | Any occurrence | `wevtutil cl` | [Rule]({{ site.baseurl }}/research/sigma/T1070.001-security-log-cleared.yml) |
| **T1562.001** Impair defenses | Process creation; Defender 5001/5007 | `Set-MpPreference` disables/exclusions | Atomic T1562.001 | [Rule]({{ site.baseurl }}/research/sigma/T1562.001-defender-tampering-powershell.yml) |
| **T1490** Inhibit recovery | Process creation | `vssadmin delete shadows`, `bcdedit`, `wbadmin delete` | Atomic T1490 (VM) | [Rule]({{ site.baseurl }}/research/sigma/T1490-shadow-copy-deletion.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/ransomware-precursors/) |
| **T1567.002** Exfil to cloud | Process creation; proxy | rclone `OriginalFileName`/flags; cloud-storage domain stacking | Atomic T1567.002 | [Rule]({{ site.baseurl }}/research/sigma/T1567.002-rclone-exfiltration.yml) · [Playbook]({{ site.baseurl }}/hunt/playbooks/data-exfiltration/) |
| **T1071** C2 | Proxy/DNS/Zeek | Timing regularity + rarity + fingerprints | Lab beacon | [Playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) |

## Detection design checklist

- [ ] The behaviour is **hard for the adversary to avoid** (high on the Pyramid of Pain)
- [ ] The telemetry is **reliably collected** (coverage measured)
- [ ] Logic names **stable fields** (OriginalFileName, access mask, GUIDs) rather than easily changed strings
- [ ] There is a **positive test** and a **negative replay**
- [ ] **False positives** are enumerated, not hand-waved
- [ ] **Response guidance** is attached (what to look at first)
- [ ] The rule has an **owner**, **status** (`experimental → test → stable`) and **review date**

## Rule status criteria used in this repo

| Status | Meaning |
|---|---|
| `experimental` | Written, syntax-valid, may be noisy; not yet tuned |
| `test` | Positive test performed in lab; false positives enumerated |
| `stable` | Tested in a production-like environment over ≥30 days with documented precision |

## Backlog (techniques planned next)

T1021.001 RDP anomalies · T1021.006 WinRM · T1036.005 Masquerading · T1110 Brute force · T1548.002 UAC bypass · T1574.001/.002 DLL hijacking · T1055 Injection (Sysmon 8/10/25) · T1071.004 DNS tunneling analytic · T1098.* cloud role changes (Sentinel analytics) · T1649 AD CS abuse.

Want to add one? See [contributing](https://github.com/iamjammie/hunt-sage/blob/main/CONTRIBUTING.md).
