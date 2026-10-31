---
title: "Emulate → Detect: Guided Exercises"
permalink: /labs/emulate-and-detect/
excerpt: "Use Atomic Red Team to generate technique telemetry, then find it, write a hunt, and ship a detection."
---

**Loop:** *emulate a technique → locate its telemetry → write the query → tune against baseline → write the Sigma rule → re-emulate to confirm it fires.*

> Run only in your isolated lab, from a snapshot. Some tests trigger AV/EDR by design.

## Setup: Atomic Red Team

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a library of small, ATT&CK-mapped tests. Use the PowerShell execution framework **Invoke-AtomicRedTeam**:

```powershell
# Install the framework and atomics (check the project README for current instructions)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Invoke-AtomicTest T1059.001 -ShowDetailsBrief        # list tests
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1           # run
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup  # always clean up
```

Review the install script before running it. Other emulation options: **MITRE Caldera**, **Stratus Red Team** (cloud), **Atomic Operator** (Python), **PurpleSharp**, **Sliver/Mythic** (full C2 on your own infrastructure).

## Exercise format

For each exercise: run the test, then answer the **Hunt questions**, then complete **Deliverable**.

### Exercise 1: PowerShell encoded command (T1059.001)

- **Run:** `Invoke-AtomicTest T1059.001` (an encoded-command test)
- **Hunt questions**
  1. Which events record the execution? (Sysmon 1, Security 4688, PowerShell 4104)
  2. What does the decoded script block look like in 4104?
  3. What is the parent process chain?
- **Deliverable:** the query from the [PowerShell playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) returning your test, plus an exclusion that would suppress a legitimate use *without* suppressing yours.

### Exercise 2: Run key + scheduled task persistence (T1547.001, T1053.005)

- **Run:** `Invoke-AtomicTest T1547.001` and `T1053.005`
- **Hunt:** Sysmon 13 for the Run key; 4698 / Sysmon 1 for `schtasks`. Use the [persistence playbook]({{ site.baseurl }}/hunt/playbooks/persistence/).
- **Deliverable:** stack all Run keys across WS01/SRV01/DC01 and explain every entry; confirm the Sigma rules [Run key]({{ site.baseurl }}/research/sigma/T1547.001-run-key-suspicious-value.yml) and [schtasks]({{ site.baseurl }}/research/sigma/T1053.005-schtasks-suspicious-create.yml) fire.

### Exercise 3: LSASS access (T1003.001)

- **Run:** `Invoke-AtomicTest T1003.001` (some tests need Defender exceptions in the lab)
- **Hunt:** Sysmon 10 to `lsass.exe`: what `GrantedAccess`, `SourceImage`, `CallTrace`? Which legitimate processes also appear?
- **Deliverable:** a baseline list of legitimate LSASS openers in your lab and the [LSASS playbook]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/) query that isolates the test.

### Exercise 4: Kerberoasting (T1558.003)

- **Prep:** create a service account with an SPN and a weak password in your lab AD.
- **Run:** `Invoke-AtomicTest T1558.003` or Rubeus/Impacket `GetUserSPNs.py` from the attacker VM.
- **Hunt:** 4769 on DC01 with `0x17`. How many SPNs in how many seconds?
- **Deliverable:** the aggregate query and the [Sigma rule]({{ site.baseurl }}/research/sigma/T1558.003-kerberoasting-rc4-tgs.yml); then add a **honey SPN**.

### Exercise 5: DCSync (T1003.006)

- **Prep:** grant a test account replication rights (lab only).
- **Run:** Mimikatz `lsadump::dcsync` or Impacket `secretsdump.py -just-dc` from a non-DC host.
- **Hunt:** 4662 with replication GUIDs on DC01; correlate `SubjectLogonId` to 4624 for the source IP.
- **Deliverable:** [DCSync playbook]({{ site.baseurl }}/hunt/playbooks/dcsync/) query + allow-list for DC accounts.

### Exercise 6: Lateral movement via service execution (T1021.002, T1569.002)

- **Run:** Sysinternals `PsExec` or Impacket `psexec.py` from WS01 to SRV01 (lab credentials).
- **Hunt:** 5145 (ADMIN$ write) → 7045/4697 (service install) → Sysmon 1 (child of `services.exe`) → 4624 type 3 on SRV01.
- **Deliverable:** one timeline stitching all four events; the [service install Sigma rule]({{ site.baseurl }}/research/sigma/T1543.003-suspicious-service-install.yml).

### Exercise 7: Defense evasion and impact (T1070.001, T1562.001, T1490)

- **Run (snapshot first):** `wevtutil cl Security`; `Set-MpPreference -DisableRealtimeMonitoring $true`; `vssadmin delete shadows /all /quiet` (on a VM with no real data).
- **Hunt:** 1102, Defender 5001, Sysmon 1.
- **Deliverable:** confirm all three Sigma rules fire; discuss: if the attacker clears logs *before* the SIEM ingests them, what protects you? (Answer: near-real-time forwarding and off-host retention.)

### Exercise 8: Beaconing (T1071.001)

- **Run:** a scripted beacon with jitter against a lab web server:

```bash
# Lab-only benign beacon: GET every ~60s ± 20% with a fixed User-Agent
while true; do curl -s -A "Mozilla/5.0 (lab-beacon)" http://lab-c2.hunt.lab/check >/dev/null; sleep $(( 48 + RANDOM % 25 )); done
```

- **Hunt:** run the timing analysis from the [C2 beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/) on proxy or Zeek `conn.log`. At what jitter does your CoV threshold stop catching it?
- **Deliverable:** a daily beacon-candidates analytic with an allow-list.

## Purple-team scorecard

Track each technique:

| Technique | Emulated? | Telemetry present? | Hunt query? | Detection? | Fires on re-test? | Precision (30-day) |
|---|---|---|---|---|---|---|
| T1059.001 | ✔ | ✔ | ✔ | ✔ | ✔ | |
| ... | | | | | | |

Use this to feed the [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/) with *validated* coverage rather than hoped-for coverage.

## Go further

- Run a **CTF**: [Argon Nexus]({{ site.baseurl }}/ctf/argon-nexus/)
- Chain techniques into a scenario (use Caldera "adversary profiles" or your own sequence from [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/#typical-post-exploitation-sequence-illustrative)) and hunt the **chain**.
- Swap roles: write a detection, have a colleague try to evade it.
