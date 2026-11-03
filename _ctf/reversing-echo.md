---
title: "Reversing Echo"
excerpt: "Reverse engineer a custom binary protocol used by an operator backdoor."
order: 2
layout: single
toc: true
toc_label: "Challenge Stages"
header:
  teaser: /assets/images/ctf/reversing-echo.png
difficulty: Intermediate
skills_tested:
  - Sysmon process, network and file telemetry
  - Static triage with strings and PE metadata
  - PCAP analysis of an unknown protocol
  - Turning behaviour into detections
---

> **Difficulty**: Intermediate  
> **Skills**: Sysmon triage, static strings analysis, Wireshark, Sigma/KQL authoring  
> **Artefacts**: *Coming soon.* The telemetry and capture bundle is on the roadmap; follow or comment on the [Hunt-Sage issues page](https://github.com/iamjammie/hunt-sage/issues) for status  
> **Estimated time**: 2–4 hours

---

## Scenario brief

A stacking hunt across a 400-host estate turned up a binary called `echo.exe` running on exactly one workstation, `WKS-ACCT-17`. The name is innocuous; the path is not: `C:\ProgramData\Microsoft\Echo\echo.exe`. The host's user is an accounts clerk with no reason to run anything from ProgramData.

The hunter who found it collected the Sysmon log for the host, a two-hour packet capture from the span port covering the workstation's VLAN, and a copy of the binary. The EDR vendor's sandbox marked the file "low confidence: suspicious", which helps nobody.

Your job is **analysis, not exploitation**. You will not run the binary. You will read what it did (Sysmon), what it is made of (strings and PE metadata), and what it said on the wire (PCAP), then recover the operator's commands and the secret the binary exfiltrated.

Answer, with evidence:

1. How did `echo.exe` get there and what keeps it running?
2. What does it do on the host?
3. What does its network protocol look like, and what did the operator send?
4. What left the network?
5. What should have detected it, and what detection do you leave behind?

---

## Artefacts (coming soon)

The bundle, when published, will contain:

```text
reversing-echo/
├── sysmon_WKS-ACCT-17.evtx    # Sysmon operational log, 72 hours, modular config (events 1,3,7,10,11,12,13,22)
├── security_WKS-ACCT-17.evtx  # Security log for the same window (4624, 4688, 4698)
├── capture_vlan17.pcap        # 2 hours of span-port capture; echo.exe traffic plus normal office noise
├── echo.exe.strings.txt       # Output of strings (ASCII and UTF-16) on the binary; the binary itself is NOT distributed
├── echo.exe.peinfo.txt        # PE header, sections, imports, version info, signature status
└── README.md                  # Rules of engagement and the flag format
```

The binary is deliberately not shipped. Everything you need is in the strings, PE metadata and telemetry; that is the point. Real analysts triage from telemetry long before anyone opens a disassembler.

**Rules of engagement.** Static analysis of the provided text files and logs only. Do not attempt to recreate the implant, connect to any host named in the capture, or reuse the protocol. All addresses and domains in the bundle are reserved or fictional.

---

## Stages

### Stage 1: Arrival and persistence

**Q1.1** — Using Sysmon event 11 (FileCreate), when was `echo.exe` written to disk, and by which process?

**Q1.2** — Trace the parent chain of that process back to its origin (Sysmon 1 `ParentProcessGuid`). What user action started it?

**Q1.3** — What persistence mechanism keeps `echo.exe` running? Cite the event (4698, Sysmon 12/13 on a Run key, or 7045) and the exact value written.

<details>
<summary>Hint</summary>

Start from the file path, not the file name: filter Sysmon 11 for `TargetFilename` containing `\ProgramData\Microsoft\Echo\`. The creating process is in the `Image` field. Walk `ParentProcessGuid` → `ProcessGuid` in Sysmon 1 until you reach an interactive parent such as `explorer.exe` or an Office application. For persistence, check Sysmon 13 for `TargetObject` ending in `\CurrentVersion\Run\...` and 4698 for a task whose action points at the ProgramData path.

```powershell
Get-WinEvent -Path .\sysmon_WKS-ACCT-17.evtx -FilterXPath "*[System[EventID=11]]" |
  Where-Object { $_.Message -match 'ProgramData\\Microsoft\\Echo' } |
  Select-Object TimeCreated, Message | Format-List
```
</details>

---

### Stage 2: What is it made of?

**Q2.1** — From `echo.exe.peinfo.txt`: what is the `OriginalFileName` in the version resource, and does it match `echo.exe`? Is the file signed?

**Q2.2** — From the strings output, list the imported APIs or string fragments that indicate networking, process execution and persistence. Which three strings would you add to a YARA or Sigma rule?

**Q2.3** — There is a hard-coded host name and a numeric constant that looks like an interval. What are they, and how do they relate to what you will see in Stage 4?

<details>
<summary>Hint</summary>

Compare `OriginalFileName`, `InternalName` and `ProductName` against the file name; mismatches are a classic renamed-tool indicator. In the strings, look for `WSAStartup`, `connect`, `send`, `recv`, `CreateProcessW`, `cmd.exe /c`, `RegSetValueExW`, `schtasks`, and anything that looks like a domain or a format string (`%s`, `%d`). A UTF-16 strings pass finds what an ASCII pass misses on Windows binaries.
</details>

---

### Stage 3: What it did on the host

**Q3.1** — List every child process `echo.exe` spawned (Sysmon 1 where `ParentImage` is the binary), with timestamps and command lines.

**Q3.2** — Which of those commands are discovery (T1082, T1033, T1016, T1069) and which touch data?

**Q3.3** — Did `echo.exe` read or write anything in the user's Documents folder? Which Sysmon event tells you, and what file is involved?

<details>
<summary>Hint</summary>

Sysmon 1 with `ParentImage` ending in `\echo.exe` gives the operator's command history as executed on the host. Discovery commands look like `whoami /all`, `ipconfig /all`, `net group "Domain Admins" /domain`, `systeminfo`. Data staging often appears as `cmd.exe /c type <file>` or a `copy` to the ProgramData directory; Sysmon 11 then shows the staged copy being created.
</details>

---

### Stage 4: Decode the protocol

**Q4.1** — In the PCAP, filter for traffic from `WKS-ACCT-17` to the host name you found in Stage 2 (use the Sysmon 22 DNS event to get the IP). What port and transport does it use, and how regular are the connections?

**Q4.2** — Follow one TCP stream. The payload is not TLS. Describe the packet structure: header length, any magic bytes, a length or opcode field, and how the body is encoded.

**Q4.3** — Decode the operator messages. Map each decoded command to the child processes you found in Stage 3. Do the timestamps line up?

<details>
<summary>Hint</summary>

Wireshark: `ip.dst == <c2 ip> && tcp` then *Follow → TCP Stream* and view as raw hex. Look for a repeated prefix at the start of every message (magic bytes), followed by one or two bytes that change with message size (a length field), then a single byte that varies by message type (an opcode). The body in this challenge uses a single-byte XOR key that also appears as a constant in the strings output; CyberChef's XOR and "From Hex" recipes decode it. Compare the decoded command text with the Sysmon 1 command lines; the gap between the two is the implant's execution delay.
</details>

---

### Stage 5: Recover the secret

**Q5.1** — One outbound message is much larger than the rest. Which opcode does it carry, and what is the decoded body?

**Q5.2** — The body is a file. Which file from Stage 3 is it, and what phrase inside it is the "secret" the operator was after?

**Q5.3** — Estimate the total bytes exfiltrated and the time between first beacon and exfiltration.

<details>
<summary>Hint</summary>

Sort streams by bytes from the client. The large message uses the same framing and XOR key; decode it the same way, then save the body and open it as text. The secret phrase is written in plain English and is also the flag content.
</details>

---

### Stage 6: Improve defences

**Q6.1** — Name at least five points in this chain where existing telemetry should have alerted. For each, give the event ID and the rule logic in one line.

**Q6.2** — Write a Sigma rule (process_creation or network_connection) that would catch this implant family *without* relying on the host name or the file name.

**Q6.3** — Write a three-sentence summary for the client's IT manager.

---

## Flag format

```text
flag{decoded_secret_phrase}
```

Lowercase, words separated by underscores, exactly as decoded from the exfiltrated file; for example `flag{the_quick_brown_fox}`.

---

## Scoring rubric

| Stage | Points | Bonus |
|---|---|---|
| Stage 1 — Arrival and persistence | 15 | +5 for the full parent chain to the user action |
| Stage 2 — Static triage | 15 | +5 for three rule-worthy strings |
| Stage 3 — Host behaviour | 15 | +5 for the ATT&CK mapping |
| Stage 4 — Protocol | 25 | +10 for a complete framing description |
| Stage 5 — Secret | 15 | +5 for the byte and time estimates |
| Stage 6 — Defences | 15 | +10 for a Sigma rule that converts cleanly |
| **Total** | **100** | **+40 bonus** |

---

## What a defender learns

- **Rarity found it; telemetry explained it.** A stacking hunt ([chapter 5]({{ site.baseurl }}/learn/hunting-techniques/)) surfaced a one-host binary. Sysmon then answered every question without touching the machine. That is the normal order of operations.
- **Names lie; metadata is cheaper to trust.** `OriginalFileName`, signature status and import tables are harder to fake than a file name. Build your detections on them ([defence evasion playbook]({{ site.baseurl }}/hunt/playbooks/defense-evasion/)).
- **Parent chains are evidence.** The route from a user's click to a persistent implant is a sequence of Sysmon 1 events linked by GUIDs. Learn to walk it quickly.
- **Custom protocols are not magic.** Magic bytes, a length field, an opcode and a single-byte XOR are what most home-grown implants amount to. Regular intervals on an odd port with small payloads are the network tell ([C2 beaconing playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/)).
- **Every stage is a detection opportunity.** File write to ProgramData by an Office child, Run key or task pointing there, unsigned binary making outbound connections, `cmd.exe /c whoami` under a non-standard parent. The implant did nothing clever; it was simply never looked for.
- **You did not run it.** Static strings, PE metadata and telemetry were enough. Sandboxing and disassembly come later, if at all.

Related: [Persistence playbook]({{ site.baseurl }}/hunt/playbooks/persistence/), [Sigma rules]({{ site.baseurl }}/research/sigma/), and the [emulate-and-detect lab]({{ site.baseurl }}/labs/emulate-and-detect/) to generate similar telemetry safely.

---

*Artefacts are coming soon. Track progress or suggest a scenario on the [Hunt-Sage issues page](https://github.com/iamjammie/hunt-sage/issues).*
