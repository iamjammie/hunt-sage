---
title: "Tools, Books, Courses & Communities"
permalink: /resources/
excerpt: "A curated starting list. Check each project's current status before adopting it."
---

## Frameworks and knowledge bases

| Resource | Why it matters |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) and [Navigator](https://mitre-attack.github.io/attack-navigator/) | Common vocabulary and coverage mapping |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Defensive technique countermeasure knowledge graph |
| [MITRE CAR](https://car.mitre.org/) | Cyber Analytics Repository: analytics mapped to ATT&CK |
| [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) | Map data sources and detection coverage |
| [Sigma](https://github.com/SigmaHQ/sigma) | Detection rules (thousands, community maintained) |
| [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) | David Bianco's model for indicator value |
| Hunting Maturity Model (David Bianco) and the Sqrrl Threat Hunting Reference Model | Maturity yardstick and hunt loop (search for the original papers) |
| TaHiTI: *Targeted Hunting integrating Threat Intelligence* (published by the Dutch financial sector) | Intel-integrated hunting methodology |
| PEAK Threat Hunting Framework (Splunk SURGe) | Hypothesis, baseline and model-assisted hunt types |
| [Threat Hunter Playbook (OTRF)](https://threathunterplaybook.com/) | Hunting notebooks and datasets |
| [LOLBAS](https://lolbas-project.github.io/) · [GTFOBins](https://gtfobins.github.io/) · [LOLDrivers](https://www.loldrivers.io/) | Living-off-the-land references |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Technique emulation tests |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) · [Splunk Security Content](https://github.com/splunk/security_content) · [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel) | Detection and hunting query repositories |
| [Awesome Threat Detection / Hunting lists](https://github.com/0x4D31/awesome-threat-detection) | Curated link collections |

## Tools

| Category | Tools |
|---|---|
| **Telemetry** | Sysmon (+ SwiftOnSecurity `sysmon-config`, `sysmon-modular`), osquery, auditd, Falco, Windows Event Forwarding |
| **Network** | Zeek, Suricata, Security Onion, RITA / AC-Hunter, Arkime (full packet capture), Wireshark |
| **SIEM / data** | Splunk, Microsoft Sentinel, Elastic Security, Graylog, Wazuh, OpenSearch |
| **EDR / live response** | Defender for Endpoint, CrowdStrike, SentinelOne, Velociraptor (open source), GRR |
| **Log triage** | Chainsaw, Hayabusa, Zircolite, EvtxECmd, Timeline Explorer, Plaso/log2timeline |
| **Intel** | MISP, OpenCTI, VirusTotal, URLhaus, Shodan, Censys, abuse.ch, GreyNoise |
| **AD analysis** | BloodHound, PingCastle, Purple Knight, ADExplorer |
| **Memory / malware** | Volatility 3, MemProcFS, CAPE/Cuckoo, CyberChef, YARA, capa, Ghidra |
| **Autoruns & triage** | Sysinternals Suite (Autoruns, Process Explorer/Monitor, TCPView), KAPE |
| **Emulation** | Atomic Red Team, Caldera, Stratus Red Team, PurpleSharp, Sliver/Mythic (own infrastructure only) |
| **Analysis** | Jupyter, pandas, DuckDB, Kusto/Log Analytics notebooks |

## Books

| Title | Why |
|---|---|
| *The Practice of Network Security Monitoring* (Richard Bejtlich) | NSM fundamentals |
| *Intelligence-Driven Incident Response* (Scott Roberts & Rebekah Brown) | CTI-led operations |
| *Practical Threat Detection Engineering* (Megan Roddie, Jason Deyalsingh, Gary J. Katz) | Detection engineering in practice |
| *Cyber Threat Hunting* (Nadhem AlFardan) | Hunting methodology and data analysis |
| *Threat Hunting with Elastic Stack* (Andrew Pease) | Hunting on Elastic |
| *Threat Hunting in the Cloud* (Chris Peiris, Binil Pillai, Abbas Kudrati) | Cloud-specific hunting |
| *The Art of Memory Forensics* (Ligh, Case, Levy, Walters) | Memory analysis |
| *Windows Internals* (Yosifovich, Russinovich et al.) | Understand what telemetry actually represents |

## Courses and training

| Provider | Courses (examples) |
|---|---|
| SANS | FOR508 Advanced Incident Response, Threat Hunting & Digital Forensics; FOR572 Network Forensics; SEC504 Hacker Tools & Incident Handling; SEC555 SIEM with Tactical Analytics; SEC511 Continuous Monitoring |
| Free | MITRE ATT&CK Defender (MAD) training; Cyber Defenders / BlueTeamLabs / LetsDefend free tiers; TryHackMe SOC paths; Microsoft Learn (KQL, Sentinel); Splunk free training; Elastic training |
| Vendor-neutral | Active Countermeasures (threat hunting webcasts); Black Hills Information Security (BHIS) webcasts |

## Blogs and communities

- The DFIR Report, Red Canary, Elastic Security Labs, Microsoft Security Blog and Threat Intelligence, Mandiant/Google Cloud Threat Intelligence, Splunk Threat Research, Huntress, Unit 42, Talos, Sekoia, SANS ISC
- Communities: SigmaHQ GitHub discussions, Blue Team Village (DEF CON), r/blueteamsec, vendor community forums (Splunk, Elastic, Microsoft Tech Community)

## Staying current

1. Follow ATT&CK release notes (twice-yearly) and add new techniques to your backlog.
2. Subscribe to 3-5 DFIR report sources; turn each report into a hypothesis card.
3. Review the Sigma repository's recent merges; adopt rules that fit your data.
4. Run a quarterly purple-team cycle ([Emulate → Detect]({{ site.baseurl }}/labs/emulate-and-detect/)).
