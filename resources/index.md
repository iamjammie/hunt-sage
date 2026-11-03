---
title: "Tools, Books, Courses & Communities"
permalink: /resources/
excerpt: "A curated starting list. Check each project's current status before adopting it."
---

A curated starting list, not an exhaustive one. Open-source projects change maintainers, licences and names; **check each project's current status before adopting it**. Where a canonical URL is not given, search for the name.

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

## Hunting and detection tooling

A closer look at the tools above, grouped by what they do for a hunter.

### Endpoint collection and triage

| Tool | Why |
|---|---|
| [Velociraptor](https://docs.velociraptor.app/) | Open-source endpoint visibility and collection at fleet scale; VQL artefacts for live hunts (autoruns, prefetch, event logs) across thousands of hosts |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast Sigma-based hunting across EVTX and other logs; good for first-pass triage of a collected bundle |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Sigma-driven EVTX timeline generator with built-in rule set and CSV/JSON output for pivoting |
| [Zircolite](https://github.com/wagga40/Zircolite) | Standalone Sigma engine over EVTX, auditd and Sysmon-for-Linux logs; works offline |
| [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) with [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular) | The free telemetry baseline for Windows hunting; both configs are maintained, documented and ATT&CK-annotated (sysmon-modular) |
| [Sigma CLI / pySigma](https://github.com/SigmaHQ/sigma-cli) | Convert Sigma rules to Splunk, KQL, Elastic and more; the basis for detection-as-code pipelines |
| HELK | Elastic-based hunting lab with Jupyter and Spark; archived, but still useful as a reference architecture |
| [Jupyter](https://jupyter.org/) + [msticpy](https://github.com/microsoft/msticpy) | Notebooks for statistics the SIEM cannot do; msticpy adds Sentinel/Defender queries, enrichment and timeline widgets |

### Emulation and labs

| Tool | Why |
|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Small, documented tests per ATT&CK technique; the fastest way to generate known-bad telemetry |
| [MITRE CALDERA](https://github.com/mitre/caldera) | Automated adversary emulation with chained abilities; exercise whole kill chains |
| [DetectionLab](https://github.com/clong/DetectionLab) (archived) · [Ludus](https://ludus.cloud/) · [GOAD](https://github.com/Orange-Cyberdefense/GOAD) | Lab builders. DetectionLab is no longer maintained but is well documented; Ludus automates ranges; GOAD is a deliberately vulnerable AD for identity hunting |
| [Security Onion](https://securityonionsolutions.com/) | Turn-key NSM and log platform (Zeek, Suricata, Elastic) for a lab or small production network |
| [Wazuh](https://wazuh.com/) | Open-source agent-based SIEM/XDR; free way to centralise endpoint logs |
| [Elastic Security](https://www.elastic.co/security) | Free tier SIEM with a public detection-rules repo and EQL for sequence hunting |

### Network

| Tool | Why |
|---|---|
| [Zeek](https://zeek.org/) | Protocol logs (conn, dns, http, ssl, files) that make network hunting possible without full packet capture |
| [Suricata](https://suricata.io/) | Signatures plus protocol metadata; pairs with Zeek |
| [Arkime](https://arkime.com/) | Indexed full packet capture when you need the payload |
| [Malcolm](https://github.com/cisagov/Malcolm) | CISA's packaged Zeek + Suricata + Arkime + OpenSearch stack with dashboards |
| [RITA](https://github.com/activecm/rita) | Beacon, long-connection and DNS tunnelling scoring over Zeek logs |

### Active Directory and identity

| Tool | Why |
|---|---|
| [BloodHound](https://github.com/SpecterOps/BloodHound) (for defenders) | Graph of AD attack paths; defenders use it to find and cut the shortest paths to Tier 0 before attackers do |
| [PingCastle](https://www.pingcastle.com/) | AD health and risk report; quick wins on password policy, delegation, trusts |
| [Purple Knight](https://www.purple-knight.com/) | Free AD and Entra ID security indicator scanner |
| [Locksmith](https://github.com/jakehildreth/Locksmith) | PowerShell tool that finds and fixes AD CS misconfigurations (ESC1–ESC8 family) |

### Threat intelligence platforms

| Tool | Why |
|---|---|
| [MISP](https://www.misp-project.org/) | Share and correlate indicators; feeds and taxonomies |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | STIX-native knowledge graph of actors, campaigns, TTPs and reports; good for turning reports into hypotheses |

## Rule and analytic repositories

| Repository | Why |
|---|---|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | The reference Sigma rule set; read the rules for a technique before writing your own |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | Well-tested rules with false-positive notes and EQL sequences |
| [Splunk Security Content](https://github.com/splunk/security_content) | ESCU analytics with SPL, data-source annotations and Atomic test mappings |
| Microsoft Sentinel content hub / [Azure-Sentinel GitHub](https://github.com/Azure/Azure-Sentinel) | KQL analytics and hunting queries per connector |
| [Google SecOps (Chronicle) detection rules](https://github.com/chronicle/detection-rules) | YARA-L rules; useful for seeing another vendor's take on the same technique |
| [KQL Search](https://www.kqlsearch.com/) | Search engine over public KQL queries |
| [Bert-Jan Pals: Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules) | Large, well-organised KQL set for Defender and Sentinel |
| Florian Roth's resources ([Nextron blog](https://www.nextron-systems.com/blog/), signature-base, Sigma) | Author of Sigma and THOR; essays on detection quality and the "detection as code" mindset |
| [Threat Hunter Playbook](https://threathunterplaybook.com/) | Hunting notebooks tied to the Security Datasets |
| [MITRE CAR](https://car.mitre.org/) | Analytics with pseudocode and data-model mapping |
| [LOLBAS](https://lolbas-project.github.io/) · [GTFOBins](https://gtfobins.github.io/) · [LOLDrivers](https://www.loldrivers.io/) · [HijackLibs](https://hijacklibs.net/) · [WADComs](https://wadcoms.github.io/) | Living-off-the-land references: binaries, Unix tools, vulnerable drivers, DLL hijack targets, Windows/AD offensive command cheat sheet (read it as a defender) |

## Reading and reports

| Source | Why |
|---|---|
| [The DFIR Report](https://thedfirreport.com/) | Full intrusion write-ups with timestamps, commands and detections; each one is a ready-made hypothesis card |
| [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/) | Annual: most-observed techniques with detection opportunities and test ideas |
| [Mandiant M-Trends](https://www.mandiant.com/m-trends) | Annual: dwell time, initial access trends, actor overview |
| CrowdStrike Global Threat Report | Annual: eCrime tempo, breakout time, identity-based attacks |
| [Microsoft Digital Defense Report](https://www.microsoft.com/security/security-insider/) | Annual: identity, cloud and nation-state trends from Microsoft telemetry |
| [Huntress blog](https://www.huntress.com/blog) | SMB-focused intrusions and tradecraft seen by an MDR |
| [SpecterOps blog](https://posts.specterops.io/) | Identity, AD CS, BloodHound and detection research from both sides |
| [Sekoia blog](https://blog.sekoia.io/) | Infrastructure tracking and malware campaign analysis |
| [Elastic Security Labs](https://www.elastic.co/security-labs) | Malware analysis and detection research with open rules |
| Also: Microsoft Threat Intelligence, Unit 42, Talos, Splunk Threat Research, SANS ISC | Steady flow of actor and campaign reports |

## Podcasts and newsletters

| Source | Why |
|---|---|
| [Risky Business](https://risky.biz/) | Weekly news and interviews; the sponsor interviews are often technical |
| [Detection at Scale](https://www.detectionatscale.com/) | Jack Naglieri's interviews with detection and security-data leaders |
| [tl;dr sec](https://tldrsec.com/) | Clint Gibler's weekly round-up of tools, talks and research |
| [Detection Engineering Weekly](https://www.detectionengineering.net/) | Zack Allen's newsletter: detection content, rules and reports |
| [This Week in Security](https://this.weekinsecurity.com/) | Zack Whittaker's concise weekly news |
| [SANS Internet Storm Center diary](https://isc.sans.edu/diaryarchive.html) | Daily, short, practical; handlers post real log excerpts |

## Courses and training

| Provider | Courses (examples) |
|---|---|
| SANS | FOR508 Advanced Incident Response, Threat Hunting & Digital Forensics; FOR572 Network Forensics; SEC504 Hacker Tools & Incident Handling; SEC555 SIEM with Tactical Analytics; SEC511 Continuous Monitoring |
| Free | MITRE ATT&CK Defender (MAD) training; Cyber Defenders / BlueTeamLabs / LetsDefend free tiers; TryHackMe SOC paths; Microsoft Learn (KQL, Sentinel); Splunk free training; Elastic training |
| Vendor-neutral | Active Countermeasures (threat hunting webcasts); Black Hills Information Security (BHIS) webcasts |

| Course / platform | Why |
|---|---|
| SANS SEC504 | Attack techniques and incident handling; the usual first SANS course |
| SANS SEC511 | Continuous monitoring and security operations design |
| SANS SEC555 | SIEM tactical analytics: enrichment, baselining, detection with logs |
| SANS FOR508 | Enterprise IR and hunting at scale; the closest fit for a hunter |
| [Active Countermeasures Cyber Threat Hunting](https://www.activecountermeasures.com/cyber-threat-hunting-training-course/) | Free, regular, network-focused hunting course with lab data |
| [Splunk Boss of the SOC (BOTS)](https://bots.splunk.com/) | Realistic datasets and questions; the free BOTS datasets are excellent for stacking and pivot practice |
| [Antisyphon Training](https://www.antisyphontraining.com/) | Pay-what-you-can courses from BHIS and friends |
| [TCM Security Academy](https://academy.tcm-sec.com/) | Affordable practical courses including SOC and detection tracks |
| [Blue Team Labs Online](https://blueteamlabs.online/) | Defensive challenges and investigations; BTL1/BTL2 come from the same organisation |
| [LetsDefend](https://letsdefend.io/) | Simulated SOC with alert queues and case management |
| [CyberDefenders](https://cyberdefenders.org/) | Blue-team CTF labs with EVTX, memory and PCAP artefacts |
| [Hack The Box Sherlocks](https://www.hackthebox.com/sherlocks) | DFIR scenario challenges with downloadable artefacts |
| [TryHackMe SOC paths](https://tryhackme.com/) | Guided SOC Level 1 and 2 learning paths |

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
| *Applied Network Security Monitoring* (Chris Sanders & Jason Smith) | Collection, detection and analysis for network hunting |
| *Practical Packet Analysis* (Chris Sanders) | Wireshark fluency for the PCAP parts of a hunt |
| *Incident Response & Computer Forensics* (Luttgens, Pepe, Mandia) | IR process and evidence handling hunters hand off into |
| *Crafting the InfoSec Playbook* (Jeff Bollinger, Brandon Enright, Matthew Valites) | Writing repeatable detection and hunt plays |
| *Blue Team Handbook: SOC, SIEM and Threat Hunting* (Don Murdoch) | Compact operational reference |
| *Evading EDR* (Matt Hand) | How EDR sensors work and where they are blind; read it to understand your own telemetry |
| *Operator Handbook* (Joshua Picolet) | Red and blue command reference |
| *Security Chaos Engineering* (Kelly Shortridge & Aaron Rinehart) | Testing assumptions about defences systematically |

## Communities and conferences

| Community | Why |
|---|---|
| SigmaHQ GitHub discussions and Discord | Rule review culture; ask about field mappings and false positives |
| DFIR Discord | Large, active community for forensics and IR questions |
| Blue Team Village (DEF CON) | Talks, workshops and the Discord that outlives the conference |
| SANS Blue Team Summit (and DFIR Summit) | Practitioner talks; many free to attend virtually, slides published |
| BSides (your nearest city) | Low cost, local, good for first talks |
| Threat hunting Slack/Discord communities (THUG and others) | Smaller practitioner groups; find current invite links through community posts |
| [r/blueteamsec](https://www.reddit.com/r/blueteamsec/) | Daily feed of detection research, tools and reports |
| Vendor community forums (Splunk Answers, Elastic Discuss, Microsoft Tech Community) | Query help and platform-specific hunting content |

## Staying current

1. Follow ATT&CK release notes (twice-yearly) and add new techniques to your backlog.
2. Subscribe to 3-5 DFIR report sources; turn each report into a hypothesis card.
3. Review the Sigma repository's recent merges; adopt rules that fit your data.
4. Run a quarterly purple-team cycle ([Emulate → Detect]({{ site.baseurl }}/labs/emulate-and-detect/)).
5. For career planning and interview preparation, see [Careers & Interview Prep]({{ site.baseurl }}/learn/career-and-interviews/).
