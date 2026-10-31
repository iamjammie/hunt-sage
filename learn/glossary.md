---
title: "Glossary"
permalink: /learn/glossary/
excerpt: "Threat hunting and detection-engineering jargon, decoded."
toc: false
---

| Term | Meaning |
|---|---|
| **AMSI** | Antimalware Scan Interface; lets AV inspect script content at runtime (PowerShell, VBScript, JScript). |
| **APT** | Advanced Persistent Threat: a well-resourced actor with sustained, targeted campaigns. |
| **ATT&CK** | MITRE's knowledge base of adversary tactics, techniques and procedures. |
| **Baseline** | A model of "normal" for an entity or population, used to detect deviations. |
| **Beaconing** | Periodic check-ins from malware to its command-and-control server. |
| **BYOVD** | Bring Your Own Vulnerable Driver: loading a signed but vulnerable driver to gain kernel access or kill security tools. |
| **C2 / C&C** | Command and control: the channel an attacker uses to remotely operate compromised systems. |
| **CTI** | Cyber threat intelligence. |
| **DCSync** | Abusing directory replication rights to pull credential hashes from a domain controller. |
| **Detection engineering** | Designing, building, testing and maintaining detections as a discipline. |
| **DGA** | Domain generation algorithm: malware generates many pseudo-random domains to find its C2. |
| **Diamond Model** | Intrusion-analysis model linking adversary, capability, infrastructure and victim. |
| **Dwell time** | Time between initial compromise and detection. |
| **EDR / XDR** | Endpoint (or extended) detection and response. |
| **EVTX** | Windows Event Log file format. |
| **False positive / negative** | Alert on benign activity / missed malicious activity. |
| **Golden / Silver ticket** | Forged Kerberos TGT (krbtgt hash) / service ticket (service account hash). |
| **Hunt hypothesis** | A testable statement about adversary activity that guides a hunt. |
| **HMM** | Hunting Maturity Model (David Bianco). |
| **IOA** | Indicator of attack: a behaviour pattern suggesting malicious intent, independent of specific tools. |
| **IOC** | Indicator of compromise: an artefact such as hash, IP or domain. |
| **JA3 / JA3S / JARM** | Fingerprints of TLS client / server handshakes (JARM actively probes servers); useful for C2 pivoting. |
| **Kerberoasting** | Requesting service tickets for SPN accounts and cracking them offline. |
| **LOLBin / LOLBAS** | Living-off-the-land binary / binaries and scripts: legitimate OS tools abused by attackers. |
| **LotL** | Living off the land. |
| **LSASS** | Local Security Authority Subsystem Service; holds credential material in memory. |
| **M-ATH** | Model-Assisted Threat Hunting (PEAK). |
| **NTDS.dit** | The Active Directory database file containing password hashes. |
| **OCSF / ECS / ASIM / CIM** | Common data schemas (Open Cybersecurity Schema Framework, Elastic Common Schema, Advanced Security Information Model, Common Information Model). |
| **PEAK** | Prepare, Execute, Act with Knowledge: Splunk SURGe hunting framework. |
| **Pivot** | Using one finding to search for related activity (same host, user, IP, hash). |
| **Pyramid of Pain** | Model ranking indicator types by cost to the adversary when detected. |
| **SIGMA** | Open, vendor-neutral detection rule format for log events. |
| **SOAR** | Security orchestration, automation and response. |
| **SPN** | Service Principal Name: identifies a service instance for Kerberos. |
| **Stacking** | Counting values of a field and examining the rare ones ("long tail"). |
| **Sysmon** | Microsoft Sysinternals service/driver providing detailed Windows endpoint telemetry. |
| **TaHiTI** | Targeted Hunting integrating Threat Intelligence methodology. |
| **TTPs** | Tactics, techniques and procedures. |
| **UEBA** | User and entity behaviour analytics. |
| **Zeek** | Network security monitor producing rich protocol logs (formerly Bro). |
