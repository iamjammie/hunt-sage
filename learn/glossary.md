---
title: "Glossary"
permalink: /learn/glossary/
excerpt: "Threat hunting and detection-engineering jargon, decoded."
toc: false
---

Alphabetical. Terms marked with a playbook link have a hunt on this site.

<div class="hs-filter" data-hs-filter data-placeholder="Filter terms..."></div>

| Term | Meaning |
|---|---|
| **Access mask** | Bit flags stating which rights a handle was opened with (e.g. Sysmon 10 `GrantedAccess`, 4663 `AccessMask`); stable across tool renames, so a strong hunt field. |
| **AD CS** | Active Directory Certificate Services: Microsoft's PKI role. Misconfigured templates and endpoints enable the ESC attack family. |
| **AiTM** | Adversary-in-the-middle: a proxy between user and identity provider that captures credentials *and* session tokens, defeating most MFA. |
| **Allow-list** | Documented benign explanations for activity that would otherwise match a hunt or rule; scoped narrowly (host, path, account), never blanket. |
| **AMSI** | Antimalware Scan Interface; lets AV inspect script content at runtime (PowerShell, VBScript, JScript). |
| **APT** | Advanced Persistent Threat: a well-resourced actor with sustained, targeted campaigns. |
| **AS-REP roasting** | Requesting AS-REP messages for accounts with Kerberos pre-authentication disabled and cracking them offline (T1558.004). Event 4768 with RC4 and no pre-auth. |
| **ATT&CK** | MITRE's knowledge base of adversary tactics, techniques and procedures. |
| **ATT&CK data component** | The specific observable under a data source that a technique's detection depends on, e.g. *Process: Process Creation* or *Active Directory: Active Directory Object Access*. |
| **Baseline** | A model of "normal" for an entity or population over a window, used to detect deviations. |
| **Beaconing** | Periodic check-ins from malware to its command-and-control server; detectable by interval regularity ([playbook]({{ site.baseurl }}/hunt/playbooks/c2-beaconing/)). |
| **BYOVD** | Bring Your Own Vulnerable Driver: loading a signed but vulnerable driver to gain kernel access or kill security tools. |
| **C2 / C&C** | Command and control: the channel an attacker uses to remotely operate compromised systems. |
| **Canary / honeytoken** | A fake account, file, SPN or credential that has no legitimate use, so any touch is a high-fidelity alert. |
| **CAR** | MITRE Cyber Analytics Repository: analytics with pseudocode mapped to ATT&CK. |
| **CLM** | Constrained Language Mode: a PowerShell mode that blocks .NET and COM access for untrusted scripts; bypass attempts are a hunt lead. |
| **CloudTrail** | AWS API audit log; the primary data source for hunting in AWS accounts. |
| **Crown jewels** | The systems, data and identities whose compromise would hurt most; the first scope for any hunt backlog. |
| **CTI** | Cyber threat intelligence. |
| **D3FEND** | MITRE's knowledge graph of defensive techniques and the offensive techniques they counter. |
| **DCShadow** | Registering a rogue domain controller to push malicious replication changes (T1207); look for 4742/4662 on nTDSDSA objects from non-DC hosts. |
| **DCSync** | Abusing directory replication rights to pull credential hashes from a domain controller (T1003.006; [playbook]({{ site.baseurl }}/hunt/playbooks/dcsync/)). |
| **Detection-as-code** | Managing detections in version control with review, tests and automated deployment, like software. |
| **Detection engineering** | Designing, building, testing and maintaining detections as a discipline. |
| **DeTT&CT** | Open-source framework for scoring data-source quality and mapping detection coverage onto ATT&CK. |
| **DGA** | Domain generation algorithm: malware generates many pseudo-random domains to find its C2. |
| **Diamond Model** | Intrusion-analysis model linking adversary, capability, infrastructure and victim. |
| **Diamond ticket** | A legitimately requested TGT decrypted and modified with the krbtgt key, then re-encrypted; harder to spot than a golden ticket because it passes through the normal AS exchange. |
| **Dwell time** | Time between initial compromise and detection. |
| **EDR / XDR / NDR** | Endpoint, extended and network detection and response: agent-based host telemetry, cross-source correlation, and network-sensor analytics respectively. |
| **Emulation vs simulation** | Emulation replays a real adversary's TTPs faithfully; simulation exercises a technique generically (e.g. an Atomic test). Both are valid; label which you did. |
| **Entra ID** | Microsoft's cloud identity platform (formerly Azure AD); source of sign-in, audit and risk logs ([playbook]({{ site.baseurl }}/hunt/playbooks/cloud-identity/)). |
| **ESC1–ESC8** | AD CS escalation paths: ESC1 enrollee-supplied subject, ESC2 Any Purpose EKU, ESC3 enrollment agent, ESC4 template ACL abuse, ESC5 PKI object ACLs, ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2, ESC7 CA ACL abuse, ESC8 NTLM relay to web enrollment. Hunt via 4886/4887 and template changes. |
| **ETW** | Event Tracing for Windows: the kernel-level telemetry bus that Sysmon, EDR and the event logs draw from. |
| **EVTX** | Windows Event Log file format. |
| **False positive / negative** | Alert on benign activity / missed malicious activity. |
| **False-positive rate vs precision** | FP rate = FP/(FP+TN), diluted by huge benign volume; precision = TP/(TP+FP), what the analyst experiences. Report precision and daily alert count. |
| **First-seen analysis** | Flagging an entity-attribute pair absent from the history window: first time user X logged on to host Y. |
| **gMSA** | Group Managed Service Account: AD-managed, auto-rotated 240-character password; removes Kerberoasting risk for the service. |
| **Golden ticket** | Forged Kerberos TGT signed with the krbtgt hash (T1558.001); grants any identity until krbtgt is reset twice. |
| **HMM** | Hunting Maturity Model (David Bianco): HMM0 initial through HMM4 leading. |
| **Hunt backlog** | Prioritised list of hypotheses waiting to be hunted, with trigger, data needs and expected output ([template]({{ site.baseurl }}/templates/#hunt-backlog)). |
| **Hunt hypothesis** | A testable statement about adversary activity that guides a hunt: "if X, we would see Y in Z." |
| **Impossible travel** | Sign-ins from locations too far apart for the elapsed time; common FP cause is VPN or mobile egress. |
| **IOA** | Indicator of attack: a behaviour pattern suggesting malicious intent, independent of specific tools. |
| **IOC** | Indicator of compromise: an artefact such as hash, IP or domain. |
| **JA3 / JA3S / JARM** | Fingerprints of TLS client / server handshakes (JARM actively probes servers); useful for C2 pivoting. |
| **JEA** | Just Enough Administration: constrained PowerShell endpoints that expose only approved commands. |
| **Kerberoasting** | Requesting service tickets for SPN accounts and cracking them offline (T1558.003; [playbook]({{ site.baseurl }}/hunt/playbooks/kerberoasting/)). |
| **Kill chain** | Lockheed Martin's seven-stage intrusion model (recon through actions on objectives); useful for "where in the chain can we see this?" |
| **KQL** | Kusto Query Language: used by Microsoft Sentinel, Defender advanced hunting and Azure Data Explorer. |
| **LAPS** | Local Administrator Password Solution: unique, rotated local admin passwords per host; kills pass-the-hash lateral movement with the local admin hash. |
| **Lateral movement** | Moving between hosts using valid credentials or remote execution (SMB, WMI, WinRM, RDP, PsExec-style services; [playbook]({{ site.baseurl }}/hunt/playbooks/lateral-movement/)). |
| **LOLBin / LOLBAS** | Living-off-the-land binary / binaries and scripts: legitimate OS tools abused by attackers ([playbook]({{ site.baseurl }}/hunt/playbooks/lolbin-proxy-execution/)). |
| **LOTL / LotL** | Living off the land: operating with built-in tools and valid credentials rather than malware. |
| **LSASS** | Local Security Authority Subsystem Service; holds credential material in memory ([playbook]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/)). |
| **M-ATH** | Model-Assisted Threat Hunting (PEAK). |
| **MFA fatigue** | Repeated push prompts until the user approves one; look for many denied/ignored MFA attempts followed by a success. |
| **MISP / OpenCTI** | Open-source threat intelligence platforms for sharing indicators (MISP) and modelling actors, campaigns and TTPs in STIX (OpenCTI). |
| **MOTW** | Mark of the Web: the Zone.Identifier alternate data stream on downloaded files that triggers SmartScreen and Office Protected View; attackers use containers (ISO, VHD) to strip it. |
| **MTTD / MTTR** | Mean time to detect / to respond (or remediate). Hunting aims to cut MTTD for threats detections miss. |
| **NTDS.dit** | The Active Directory database file containing password hashes. |
| **NTLM relay** | Forwarding a captured NTLM authentication to another service without cracking it; mitigated by SMB/LDAP signing and EPA. |
| **OAuth consent grant** | A user (or attacker) authorising a third-party app to access their cloud data; illicit consent is persistent, token-based access that survives password resets. |
| **OCSF / ECS / ASIM / CIM** | Common data schemas (Open Cybersecurity Schema Framework, Elastic Common Schema, Advanced Security Information Model, Common Information Model). |
| **PEAK** | Prepare, Execute, Act with Knowledge: Splunk SURGe hunting framework. |
| **Pivot** | Using one finding to search for related activity (same host, user, IP, hash). |
| **PKINIT** | Kerberos pre-authentication using certificates instead of passwords; what makes AD CS abuse a credential-theft path. |
| **PtH / PtT** | Pass-the-hash (authenticate with an NTLM hash, T1550.002) / pass-the-ticket (reuse a stolen Kerberos ticket, T1550.003). |
| **Purple teaming** | Red and blue working together in real time: run a technique, check what the data shows, fix, repeat ([lab]({{ site.baseurl }}/labs/emulate-and-detect/)). |
| **Pyramid of Pain** | Model ranking indicator types by cost to the adversary when detected. |
| **Rule lifecycle** | Idea → draft → test → deploy → tune → review → retire; each stage has an owner and evidence ([chapter 7]({{ site.baseurl }}/learn/detection-engineering/)). |
| **Session hijacking** | Reusing a stolen browser or cloud session cookie/token to act as the user without re-authenticating. |
| **SIEM** | Security information and event management: central log store, search and correlation. |
| **Sigma** | Open, vendor-neutral detection rule format for log events, converted to SIEM queries by pySigma. |
| **Silver ticket** | Forged Kerberos service ticket signed with a service account's hash (T1558.002); no DC contact, so 4769 is absent. |
| **SOAR** | Security orchestration, automation and response. |
| **SPL** | Splunk Search Processing Language. |
| **SPN** | Service Principal Name: identifies a service instance for Kerberos. |
| **Stacking** | Counting values of a field and examining the rare ones ("long tail"). |
| **STIX / TAXII** | Structured threat intelligence format / transport protocol for sharing it. |
| **Sysmon** | Microsoft Sysinternals service/driver providing detailed Windows endpoint telemetry. |
| **TaHiTI** | Targeted Hunting integrating Threat Intelligence methodology. |
| **Tiering model** | Separating administrative identities and systems into tiers (Tier 0 = domain controllers and identity) so credentials never flow downward. |
| **Time-box** | A fixed duration for a hunt (typically 1–3 days) after which the result is documented regardless; prevents open-ended browsing. |
| **TLP** | Traffic Light Protocol: sharing restrictions on intel (CLEAR, GREEN, AMBER, AMBER+STRICT, RED). |
| **Token theft** | Stealing an access/refresh token or Windows access token to act as a user; bypasses MFA already satisfied. |
| **TTPs** | Tactics, techniques and procedures. |
| **UEBA** | User and entity behaviour analytics. |
| **Unified Kill Chain** | Paul Pols' 18-phase model combining the Lockheed kill chain with ATT&CK; covers the in-network loop the original lacks. |
| **Web shell** | Script placed on a web server that executes attacker commands via HTTP (T1505.003); seen as the web server process spawning shells ([playbook]({{ site.baseurl }}/hunt/playbooks/web-shells/)). |
| **WEF / WEC** | Windows Event Forwarding / Windows Event Collector: agentless, subscription-based log centralisation. |
| **Zeek** | Network security monitor producing rich protocol logs (formerly Bro). |
