---
title: "Practice Datasets & Ranges"
permalink: /labs/datasets/
excerpt: "Pre-recorded attack telemetry, packet captures and hosted ranges for when you have no lab."
---

Verify licence terms and each project's current status before use. Treat all downloaded malware-related data as untrusted (analyse in an isolated environment).

## Endpoint / Windows telemetry

| Dataset | What it is |
|---|---|
| **OTRF Security-Datasets** (Mordor) | JSON logs from simulated ATT&CK techniques in Windows labs (Sysmon, Security) mapped to techniques |
| **EVTX-ATTACK-SAMPLES** (sbousseaden) | `.evtx` files per ATT&CK technique; ideal for Chainsaw/Hayabusa practice |
| **Splunk Attack Data** | Replayable datasets used by Splunk Security Content detections |
| **Boss of the SOC (BOTS)** | Splunk's CTF datasets (v1-v3) with realistic multi-source scenarios |
| **Sigma test logs / `sigma-rules-testing`** | Evidence for rule testing |
| **The DFIR Report** (articles) | Detailed intrusion write-ups with IOCs and commands you can recreate |

## Network

| Dataset | What it is |
|---|---|
| **Malware-Traffic-Analysis.net** | PCAPs with exercises (by Brad Duncan) |
| **Security Onion / Zeek sample pcaps** | Teaching captures |
| **CIC-IDS / UNSW-NB15** | Academic network-flow datasets (labelled) for statistical/ML experiments |
| **Wireshark sample captures** | Protocol examples |

## Cloud

| Dataset | What it is |
|---|---|
| **flaws.cloud / flaws2.cloud** | AWS security challenges |
| **CloudGoat / Stratus Red Team** | Deploy vulnerable AWS scenarios and emulate attacks yourself |
| **AWS CloudTrail sample logs / `invictus-ir` datasets** | Sample CloudTrail and M365 logs |

## Ranges and platforms

| Resource | What it is |
|---|---|
| **Splunk Attack Range** | Deploys a lab with attack simulation (Atomic Red Team) and Splunk |
| **DetectionLab / Ludus / GOAD** | Automated AD labs |
| **CyberDefenders, BlueTeamLabs.online, LetsDefend, TryHackMe SOC paths, RangeForce** | Hosted blue-team challenges (some free tiers) |
| **MITRE Caldera** | Automated adversary emulation platform |

## Tools to analyse offline logs

| Tool | Use |
|---|---|
| **Chainsaw** | Fast hunt and Sigma matching over EVTX |
| **Hayabusa** | Sigma-based EVTX timeline and threat hunting |
| **Zircolite** | Sigma on EVTX/JSON |
| **EvtxECmd + Timeline Explorer** | EVTX parsing and timeline analysis |
| **Velociraptor offline collector** | Collect artefacts without a server |
| **Zeek / RITA** | PCAP → logs → beacon scoring |
| **Jupyter + pandas** | Custom statistical hunts |

### Quick start: hunt an EVTX sample with Chainsaw

```bash
# 1. Get chainsaw and Sigma rules from their official repos
# 2. Hunt with Sigma rules and the Chainsaw mapping
chainsaw hunt ./evtx-samples/ -s ./sigma/ --mapping ./mappings/sigma-event-logs-all.yml --level high

# 3. Search for a string across logs
chainsaw search "mimikatz" -i ./evtx-samples/
```

Our own rules in [`research/sigma/`]({{ site.baseurl }}/research/sigma/) can be fed to Chainsaw, Hayabusa-compatible converters or Zircolite as additional rule sources.
