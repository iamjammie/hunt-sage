---
title: "Sigma Detection Rules"
permalink: /research/sigma/
layout: single
toc: true
toc_label: "Rules by Tactic"
excerpt: "Sigma detection rules authored by Hunt-Sage. Each rule includes KQL and SPL equivalents, hunt notes, and ATT&CK mappings."
---

All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to your SIEM's native query language using [sigmac](https://github.com/SigmaHQ/sigma#sigma-converter) or [pySigma](https://github.com/SigmaHQ/pySigma).

---

## Rules Index

### Execution

| Rule | Technique | Level | File |
|------|-----------|-------|------|
| PowerShell Encoded Command | T1059.001 | Medium | [View](/research/sigma/T1059.001-powershell-encoded-command.yml) |

### Persistence

| Rule | Technique | Level | File |
|------|-----------|-------|------|
| WMI Event Subscription | T1546.003 | High | [View](/research/sigma/T1546.003-wmi-event-subscription.yml) |

### Credential Access / Lateral Movement

| Rule | Technique | Level | File |
|------|-----------|-------|------|
| Pass-the-Hash (NTLM Type 3) | T1550.002 | Medium | [View](/research/sigma/T1550.002-pass-the-hash.yml) |

### Defense Evasion

| Rule | Technique | Level | File |
|------|-----------|-------|------|
| CertUtil LOLBin Abuse | T1140 | High | [View](/research/sigma/T1140-certutil-encode-lolbin.yml) |

### Privilege Escalation

| Rule | Technique | Level | File |
|------|-----------|-------|------|
| Service Account Interactive Logon | T1078.002 | High | [View](/research/sigma/T1078.002-service-account-interactive-logon.yml) |

---

## How to Use These Rules

**Convert to KQL (Microsoft Sentinel)**:
```bash
sigmac -t azure-monitor -c sysmon rule.yml
```

**Convert to Splunk SPL**:
```bash
sigmac -t splunk -c splunk-windows rule.yml
```

**Convert to Elastic EQL**:
```bash
sigmac -t es-eql rule.yml
```

Each rule file also contains a `kql_equivalent` and `spl_equivalent` field with manually written, tested queries if you prefer not to use the converter.

---

*[Suggest a rule or submit your own →](https://github.com/iamjammie/hunt-sage/issues)*
