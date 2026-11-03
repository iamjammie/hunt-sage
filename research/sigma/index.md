---
title: "Sigma Detection Rules"
permalink: /research/sigma/
layout: single
toc: true
toc_label: "On this page"
toc_sticky: true
excerpt: "Vendor-neutral Sigma rules authored by Hunt-Sage, each mapped to ATT&CK with documented false positives and validated in CI."
---

All rules follow the [Sigma specification](https://sigmahq.io/docs/basics/rules.html) and convert to your SIEM's query language with [pySigma](https://github.com/SigmaHQ/pySigma) backends. Every pull request runs `scripts/validate_rules.py`, which checks metadata, ATT&CK tags, uniqueness of ids, and that each rule converts cleanly with the Splunk and Kusto backends. The tables below are generated from the rule files, so they cannot drift.

> **Status** follows the criteria in the [detection engineering notes]({{ site.baseurl }}/research/mitre-detection-engineering/#rule-status-criteria-used-in-this-repo): `experimental` (untested outside the author's lab), `test` (lab-validated, false positives enumerated), `stable` (30+ days in production with measured precision). **Tune before alerting in production.** Each rule links to the playbook that hunts the same behaviour on the [coverage map]({{ site.baseurl }}/research/mitre-mapping/).

## All rules

{% include sigma-rules-table.html %}

## How to use these rules

Install pySigma and the backend for your platform:

```bash
pip install sigma-cli
sigma plugin install splunk
sigma plugin install kusto         # Microsoft Sentinel / Defender KQL
sigma plugin install elasticsearch
sigma plugin install sysmon        # Sysmon field-name pipeline
```

Convert a rule:

```bash
# Splunk
sigma convert -t splunk -p splunk_windows research/sigma/T1490-shadow-copy-deletion.yml

# Microsoft Sentinel / KQL
sigma convert -t kusto -p microsoft_xdr research/sigma/T1490-shadow-copy-deletion.yml

# Elastic (Lucene) with ECS-style pipeline
sigma convert -t lucene -p ecs_windows research/sigma/T1490-shadow-copy-deletion.yml
```

Pipelines map generic Sigma fields (`Image`, `CommandLine`) to your schema; choose the one that matches how your data is ingested. Always test the converted query on sample data. Run `sigma check research/sigma/` to lint locally.

### Fields that do not survive conversion

Some rules use Sysmon-only fields (`Signed`, `SignatureStatus`, `GrantedAccess`, `StartFunction`). Backends without an equivalent field drop that clause, so the converted query can be broader than the rule. Each affected rule says so in its description; check the output before deploying.

### Notes on the older rules

The first five rules (`T1059.001`, `T1078.002`, `T1140`, `T1546.003`, `T1550.002`) also carry extra non-standard keys (`hunt_notes`, `kql_equivalent`, `spl_equivalent`). Converters ignore them; they remain for analyst reference. The newer rules keep the file standard and put hunt queries in the [playbooks]({{ site.baseurl }}/hunt/).

## Test every rule

1. **Positive:** emulate with [Atomic Red Team]({{ site.baseurl }}/labs/emulate-and-detect/) and confirm the alert.
2. **Negative:** replay representative benign logs and count hits.
3. **Tune** with narrow, documented exclusions, then record the result in the [detection backlog]({{ site.baseurl }}/templates/).

---

*[Suggest a rule or submit your own →](https://github.com/iamjammie/hunt-sage/blob/main/CONTRIBUTING.md)*
