---
title: "Hunt Playbook Library"
permalink: /hunt/
excerpt: "Twenty field-ready hunt playbooks: hypothesis, data, queries (KQL + SPL), triage, false positives, escalation, validation and hardening."
classes: wide
toc: false
---

Each playbook is a self-contained, repeatable hunt. They follow the same structure so you can run them quickly and compare results:

1. **Hypothesis**: what you believe an adversary would do and what you'd see
2. **Data required**: and how to verify you have it
3. **Hunt steps**: queries in KQL (Microsoft Sentinel / Defender) and SPL (Splunk), simplest to most advanced
4. **Triage**: how to separate true from false positives
5. **Escalation criteria**: when to hand to IR
6. **Validate**: emulate the technique in your [lab]({{ site.baseurl }}/labs/) to prove the query works
7. **Operationalise**: the detection and hardening that make the hunt unnecessary next time

> **Before you start:** confirm the [data is actually being collected]({{ site.baseurl }}/learn/data-and-telemetry/). A query that returns nothing on a missing log source is not a negative result. Query field names vary by platform, parser and add-on version, so treat the queries as well-tested starting points and adapt them to your schema.

Need a hypothesis first? Pick one from the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/). Need a query pattern rather than a full hunt? Use the [query index]({{ site.baseurl }}/hunt/query-index/).

## Playbooks by tactic

{% assign playbooks = site.pages | where_exp: "p", "p.permalink contains '/hunt/playbooks/'" | sort: "title" %}
{% for tactic in site.data.attack.tactics %}{% assign rows = playbooks | where: "tactic", tactic.name %}{% if rows.size > 0 %}
### {{ tactic.name }}

| Playbook | Hunts for | ATT&CK | Data | Difficulty | Time-box |
|---|---|---|---|---|---|
{% for p in rows %}{% assign ids = p.attack | slice: 0, 4 %}| [{{ p.title | remove_first: "Playbook: " }}]({{ site.baseurl }}{{ p.permalink }}) | {{ p.excerpt }} | {{ ids | join: ", " }}{% if p.attack.size > 4 %} +{{ p.attack.size | minus: 4 }}{% endif %} | {{ p.data | join: ", " }} | {% if p.difficulty == 1 %}★☆☆{% elsif p.difficulty == 2 %}★★☆{% else %}★★★{% endif %} | {{ p.timebox }} |
{% endfor %}{% endif %}{% endfor %}

Difficulty reflects analytical complexity and required data, not importance. Playbooks are grouped by their primary tactic; the techniques they cover often span several, see the [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/).

### Data source keys

| Key | Meaning |
|---|---|
| `windows-security` | Windows Security / System event logs (4624, 4688, 4769, 7045, ...) |
| `sysmon` | Sysmon (1, 3, 7, 8, 10, 11, 12/13, 22) |
| `edr` | Any EDR with process, file, registry and network telemetry (Defender tables used as the example) |
| `powershell` | PowerShell script block / module logging (4104, 4103) |
| `dns`, `proxy`, `firewall`, `zeek` | Network telemetry |
| `linux-auditd` | auditd, journald, auth logs |
| `entra-id`, `aws-cloudtrail`, `email` | Identity, cloud and mail telemetry |
| `adcs`, `iis` | Certificate Services and web-server logs |

## Suggested first five hunts

1. [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/): high-yield, simple data.
2. [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/): stacking is easy and instructive.
3. [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/): few events, high-signal on a DC.
4. [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/): learn about access masks.
5. [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/): ties it all together.

Then go deeper: [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) to catch the recon that precedes all of the above, and [AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) for the privilege-escalation path most environments have never audited.

## Run a hunt in 60 minutes

When you only have an hour, use this cut-down loop:

| Minutes | Do |
|---|---|
| 0-5 | Pick a hypothesis ([library]({{ site.baseurl }}/hunt/hypotheses/)) and write it on the [hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card) |
| 5-10 | Confirm the data source exists and has events for the window you care about |
| 10-40 | Run the playbook's first two steps; stack, then look at the long tail |
| 40-50 | Triage the top ten oddities with the playbook's triage table |
| 50-60 | Record findings, false positives and gaps in the [hunt report]({{ site.baseurl }}/templates/#hunt-report); open backlog items |

## Related

- [Hypothesis library]({{ site.baseurl }}/hunt/hypotheses/) and [query index]({{ site.baseurl }}/hunt/query-index/)
- [Sigma rules]({{ site.baseurl }}/research/sigma/) that productionise these hunts
- [Cheat sheets]({{ site.baseurl }}/cheatsheets/) for event IDs and query syntax
- [Hunt report template]({{ site.baseurl }}/templates/#hunt-report)
- Blog deep-dives: [Fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/), [Pass-the-hash]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/), [C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/), [Persistence]({{ site.baseurl }}/blog/hunting-persistence/), [Stacking and baselining]({{ site.baseurl }}/blog/stacking-and-baselining-worked-example/)
