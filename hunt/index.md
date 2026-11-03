---
title: "Hunt Playbook Library"
permalink: /hunt/
excerpt: "Twenty-five field-ready hunt playbooks: hypothesis, data, queries (KQL + SPL), triage, false positives, escalation, validation and hardening. Plus hunt packs that chain them and a finder that matches them to your telemetry."
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

<div class="hs-cards hs-cards--3 hs-no-attack-links">
  <article class="hs-card"><h3><a href="{{ '/hunt/finder/' | relative_url }}">Playbook finder</a></h3><p class="hs-card__excerpt">Tick the telemetry you collect; see which playbooks you can run today and which log source would unlock the most hunts.</p></article>
  <article class="hs-card"><h3><a href="{{ '/hunt/packs/' | relative_url }}">Hunt packs</a></h3><p class="hs-card__excerpt">{{ site.data.coverage.summary.packs }} scenario campaigns (ransomware, AD dominance, BEC, web compromise, insider theft, Linux intrusion) that chain the playbooks into a one-week plan.</p></article>
  <article class="hs-card"><h3><a href="{{ '/hunt/hypotheses/' | relative_url }}">Hypothesis library</a></h3><p class="hs-card__excerpt">{{ site.data.coverage.summary.hypotheses }} numbered hypotheses mapped to ATT&CK, data and playbook, with a live filter. Query patterns live in the <a href="{{ '/hunt/query-index/' | relative_url }}">query index</a>.</p></article>
</div>

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

The `Data` column uses the keys below; the same keys drive the [playbook finder]({{ site.baseurl }}/hunt/finder/).

| Key | Source | What it covers |
|---|---|---|
{% for ds in site.data.datasources %}| `{{ ds.key }}` | [{{ ds.label }}]({{ ds.how | relative_url }}) | {{ ds.description }} |
{% endfor %}

## Suggested first five hunts

New to the library? Run these in order; each one teaches a technique the next one relies on. If you are not sure your logs support them, the [finder]({{ site.baseurl }}/hunt/finder/) will tell you.

1. [PowerShell abuse]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/): high-yield, simple data.
2. [Persistence]({{ site.baseurl }}/hunt/playbooks/persistence/): stacking is easy and instructive.
3. [Kerberoasting]({{ site.baseurl }}/hunt/playbooks/kerberoasting/): few events, high-signal on a DC.
4. [LSASS credential dumping]({{ site.baseurl }}/hunt/playbooks/lsass-credential-dumping/): learn about access masks.
5. [Lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/): ties it all together.

Then go deeper: [AD discovery & BloodHound]({{ site.baseurl }}/hunt/playbooks/ad-discovery-bloodhound/) to catch the recon that precedes all of the above, [AD CS abuse]({{ site.baseurl }}/hunt/playbooks/adcs-abuse/) for the privilege-escalation path most environments have never audited, and [business email compromise]({{ site.baseurl }}/hunt/playbooks/business-email-compromise/) for the intrusion that never touches an endpoint. When you are ready for a campaign, pick a [hunt pack]({{ site.baseurl }}/hunt/packs/).

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

- [Hunt packs]({{ site.baseurl }}/hunt/packs/), the [playbook finder]({{ site.baseurl }}/hunt/finder/), the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/) and the [query index]({{ site.baseurl }}/hunt/query-index/)
- [Sigma rules]({{ site.baseurl }}/research/sigma/) that productionise these hunts
- [Cheat sheets]({{ site.baseurl }}/cheatsheets/) for event IDs and query syntax
- [Hunt report template]({{ site.baseurl }}/templates/#hunt-report)
- Blog deep-dives: [Fundamentals]({{ site.baseurl }}/blog/threat-hunting-fundamentals/), [Pass-the-hash]({{ site.baseurl }}/blog/hunting-lateral-movement-pass-the-hash/), [C2 beaconing]({{ site.baseurl }}/blog/hunting-c2-beaconing/), [Persistence]({{ site.baseurl }}/blog/hunting-persistence/), [Stacking and baselining]({{ site.baseurl }}/blog/stacking-and-baselining-worked-example/)
