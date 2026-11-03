---
title: "Hunt Packs"
permalink: /hunt/packs/
excerpt: "Scenario-driven campaigns that chain the playbooks into a one-week hunt: ransomware, AD domain dominance, BEC, web compromise, insider data theft and Linux intrusion."
classes: wide
toc: false
---

A playbook answers *"how do I hunt for Kerberoasting?"*. A **hunt pack** answers *"an affiliate is probably in our network right now; what do we do this week?"*. Each pack takes one intrusion story, lays out the kill chain phase by phase, names the hypotheses and playbook steps that cover each phase, and gives you a five-day plan, a pivot map (if you find X, look at Y next), the detections that should already be live, and the tabletop questions a hunt lead should ask.

Packs are for campaigns rather than single hunts: after a relevant intel report, during a sector-wide wave, as post-incident assurance, or as a quarterly exercise. They assume you have run at least a couple of the underlying playbooks before.

{% assign packs = site.pages | where: "pack", true | sort: "title" %}
<div class="hs-cards hs-no-attack-links">
{% for pk in packs %}
  <article class="hs-card hs-card--pack">
    <h3><a href="{{ pk.permalink | relative_url }}">{{ pk.title | remove_first: "Hunt Pack: " }}</a></h3>
    <p class="hs-card__excerpt">{{ pk.excerpt }}</p>
    <p class="hs-card__meta"><strong>{{ pk.playbooks | size }}</strong> playbooks · <strong>{{ pk.attack | size }}</strong> techniques · {{ pk.duration }}</p>
    <p class="hs-card__chips">{% for slug in pk.playbooks limit: 6 %}<a class="hs-chip hs-chip--muted" href="{{ '/hunt/playbooks/' | append: slug | append: '/' | relative_url }}">{{ slug | replace: "-", " " }}</a> {% endfor %}{% if pk.playbooks.size > 6 %}<span class="hs-chip">+{{ pk.playbooks.size | minus: 6 }} more</span>{% endif %}</p>
  </article>
{% endfor %}
</div>

## How a pack week runs

| Day | Theme | What happens |
|---|---|---|
| 1 | Scope and telemetry | Confirm the crown jewels in scope, check every must-have log source in the pack is present for the window, write the hypothesis cards |
| 2-3 | Early phases | Initial access, execution, discovery and credential access steps; stack first, then read the long tail |
| 4 | Late phases and pivots | Lateral movement, persistence, exfiltration and impact precursors; follow every pivot the earlier days opened |
| 5 | Close | Hunt report, false-positive notes, visibility gaps, detections handed to engineering, backlog updated |

Two analysts can run most packs in a week; one analyst should take two. Keep the time-box: a pack that is not finished is reported as partially covered, not extended.

## Writing your own pack

Copy any pack's front matter (`pack: true`, `playbooks: [...]`, `attack: [...]`, `duration`) and sections. The `playbooks` list drives the chips at the top and the "part of these hunt packs" link on each playbook; the `attack` list puts the pack on the [coverage map]({{ site.baseurl }}/research/mitre-mapping/). Propose it through a pull request; see [CONTRIBUTING](https://github.com/iamjammie/hunt-sage/blob/main/CONTRIBUTING.md).

## Related

- [Playbook library]({{ site.baseurl }}/hunt/) and the [playbook finder]({{ site.baseurl }}/hunt/finder/) to check which steps your telemetry supports
- [Hypothesis library]({{ site.baseurl }}/hunt/hypotheses/) for the H-ids the packs reference
- [Templates]({{ site.baseurl }}/templates/): hypothesis card, hunt report, IR hand-off
- [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/) for the kill-chain thinking behind the packs
