---
title: "Playbook Finder: What Can I Hunt With My Data?"
permalink: /hunt/finder/
excerpt: "Tick the telemetry you collect and the finder sorts every playbook into ready-to-run, partially runnable and not-yet, then tells you which single log source would unlock the most hunts."
classes: wide
toc: false
---

Most hunt ideas die on the same question: *do we even have the logs for that?* This page answers it up front. Tick the data sources you actually collect (not the ones on the roadmap), and every playbook is sorted by whether you can run it today. Your selection is remembered in this browser only; nothing is sent anywhere.

<div id="hs-finder" class="hs-no-attack-links">
  <noscript><p class="notice--warning">The finder needs JavaScript. Without it, use the <a href="{{ '/hunt/' | relative_url }}">playbook library</a>, which lists the data sources for every playbook.</p></noscript>
</div>

{% assign playbooks = site.pages | where_exp: "p", "p.permalink contains '/hunt/playbooks/'" | sort: "title" %}
<script type="application/json" id="hs-finder-data">
{
  "sources": [{% for s in site.data.datasources %}{"key": {{ s.key | jsonify }}, "label": {{ s.label | jsonify }}, "group": {{ s.group | jsonify }}, "description": {{ s.description | jsonify }}, "how": {{ s.how | relative_url | jsonify }}}{% unless forloop.last %},{% endunless %}{% endfor %}],
  "playbooks": [{% for p in playbooks %}{% assign meta = site.data.coverage.playbooks | where: "url", p.permalink | first %}{"title": {{ p.title | remove_first: "Playbook: " | jsonify }}, "url": {{ p.permalink | relative_url | jsonify }}, "excerpt": {{ p.excerpt | jsonify }}, "tactic": {{ p.tactic | jsonify }}, "attack": {{ p.attack | jsonify }}, "difficulty": {{ p.difficulty | jsonify }}, "timebox": {{ p.timebox | jsonify }}, "data": {{ p.data | jsonify }}, "rules": {{ meta.rules | size | default: 0 }}}{% unless forloop.last %},{% endunless %}{% endfor %}]
}
</script>

## How to read the result

- **Ready to run**: every source the playbook needs is one you ticked. Start with the lowest difficulty, set a time-box, and copy the hypothesis into the [hunt hypothesis card]({{ site.baseurl }}/templates/#hunt-hypothesis-card).
- **Partially runnable**: you can run the steps that use the sources you have. The card says what is missing; the steps in each playbook name their source, so skip the ones you cannot feed.
- **Biggest visibility win**: the one log source that would move the most playbooks into "ready". That is usually the best argument for your next onboarding ticket, and the [data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) chapter explains how to enable each source.
- **Needs telemetry you do not have**: not wasted. Record these as visibility gaps in the [data-source assessment template]({{ site.baseurl }}/templates/#data-source-assessment); a gap you know about is already better than one you do not.

Data source keys are the same ones used in the playbook front matter and in the [hypothesis library]({{ site.baseurl }}/hunt/hypotheses/). The list of sources lives in `_data/datasources.yml`, so adding a playbook with a new source is a one-line change.

## Related

- [Playbook library]({{ site.baseurl }}/hunt/): all playbooks by tactic
- [Hunt packs]({{ site.baseurl }}/hunt/packs/): playbooks chained into end-to-end scenarios
- [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/): where the content is thin
- [Hunt maturity self-assessment]({{ site.baseurl }}/learn/maturity-assessment/): where your programme is thin
