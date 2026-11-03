---
layout: splash
title: "Hunt-Sage"
permalink: /
header:
  overlay_color: "#0A0F1F"
  overlay_filter: 0.35
  overlay_image: /assets/images/hero-bg.png
  actions:
    - label: "Start learning"
      url: "/learn/"
    - label: "Open the playbooks"
      url: "/hunt/"
    - label: "What can I hunt with my data?"
      url: "/hunt/finder/"
excerpt: "The one-stop threat hunting knowledge hub: theory, hunt playbooks, scenario hunt packs, a hypothesis library, cheat sheets, labs and CI-validated Sigma rules, all mapped to MITRE ATT&CK. *Every threat leaves a trace. The hunt never stops.*"
feature_row:
  - title: "Learn: the theory"
    excerpt: "Nine short chapters and a glossary: what hunting is, the hunt loop, PEAK / TaHiTI / Sqrrl, hypotheses, intelligence, telemetry, statistical techniques, detection engineering, programme metrics, careers and 40 interview questions. Track what you have read; score your team with the maturity self-assessment."
    url: "/learn/"
    btn_label: "Follow the path"
    btn_class: "btn--primary"
  - title: "Hunt: the practice"
    excerpt: "Playbooks with hypothesis, telemetry, KQL + SPL queries, triage, false positives, escalation criteria and hardening, from phishing and UAC bypass to Kerberoasting, AD CS, BEC, Kubernetes and macOS. Chain them with the hunt packs; match them to your logs with the finder."
    url: "/hunt/"
    btn_label: "Open the library"
    btn_class: "btn--primary"
  - title: "Reference: cheat sheets"
    excerpt: "Windows and Sysmon event IDs, Linux auditd, KQL, SPL, Zeek, LOLBins and AD attack artefacts. Read them online with a live filter (type an event id, everything else disappears) or print the watermarked PDFs."
    url: "/cheatsheets/"
    btn_label: "Grab a sheet"
    btn_class: "btn--primary"
feature_row2:
  - title: "Labs & datasets"
    excerpt: "Build a hunting lab in an afternoon, emulate techniques with Atomic Red Team, then find yourself in the logs. Public datasets for when you have no lab."
    url: "/labs/"
    btn_label: "Build the lab"
  - title: "Detection content"
    excerpt: "Sigma rules validated in CI on every push, an ATT&CK coverage heatmap generated from the content, an importable Navigator layer, and detection-engineering notes."
    url: "/research/"
    btn_label: "Browse research"
  - title: "Templates & resources"
    excerpt: "Hunt hypothesis card, hunt report, backlog, data-source assessment and IR hand-off, plus curated tools, rule repositories, reports, podcasts, courses and communities."
    url: "/templates/"
    btn_label: "Get templates"
---

<ol class="hs-loop hs-no-attack-links" aria-label="The Hunt-Sage loop">
  <li><a href="{{ '/learn/' | relative_url }}">Learn the theory</a><small>Hunting vs detection, the hunt loop, how to think in ATT&CK</small></li>
  <li><a href="{{ '/hunt/hypotheses/' | relative_url }}">Pick a hypothesis</a><small>{{ site.data.coverage.summary.hypotheses }} testable "if X, then Y in Z" statements</small></li>
  <li><a href="{{ '/hunt/finder/' | relative_url }}">Check your telemetry</a><small>The finder shows what your logs can support</small></li>
  <li><a href="{{ '/hunt/' | relative_url }}">Run a playbook</a><small>KQL + SPL, triage, false positives, escalation</small></li>
  <li><a href="{{ '/labs/emulate-and-detect/' | relative_url }}">Prove it in the lab</a><small>Emulate the technique, find it in the logs</small></li>
  <li><a href="{{ '/research/sigma/' | relative_url }}">Ship the detection</a><small>Sigma rule, tuned, versioned, on the coverage map</small></li>
</ol>
<p class="hs-loop__caption">Whether you are a SOC analyst making a first hypothesis or a hunt lead building a programme, the loop is the same; every page on this site sits on one of its steps.</p>

<ul class="hs-stats" aria-label="What is on this site">
  <li><strong>{{ site.data.coverage.summary.playbooks }}</strong><span>hunt playbooks (KQL + SPL)</span></li>
  <li><strong>{{ site.data.coverage.summary.packs }}</strong><span>scenario hunt packs</span></li>
  <li><strong>{{ site.data.coverage.summary.hypotheses }}</strong><span>ready-made hypotheses</span></li>
  <li><strong>{{ site.data.coverage.summary.rules }}</strong><span>Sigma rules, CI-validated</span></li>
  <li><strong>{{ site.data.coverage.summary.techniques }}</strong><span>ATT&CK techniques mapped</span></li>
  <li><strong>{{ site.data.coverage.summary.cheatsheets }}</strong><span>cheat sheets, web + PDF</span></li>
</ul>

{% include feature_row %}

<section class="hs-home-section hs-no-attack-links">
<h2 id="hunt-packs">Hunt packs: a week-long campaign, phase by phase</h2>
<p>A playbook answers "how do I hunt Kerberoasting?". A pack answers "an affiliate is probably inside right now; what do we do this week?". Each one chains the playbooks along a kill chain with a five-day plan, pivot map and the detections that should already be live.</p>
{% assign packs = site.pages | where: "pack", true | sort: "title" %}
<div class="hs-cards">
{% for pk in packs %}
  <article class="hs-card hs-card--pack">
    <h3><a href="{{ pk.permalink | relative_url }}">{{ pk.title | remove_first: "Hunt Pack: " }}</a></h3>
    <p class="hs-card__excerpt">{{ pk.excerpt }}</p>
    <p class="hs-card__meta"><strong>{{ pk.playbooks | size }}</strong> playbooks · <strong>{{ pk.attack | size }}</strong> techniques</p>
  </article>
{% endfor %}
</div>
</section>

{% include feature_row id="feature_row2" %}

## Pick your starting point

| If you are... | Start with |
|---|---|
| New to hunting | [What is threat hunting?]({{ site.baseurl }}/learn/what-is-threat-hunting/) → [The hunting process]({{ site.baseurl }}/learn/hunting-process-and-frameworks/) |
| A SOC analyst wanting a first real hunt | [PowerShell abuse playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) with the [Windows event ID sheet]({{ site.baseurl }}/cheatsheets/windows-event-ids/) open beside it |
| Not sure which hunts your logs support | [Playbook finder]({{ site.baseurl }}/hunt/finder/) → the "biggest visibility win" it suggests |
| Out of ideas for the next hunt | [Hypothesis library]({{ site.baseurl }}/hunt/hypotheses/) → the playbook-only cells on the [coverage map]({{ site.baseurl }}/research/mitre-mapping/) |
| Responding to an intel report or a sector campaign | [Hunt packs]({{ site.baseurl }}/hunt/packs/): ransomware, AD dominance, BEC, web compromise, insider theft, Linux intrusion |
| Building a lab | [Build a hunting lab]({{ site.baseurl }}/labs/) → [Emulate and detect]({{ site.baseurl }}/labs/emulate-and-detect/) |
| A detection engineer | [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/) → [Sigma rules]({{ site.baseurl }}/research/sigma/) → [Query index]({{ site.baseurl }}/hunt/query-index/) |
| Leading a hunt team | [Maturity self-assessment]({{ site.baseurl }}/learn/maturity-assessment/) → [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/) → [Templates]({{ site.baseurl }}/templates/) |
| Interviewing for a hunting role | [Careers & interview prep]({{ site.baseurl }}/learn/career-and-interviews/) → [Argon Nexus CTF]({{ site.baseurl }}/ctf/argon-nexus/) |

## Latest from the blog

<ul>
{% for post in site.posts limit:4 %}
  <li><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a> <span class="page__meta">{{ post.date | date: "%b %Y" }}</span></li>
{% endfor %}
</ul>

<p><a href="{{ site.baseurl }}/blog/">All posts</a> · <a href="{{ site.baseurl }}/feed.xml">RSS</a> · <a href="https://github.com/iamjammie/hunt-sage">Source on GitHub</a> · Everything here is for defensive use in environments you own or are authorised to test.</p>
