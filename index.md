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
    - label: "Grab a cheat sheet"
      url: "/cheatsheets/"
excerpt: "The one-stop threat hunting knowledge hub: theory, hunt playbooks, a hypothesis library, cheat sheets, labs and ATT&CK-mapped detection content. *Every threat leaves a trace. The hunt never stops.*"
intro:
  - excerpt: "Whether you are a SOC analyst making your first hypothesis or a hunt lead building a program, follow the path: **learn the theory → pick a hypothesis → run a playbook → practise in a lab → ship a detection.**"
feature_row:
  - title: "Learn: theory"
    excerpt: "Nine chapters: what hunting is, the hunt loop, PEAK / TaHiTI / Sqrrl, hypotheses, intelligence, data sources, statistical techniques, program metrics, careers and interviews."
    url: "/learn/"
    btn_label: "Read the path"
    btn_class: "btn--primary"
  - title: "Hunt: practice"
    excerpt: "20 playbooks with hypothesis, data, KQL + SPL queries, triage, false positives and escalation criteria, plus a 100-hypothesis backlog and a query index."
    url: "/hunt/"
    btn_label: "Open playbooks"
    btn_class: "btn--primary"
  - title: "Cheat sheets"
    excerpt: "Windows & Sysmon event IDs, Linux auditd, KQL, SPL, Zeek, LOLBins, and AD attack artifacts: one printable PDF each."
    url: "/cheatsheets/"
    btn_label: "Grab a sheet"
    btn_class: "btn--primary"
feature_row2:
  - title: "Labs & datasets"
    excerpt: "Build a lab in an afternoon, emulate techniques with Atomic Red Team, then find yourself in the logs. Public datasets for when you have no lab."
    url: "/labs/"
    btn_label: "Build the lab"
  - title: "Detection content"
    excerpt: "Sigma rules validated in CI, an ATT&CK coverage heatmap generated from the content, a Navigator layer you can overlay on your own, and detection-engineering notes."
    url: "/research/"
    btn_label: "Browse research"
  - title: "Templates & resources"
    excerpt: "Hunt hypothesis, hunt report and backlog templates, plus a curated list of tools, rule repositories, reports, podcasts, courses and communities."
    url: "/templates/"
    btn_label: "Get templates"
---

{% include feature_row id="intro" type="center" %}

<ul class="hs-stats" aria-label="What is on this site">
  <li><strong>{{ site.data.coverage.summary.playbooks }}</strong><span>hunt playbooks (KQL + SPL)</span></li>
  <li><strong>{{ site.data.coverage.summary.rules }}</strong><span>Sigma rules, CI-validated</span></li>
  <li><strong>{{ site.data.coverage.summary.techniques }}</strong><span>ATT&CK techniques mapped</span></li>
  <li><strong>8</strong><span>printable cheat sheets</span></li>
  <li><strong>100+</strong><span>ready-made hunt hypotheses</span></li>
</ul>

{% include feature_row %}

{% include feature_row id="feature_row2" %}

## Pick your starting point

| If you are... | Start with |
|---|---|
| New to hunting | [What is threat hunting?]({{ site.baseurl }}/learn/what-is-threat-hunting/) → [The hunting process]({{ site.baseurl }}/learn/hunting-process-and-frameworks/) |
| A SOC analyst wanting a first real hunt | [PowerShell abuse playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) and the [Windows event ID sheet]({{ site.baseurl }}/cheatsheets/windows-event-ids.pdf) |
| Out of ideas for the next hunt | [Hypothesis library]({{ site.baseurl }}/hunt/hypotheses/) → the dashed cells on the [coverage map]({{ site.baseurl }}/research/mitre-mapping/) |
| Building a lab | [Build a hunting lab]({{ site.baseurl }}/labs/) → [Emulate and detect]({{ site.baseurl }}/labs/emulate-and-detect/) |
| A detection engineer | [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/) → [Sigma rules]({{ site.baseurl }}/research/sigma/) → [Query index]({{ site.baseurl }}/hunt/query-index/) |
| Leading a hunt team | [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/) → [Templates]({{ site.baseurl }}/templates/) |
| Interviewing for a hunting role | [Careers & interview prep]({{ site.baseurl }}/learn/career-and-interviews/) → [Argon Nexus CTF]({{ site.baseurl }}/ctf/argon-nexus/) |

## Latest from the blog

<ul>
{% for post in site.posts limit:4 %}
  <li><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a> <span class="page__meta">{{ post.date | date: "%b %Y" }}</span></li>
{% endfor %}
</ul>

<p><a href="{{ site.baseurl }}/blog/">All posts</a> · <a href="{{ site.baseurl }}/feed.xml">RSS</a> · <a href="https://github.com/iamjammie/hunt-sage">Source on GitHub</a></p>
