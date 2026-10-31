---
layout: splash
title: "Hunt-Sage"
permalink: /
header:
  overlay_color: "#0A0F1F"
  overlay_filter: 0.4
  actions:
    - label: "Start learning"
      url: "/learn/"
    - label: "Open the playbooks"
      url: "/hunt/"
excerpt: "The one-stop threat hunting knowledge hub: theory, hunt playbooks, cheat sheets, labs and detection content. *Every threat leaves a trace. The hunt never stops.*"
intro:
  - excerpt: "Whether you are a SOC analyst making your first hypothesis or a hunt lead building a program, follow the path: **learn the theory → run a playbook → practise in a lab → ship a detection.**"
feature_row:
  - title: "Learn: theory"
    excerpt: "What hunting is, the hunt loop, PEAK / TaHiTI / Sqrrl, hypotheses, intelligence, data sources, statistical techniques, program metrics."
    url: "/learn/"
    btn_label: "Read the path"
    btn_class: "btn--primary"
  - title: "Hunt: practice"
    excerpt: "14 playbooks, each with hypothesis, data, KQL + SPL queries, triage steps, false positives and escalation criteria."
    url: "/hunt/"
    btn_label: "Open playbooks"
    btn_class: "btn--primary"
  - title: "Cheat sheets"
    excerpt: "Windows & Sysmon event IDs, Linux auditd, KQL, SPL, Zeek, LOLBins, and AD attack artifacts on one page each."
    url: "/cheatsheets/"
    btn_label: "Grab a sheet"
    btn_class: "btn--primary"
feature_row2:
  - title: "Labs & datasets"
    excerpt: "Build a lab in an afternoon, emulate techniques with Atomic Red Team, then find yourself in the logs. Public datasets for when you have no lab."
    url: "/labs/"
    btn_label: "Build the lab"
  - title: "Detection content"
    excerpt: "Sigma rules, an ATT&CK coverage map and detection-engineering notes. Hunts that worked become detections."
    url: "/research/"
    btn_label: "Browse research"
  - title: "Templates & resources"
    excerpt: "Hunt hypothesis, hunt report and backlog templates, plus a curated list of tools, books, courses and communities."
    url: "/templates/"
    btn_label: "Get templates"
---

{% include feature_row id="intro" type="center" %}

{% include feature_row %}

{% include feature_row id="feature_row2" %}

## Pick your starting point

| If you are... | Start with |
|---|---|
| New to hunting | [What is threat hunting?]({{ site.baseurl }}/learn/what-is-threat-hunting/) → [The hunting process]({{ site.baseurl }}/learn/hunting-process-and-frameworks/) |
| A SOC analyst wanting a first real hunt | [PowerShell abuse playbook]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/) and the [Windows event ID sheet]({{ site.baseurl }}/cheatsheets/windows-event-ids.pdf) |
| Building a lab | [Build a hunting lab]({{ site.baseurl }}/labs/) → [Emulate and detect]({{ site.baseurl }}/labs/emulate-and-detect/) |
| A detection engineer | [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/) → [Sigma rules]({{ site.baseurl }}/research/sigma/) |
| Leading a hunt team | [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/) → [Templates]({{ site.baseurl }}/templates/) |
