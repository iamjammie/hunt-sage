---
title: "Learn Threat Hunting"
permalink: /learn/
excerpt: "A structured path from first principles to running a hunt program. Read in order, or jump to what you need."
toc: false
---

This is the theory half of Hunt-Sage. Each chapter is short, practical and ends with a pointer to the hands-on material in [Hunt]({{ site.baseurl }}/hunt/), [Cheat Sheets]({{ site.baseurl }}/cheatsheets/) and [Labs]({{ site.baseurl }}/labs/).

## The learning path

| # | Chapter | You will be able to... |
|---|---------|------------------------|
| 1 | [What is threat hunting?]({{ site.baseurl }}/learn/what-is-threat-hunting/) | Explain hunting vs. detection vs. IR, and when hunting is worth doing |
| 2 | [The hunting process & frameworks]({{ site.baseurl }}/learn/hunting-process-and-frameworks/) | Run a hunt end to end using the hunt loop, PEAK or TaHiTI |
| 3 | [Hypotheses & threat intelligence]({{ site.baseurl }}/learn/hypotheses-and-intelligence/) | Write a testable hypothesis from intel, ATT&CK or an anomaly |
| 4 | [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) | Map a technique to the logs that can see it, and find your blind spots |
| 5 | [Hunting techniques]({{ site.baseurl }}/learn/hunting-techniques/) | Apply searching, stacking, baselining, clustering and timing analysis |
| 6 | [Adversary tradecraft]({{ site.baseurl }}/learn/adversary-tradecraft/) | Think in kill chains and ATT&CK; know what attackers do after they land |
| 7 | [Detection engineering]({{ site.baseurl }}/learn/detection-engineering/) | Turn a finished hunt into a tested, tuned, versioned detection |
| 8 | [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/) | Staff, measure and mature hunting in your organisation |
| - | [Glossary]({{ site.baseurl }}/learn/glossary/) | Decode the jargon |

## Suggested tracks

**Analyst track (2 weeks, ~1 hr/day)**
1. Chapters 1-4, then build the [lab]({{ site.baseurl }}/labs/).
2. Run three playbooks in the lab: [PowerShell]({{ site.baseurl }}/hunt/playbooks/powershell-abuse/), [persistence]({{ site.baseurl }}/hunt/playbooks/persistence/), [lateral movement]({{ site.baseurl }}/hunt/playbooks/lateral-movement/).
3. Chapter 5, then hunt the [Argon Nexus CTF]({{ site.baseurl }}/ctf/argon-nexus/).

**Detection engineer track**
1. Chapters 3, 4, 7.
2. Pick five [Sigma rules]({{ site.baseurl }}/research/sigma/), emulate each with [Atomic Red Team]({{ site.baseurl }}/labs/emulate-and-detect/), tune against your lab baseline.

**Hunt lead track**
1. Chapters 1, 2, 6, 8.
2. Adopt the [hunt templates]({{ site.baseurl }}/templates/) and start a hunt backlog from the [ATT&CK coverage map]({{ site.baseurl }}/research/mitre-mapping/).

## How to use this material responsibly

Everything here is for **defensive** use in environments you own or are authorised to test. Run attack emulation only in isolated labs or with written approval.
