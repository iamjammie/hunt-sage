---
layout: single
title: "About"
permalink: /about/
author_profile: false
---

## What Hunt-Sage is

Hunt-Sage is a **one-stop threat hunting reference**: the theory you need to think like a hunter, and the practical playbooks, queries, cheat sheets, labs and detection content you need to act like one. It is maintained by [iamjammie](https://github.com/iamjammie) as an open, defensive resource for SOC analysts, threat hunters, detection engineers and the people who lead them.

- 📘 [Learn]({{ site.baseurl }}/learn/): theory, frameworks and methodology, with a [maturity self-assessment]({{ site.baseurl }}/learn/maturity-assessment/)
- 🎯 [Hunt]({{ site.baseurl }}/hunt/): {{ site.data.coverage.summary.playbooks }} field-ready playbooks with KQL and SPL, {{ site.data.coverage.summary.packs }} [scenario hunt packs]({{ site.baseurl }}/hunt/packs/), a [playbook finder]({{ site.baseurl }}/hunt/finder/) that matches hunts to your telemetry, a {{ site.data.coverage.summary.hypotheses }}-hypothesis library and a query index
- 🧾 [Cheat sheets]({{ site.baseurl }}/cheatsheets/) (web + PDF), 🧪 [Labs]({{ site.baseurl }}/labs/), 🧬 [Research]({{ site.baseurl }}/research/): {{ site.data.coverage.summary.rules }} Sigma rules and the generated ATT&CK coverage map
- 📝 [Blog]({{ site.baseurl }}/blog/) and 🚩 [CTF]({{ site.baseurl }}/ctf/): worked examples, case studies and defender-focused challenges

## How it is built

Everything is Markdown, YAML and a little CSS and JavaScript, built with Jekyll and deployed from GitHub Actions. There is no backend, no tracking and no cookies; the interactive tools keep their state in your own browser. Playbooks declare the techniques and telemetry they use in front matter, Sigma rules carry ATT&CK tags, and a build script turns both into the coverage map, so a page can only claim a rule that actually exists.

## Contributing and contact

Contributions and corrections are welcome: playbooks, Sigma rules, hypotheses, fixes. See the [contributing guide](https://github.com/iamjammie/hunt-sage/blob/main/CONTRIBUTING.md), open an [issue](https://github.com/iamjammie/hunt-sage/issues) for problems or ideas. Inaccurate detection guidance is treated as a bug.

## Responsible use

Everything here is for **defensive** purposes in environments you own or are authorised to test. Run attack emulation only in isolated labs or with written approval. Content is © iamjammie; educational and defensive use is permitted with attribution (see the [licence](https://github.com/iamjammie/hunt-sage/blob/main/LICENSE.md)).
