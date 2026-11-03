---
title: "Hunt Maturity Self-Assessment"
permalink: /learn/maturity-assessment/
excerpt: "Twenty questions, ten minutes: score your hunting capability across data, process, people, tooling and outcomes, and get a prioritised reading list."
classes: wide
toc: false
track_progress: false
---

Sqrrl's Hunting Maturity Model (HMM) describes five levels, from **HMM0 Initial** (alert-driven, no hunting) to **HMM4 Leading** (hunting is routine, automated where it can be, and feeds detection engineering). The level is useful, but the dimensions behind it are more useful: a team can have excellent data and no process, or a great process starved of telemetry. This assessment scores five dimensions separately and tells you which chapter to read next.

Pick the statement that describes your team **today**, not the plan. Answers stay in this browser only (nothing is sent anywhere), so you can come back and re-score next quarter. The scorecard updates as you answer and can be copied as Markdown into a [hunt programme report]({{ site.baseurl }}/templates/#hunt-report).

<div id="hs-assess" class="hs-no-attack-links">
  <noscript><p class="notice--warning">The assessment needs JavaScript. The five dimensions and the maturity levels are described in <a href="{{ '/learn/building-a-hunt-program/' | relative_url }}">Building a hunt program</a>.</p></noscript>
</div>

<script type="application/json" id="hs-assess-data">
{
  "levels": ["HMM0 Initial", "HMM1 Minimal", "HMM2 Procedural", "HMM3 Innovative", "HMM4 Leading"],
  "dimensions": [
    {
      "key": "data",
      "name": "Data & visibility",
      "blurb": "Can you see the techniques you care about? A hunt on a missing log source is not a negative result.",
      "link": "{{ site.baseurl }}/learn/data-and-telemetry/",
      "next": [
        "Start with the Windows Security log and command-line auditing (4688 with command line, or Sysmon 1) on every endpoint, then DNS. Use the playbook finder to see what that alone unlocks.",
        "Add Sysmon or EDR process, network and registry telemetry, and PowerShell script block logging. Write down the retention you actually have.",
        "Map data sources to ATT&CK techniques and record the gaps in a data-source assessment; add identity (Entra/AD) and proxy telemetry.",
        "Validate collection continuously (heartbeat per source per host) and emulate techniques to prove the logs capture them.",
        "Treat visibility as a product: coverage metrics per technique, automated gap alerts, and new sources onboarded against hunt demand."
      ],
      "questions": [
        { "q": "Endpoint telemetry (process creation with command line, network connections, file and registry writes)", "options": [
          "We have antivirus alerts and little else",
          "Windows Security log is central, without command lines on most hosts",
          "Command lines, Sysmon or EDR cover most servers and workstations",
          "EDR/Sysmon everywhere, with coverage checked against an asset inventory",
          "Full EDR plus Sysmon, coverage monitored continuously and gaps alert automatically" ] },
        { "q": "Identity and authentication telemetry (AD, Kerberos, cloud identity)", "options": [
          "Not collected centrally",
          "Domain controller Security logs are collected but not all DCs, or not 4769/4768",
          "All DCs plus Entra/IdP sign-in and audit logs",
          "Identity logs are enriched (privileged account lists, tiering, service account inventory)",
          "Identity telemetry is correlated across on-prem and cloud with risk scoring we tune ourselves" ] },
        { "q": "Network and DNS telemetry", "options": [
          "Firewall allow/deny only, or nothing",
          "Proxy or DNS logs, but not both, and short retention",
          "Proxy, DNS and flow logs with 30+ days retention",
          "Zeek or equivalent on key segments, with east-west visibility for tier-0",
          "Full network metadata with long retention and automated beacon/first-seen analytics" ] },
        { "q": "Knowing what you cannot see", "options": [
          "We assume the logs are there",
          "We find gaps when a hunt returns nothing",
          "A data-source assessment exists and is reviewed yearly",
          "Gaps are tracked against ATT&CK and drive onboarding priorities",
          "Visibility is tested by emulation and gap closure is measured quarterly" ] }
      ]
    },
    {
      "key": "process",
      "name": "Hypotheses & process",
      "blurb": "Do hunts start from a written, testable hypothesis, follow a repeatable loop, and end in a report?",
      "link": "{{ site.baseurl }}/learn/hunting-process-and-frameworks/",
      "next": [
        "Run one time-boxed hunt a month from the hypothesis library using the hypothesis card; write a one-page report even when you find nothing.",
        "Adopt a loop (PEAK or the hunt loop in chapter 2), keep a backlog, and record false positives per hunt.",
        "Prioritise the backlog by crown jewels, intel and coverage gaps; retire or promote hypotheses deliberately.",
        "Measure hunts (time-box adherence, findings, detections shipped, gaps logged) and review the programme quarterly.",
        "Feed intel and incident lessons straight into hypotheses; publish hunt reports internally and share patterns externally." ],
      "questions": [
        { "q": "How hunts begin", "options": [
          "They do not; we work alerts",
          "Someone has an idea and looks around",
          "A written hypothesis with scope and a time-box, chosen from a backlog",
          "Hypotheses are prioritised against crown jewels, intel and coverage gaps",
          "Hypotheses are generated systematically from intel, incidents and coverage metrics" ] },
        { "q": "How hunts end", "options": [
          "They fade out when something else comes up",
          "A chat message or a ticket comment",
          "A short report with findings, false positives and gaps, every time",
          "A report plus a detection or hardening hand-off and a backlog update",
          "Reports feed metrics, detection engineering and the next quarter's plan" ] },
        { "q": "Repeatability", "options": [
          "Each hunt is a one-off",
          "Some queries are saved, in personal notebooks",
          "Playbooks exist for common hunts with shared, versioned queries",
          "Playbooks are tested in a lab against emulation before use",
          "Playbooks are automated where possible and re-run on a schedule as analytics" ] },
        { "q": "Threat intelligence input", "options": [
          "IOC feeds only",
          "We read reports occasionally",
          "Reports are translated into ATT&CK techniques and hypotheses",
          "A documented intel requirement list drives collection and hunting priorities",
          "Intel, hunting and detection engineering share one backlog and one set of priorities" ] }
      ]
    },
    {
      "key": "people",
      "name": "People & skills",
      "blurb": "Who hunts, how much time they are protected from the queue, and how skills grow.",
      "link": "{{ site.baseurl }}/learn/building-a-hunt-program/",
      "next": [
        "Protect a half-day a week for one analyst to hunt; pair it with the analyst track on the learning path.",
        "Rotate SOC analysts through hunting; build a lab so skills are practised, not just read about.",
        "Define a hunter role and a training path (query languages, ATT&CK, statistics, detection engineering).",
        "Specialise (identity, cloud, network) while keeping the team cross-trained; mentor and run internal CTFs.",
        "The team teaches others, contributes rules upstream and measures skills growth." ],
      "questions": [
        { "q": "Protected time", "options": [
          "None; hunting happens if the queue is empty",
          "Occasional, ad hoc",
          "A fixed allocation per week or sprint that is usually honoured",
          "Dedicated hunters or a dedicated rotation",
          "A dedicated team with capacity planned against the hunt backlog" ] },
        { "q": "Skills", "options": [
          "Alert triage skills only",
          "One person can write queries beyond the console defaults",
          "Most hunters are fluent in the SIEM query language and ATT&CK",
          "Hunters can baseline, stack and cluster, and write Sigma rules",
          "Hunters script enrichment, build analytics and review each other's work" ] },
        { "q": "Learning loop", "options": [
          "Learning is on your own time",
          "Occasional vendor training",
          "A lab exists and is used to practise techniques",
          "Emulate-then-detect exercises run regularly and findings are shared",
          "Skills are assessed, developed and tracked; the team publishes" ] },
        { "q": "Hand-offs to IR and engineering", "options": [
          "Unclear who takes a hunt finding",
          "Findings go to whoever is around",
          "Escalation criteria are written in each playbook and IR accepts a defined hand-off",
          "Detection engineering has an intake for hunt output and reports back on deployment",
          "Hunting, IR and engineering run as one loop with shared metrics" ] }
      ]
    },
    {
      "key": "tooling",
      "name": "Tooling & automation",
      "blurb": "Can hunters query at scale, enrich quickly, and turn finished hunts into analytics?",
      "link": "{{ site.baseurl }}/learn/detection-engineering/",
      "next": [
        "Make sure every hunter has search access to the raw data with reasonable retention; save queries in a shared repository.",
        "Add lookups (asset, identity, privileged accounts) and standardise on a query pattern library.",
        "Version control queries and detections; adopt Sigma or an equivalent so hunts become portable rules.",
        "Automate the stacking and first-seen patterns as scheduled analytics; CI tests rules before deployment.",
        "Detection-as-code with testing, metrics on rule health and automated regression against emulation." ],
      "questions": [
        { "q": "Data access", "options": [
          "Analysts see alerts, not raw events",
          "Search is possible but slow or limited to a few days",
          "Fast search across 30+ days with saved queries",
          "Search plus notebooks or scripting for enrichment and statistics",
          "A data platform where analytics can be built, tested and scheduled" ] },
        { "q": "Query and detection management", "options": [
          "Queries live in people's heads",
          "A shared document of queries",
          "A versioned repository (Git) of hunts and detections",
          "Sigma or an equivalent format with CI validation",
          "Detection-as-code: tests, peer review, metrics, automated deployment" ] },
        { "q": "Enrichment", "options": [
          "Manual lookups in other consoles",
          "Some lookups in the SIEM",
          "Asset, identity and threat intel enrichment available at query time",
          "Context (ownership, criticality, baselines) attached automatically",
          "Enrichment pipelines maintained as products with owners" ] },
        { "q": "Automation of finished hunts", "options": [
          "Hunts are never re-run",
          "Occasionally a hunt becomes a saved search",
          "Successful hunts are converted into scheduled analytics or rules as a rule",
          "Analytics are tuned with recorded false positives and reviewed on a cadence",
          "Analytics are measured (coverage, precision, time-to-detect) and retired when obsolete" ] }
      ]
    },
    {
      "key": "outcomes",
      "name": "Outcomes & measurement",
      "blurb": "Does hunting change anything: detections shipped, gaps closed, incidents found earlier?",
      "link": "{{ site.baseurl }}/learn/building-a-hunt-program/#metrics-that-matter",
      "next": [
        "Record three numbers per hunt: hours spent, findings, and gaps or detections produced. That is already a metric.",
        "Track detections shipped and visibility gaps closed per quarter; show them to leadership.",
        "Map hunts and detections to ATT&CK and publish a coverage map; measure dwell-time trends.",
        "Benchmark coverage against the threats you actually face and use it to argue for telemetry and staff.",
        "Hunting demonstrably reduces time-to-detect and feeds risk decisions; results are shared with peers." ],
      "questions": [
        { "q": "What hunting produces", "options": [
          "Nothing we can point to",
          "Occasional findings, undocumented",
          "Findings, false-positive notes and gaps recorded per hunt",
          "New detections and hardening changes attributed to hunts",
          "Measurable reduction in dwell time and risk, attributed to hunting" ] },
        { "q": "Coverage view", "options": [
          "None",
          "A list of alert rules",
          "An ATT&CK map of detections and hunts",
          "Coverage map plus data-source map, reviewed quarterly",
          "Coverage drives the roadmap and is validated by emulation" ] },
        { "q": "Reporting", "options": [
          "Hunting is invisible to management",
          "Mentioned in passing",
          "A regular hunt summary with findings and gaps",
          "Metrics reported against goals (hunts completed, detections shipped, gaps closed)",
          "Hunting outcomes inform budget, architecture and risk decisions" ] },
        { "q": "Learning from incidents", "options": [
          "Incidents are closed and forgotten",
          "Lessons are discussed informally",
          "Each incident produces hypotheses for the backlog",
          "Post-incident hunts check for the same tradecraft elsewhere, every time",
          "Incident, hunt and detection data are analysed together to find systemic gaps" ] }
      ]
    }
  ]
}
</script>

## How the levels map

| Score | HMM level | What it looks like |
|---|---|---|
| 0-0.5 | HMM0 Initial | Alert-driven; no routine data collection beyond what the tools default to |
| 0.5-1.5 | HMM1 Minimal | Some telemetry collected; hunting is ad hoc, usually IOC searches from a report |
| 1.5-2.5 | HMM2 Procedural | Written procedures and playbooks; hunts follow a loop and produce reports; little automation |
| 2.5-3.5 | HMM3 Innovative | The team creates its own procedures and analytics, baselines and stacks, and ships detections |
| 3.5-4 | HMM4 Leading | Successful hunts are automated into analytics; hunting is measured and shapes the programme |

The dimension scores matter more than the headline. Fix the lowest one first: data before process, process before tooling. A team that scores "Innovative" on tooling and "Minimal" on data is measuring a dashboard, not a capability.

## Related

- [Building a hunt program]({{ site.baseurl }}/learn/building-a-hunt-program/): staffing, metrics and the maturity path in detail
- [Data & telemetry]({{ site.baseurl }}/learn/data-and-telemetry/) and the [playbook finder]({{ site.baseurl }}/hunt/finder/): what your current logs can already support
- [Templates]({{ site.baseurl }}/templates/): the hunt report and data-source assessment the recommendations refer to
