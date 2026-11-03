---
title: "OSINT Flight"
excerpt: "Track an aircraft, locate a safe house, and recover the final flag using open-source intelligence."
order: 1
layout: single
toc: true
toc_label: "Challenge Stages"
header:
  teaser: /assets/images/ctf/osint-flight.png
difficulty: Beginner
skills_tested:
  - Image metadata (EXIF) analysis
  - Geolocation and map reasoning
  - Historical flight tracking
  - Source evaluation and note-keeping
---

> **Difficulty**: Beginner  
> **Skills**: EXIF metadata, geolocation, flight-tracking tools, source evaluation  
> **Artefacts**: *Coming soon.* The image and briefing bundle is on the roadmap; follow or comment on the [Hunt-Sage issues page](https://github.com/iamjammie/hunt-sage/issues) for status  
> **Estimated time**: 1–2 hours

---

## Scenario brief

A freelance journalist investigating a procurement fraud case stops answering messages. Her last contact was a photo sent to an editor from a rooftop at dusk, captioned only "boarding in an hour". Colleagues believe she was persuaded onto a private flight and is now being kept at a "safe house" by the people she was investigating.

You are an analyst on a non-profit OSINT team supporting the editor. You have no legal authority, no access to private databases and no contact with the airline or the aircraft operator. Everything you use must be open, lawful and reproducible by someone checking your work.

Your job is to answer, with evidence:

1. Where was the photograph taken?
2. Which airport did she most likely depart from?
3. Which flight matches the time and place?
4. Where did that flight land, and therefore in which city is the safe house most likely to be?

---

## Artefacts (coming soon)

The bundle, when published, will contain:

```text
osint-flight/
├── skyline.png            # Rooftop photo with intact EXIF metadata (GPS, timestamp, device)
├── editor_notes.txt       # The editor's recollection: time zone, message timestamps, caption
├── chat_export.txt        # Redacted messaging export with the last three exchanges
└── README.md              # Rules of engagement and the flag format
```

Until it is released, you can practise the same workflow on any geotagged photo you own: run the metadata stage on it and work through the airport and flight stages for a date of your choice.

**Rules of engagement.** Use only open sources. Do not contact any real person, operator, airport or company. Do not attempt to access accounts. The scenario is fictional; any resemblance to real flights or people is coincidental.

---

## Stages

Answer each stage before moving on. Keep a running log of every source, URL and timestamp you used; the final stage asks for it.

### Stage 1: Read the photograph

**Q1.1** — What device took the photo, and when (in UTC)?

**Q1.2** — What GPS coordinates are embedded? Convert them to decimal degrees.

**Q1.3** — Does the time zone in the EXIF agree with the editor's notes? If not, which do you trust and why?

<details>
<summary>Hint</summary>

Any EXIF reader works: `exiftool skyline.png`, or the properties panel in an image viewer. Note that PNG files store metadata differently from JPEG; look for `XMP` and `eXIf` chunks. GPS in EXIF is stored as degrees/minutes/seconds with a hemisphere reference; a negative sign is implied by `S` or `W`.
</details>

---

### Stage 2: Place the rooftop

**Q2.1** — Put the coordinates on a map. What city and district are you in?

**Q2.2** — The photo shows a skyline with two distinctive towers and a body of water. Confirm or refute the GPS position using the view itself (direction of the sun at the stated time, landmarks, shoreline shape).

**Q2.3** — Which airports are within a 60-minute drive? List them with ICAO codes and note which handle private or charter traffic.

<details>
<summary>Hint</summary>

GPS can be spoofed or stale; the view is the ground truth. Use a sun-position calculator with the EXIF timestamp to check the direction of the light, then compare landmark bearings against a map. For airports, a map search for "airport" plus the local general-aviation field is enough; Wikipedia pages list ICAO/IATA codes and the kind of traffic each field takes.
</details>

---

### Stage 3: Find the flight

**Q3.1** — Using a historical flight-tracking service, list departures from each candidate airport in the window from photo time + 45 minutes to photo time + 2 hours.

**Q3.2** — The editor's notes say she mentioned "a small jet, not a commercial flight". Which departures fit?

**Q3.3** — Pick the most likely flight. State its callsign or registration, departure time and destination, and explain why you ruled out the alternatives.

<details>
<summary>Hint</summary>

Free tiers of flight-tracking sites usually show a few days of history; the bundle's scenario date is chosen to fall inside that window from the release date, and the README will note a fallback dataset if it does not. Filter by aircraft type (business jets, turboprops) and ignore scheduled airlines. "Blocked" or unidentified callsigns are themselves a clue.
</details>

---

### Stage 4: Infer the safe house city

**Q4.1** — Where did the flight land? Give the destination ICAO code.

**Q4.2** — Is the destination a hub with onward connections, or a small field where the passengers most likely stayed nearby? What does that imply about the safe house city?

**Q4.3** — Build the flag.

<details>
<summary>Hint</summary>

Small regional fields rarely have onward connections late in the day; if the aircraft stayed overnight (check its next movement), the passengers almost certainly did too. The city is the one the airport serves, not necessarily the one it is named after.
</details>

---

### Stage 5: Write it up

**Q5.1** — Produce a one-page summary: what you concluded, your confidence in each step (high / medium / low), and the single piece of evidence each conclusion rests on.

**Q5.2** — List the sources you used with retrieval times. Could another analyst reproduce your result tomorrow?

**Q5.3** — What would you tell the editor *not* to do with this information?

---

## Flag format

```text
flag{ICAO_code_city}
```

The ICAO code is the four-letter code of the **destination** airport; the city is lowercase with underscores for spaces, for example `flag{EGLC_london}`.

---

## Scoring rubric

| Stage | Points | Bonus |
|---|---|---|
| Stage 1 — Metadata | 10 | +5 for catching the time-zone discrepancy |
| Stage 2 — Geolocation | 20 | +5 for a sun-position check |
| Stage 3 — Flight | 30 | +10 for documenting why the alternatives were excluded |
| Stage 4 — Destination | 20 | +5 for checking the aircraft's next movement |
| Stage 5 — Write-up | 20 | +10 for a reproducible source log |
| **Total** | **100** | **+35 bonus** |

---

## What a defender learns

OSINT is the reconnaissance phase of most intrusions. Running this exercise teaches the same skills from the receiving end:

- **Metadata is data.** Photos, documents and PDFs your organisation publishes carry device, location and author details. Know what your own exports leak.
- **Corroborate, do not trust.** One source (GPS) is a lead; two independent sources (GPS plus view) is a finding. The same discipline applies to a SIEM alert.
- **Time zones break investigations.** Half of all timeline errors in incident response are UTC vs local. Fix the zone first, every time.
- **Evidence logs matter.** A conclusion without a source trail cannot be peer-reviewed, challenged or defended. The hunt report template on this site asks for the same thing.
- **Think like the adversary's recon team.** Which of your staff post geotagged photos? Which of your sites are identifiable from a skyline? That is the start of a physical-security and social-engineering threat model.

Related reading: [Hypotheses & threat intelligence]({{ site.baseurl }}/learn/hypotheses-and-intelligence/) and the [hunt report template]({{ site.baseurl }}/templates/#hunt-report).

---

*Artefacts are coming soon. Track progress or suggest a scenario on the [Hunt-Sage issues page](https://github.com/iamjammie/hunt-sage/issues).*
