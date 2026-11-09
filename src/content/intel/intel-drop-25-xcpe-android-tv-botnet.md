---
title: "Intel Drop 25 | XCPE: a botnet built in at the factory"
type: intel-drop
drop: 25
motivation: financial
sectors: []
regions: [Iraq]
attack: []
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Google disrupted XCPE, a firmware backdoor in 1.3M+ Android TV boxes and other IoT, which it says the maker built and sold access to."
date: 2026-11-03
---

Google disrupted **XCPE**, a firmware backdoor in more than 1.3 million Android TV boxes and other IoT devices. Google assesses with high confidence that the maker, Videostrong, built it and sold access to criminals. Iraq is among the largest concentrations.

## How it worked

1. **Preinstalled backdoor.** It runs as a system app and reinstalls itself after a reboot.
2. **Silent control.** It disables Play Protect checks, installs apps and runs a shell.
3. **Access sold to affiliates.** Residential-proxy and ad-fraud modules are loaded.
4. **Hands-on operations.** Screenshots, keystroke injection and network reconnaissance.

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Maker attribution (Google) | HIGH |

## Business risk

Unmanaged devices turn your network into someone else's proxy.

## What to do now

- Inventory and segment Android TV boxes, signage and other unmanaged IoT.

## Sources

1. Google Threat Intelligence Group (2 Nov 2026): <https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet>
2. CyberScoop (2 Nov 2026): <https://cyberscoop.com/google-disrupts-xcpe-botnet-videostrong-android-devices/>
3. Help Net Security (2 Nov 2026): <https://www.helpnetsecurity.com/2026/11/02/xcpe-botnet-android-backdoor/>
