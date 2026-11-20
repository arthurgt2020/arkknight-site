---
title: "Intel Drop 39 | FaceStealer: North Korea turns contacts' faces into lures"
type: intel-drop
drop: 39
actor: BlueNoroff
motivation: financial
sectors: [Finance, Crypto]
regions: []
attack: [T1204.004, T1656, T1657]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "The FBI and DOJ say BlueNoroff stole more than $400M in crypto in 18 months using hijacked accounts, replayed contact videos and paste-and-run \"fixes\"; US authorities seized infrastructure and 900+ victim videos."
date: 2026-11-15
---

The FBI and DOJ say North Korea's BlueNoroff stole more than $400M in crypto in 18 months. Hijacked Telegram, LinkedIn, Slack or Discord accounts send meeting invites, a replayed video of a known contact plays, and a fake audio fault pushes a paste-and-run "fix" that installs malware. US authorities seized the infrastructure and 900+ victim videos. Arctic Wolf counts 677 targets in 58 countries, 84% founders or C-suite.

Posted together with [Intel Drop 40](/intel/intel-drop-40-artex-fbi-flash/).

## Attack chain

1. **Lure**. Hijacked messaging account sends a meeting invite (T1656).
2. **Trick**. Replayed video of a known contact; fake audio fault.
3. **Run**. The user pastes a "fix" command that installs malware (T1204.004).
4. **Theft**. Crypto and credentials stolen (T1657).

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity and losses (DOJ, FBI) | HIGH |
| North Korea link (US government) | HIGH |

## Business risk

Both start where trust is assumed: a familiar face on a call, a forgotten internet-facing app. Expect fast fund loss, tenant takeover and supply-chain exposure across GCC finance, government and critical infrastructure.

## What to do now

- Verify unexpected meeting invites out of band; join only through official apps.
- Alert on paste-and-run commands (PowerShell, curl-piped, osascript).

## Sources

1. US DOJ (12 Nov 2026): <https://www.justice.gov/opa/pr/justice-department-announces-actions-disrupt-north-koreas-massive-theft-cryptocurrency>
2. FBI FLASH AC-111226-MS (12 Nov 2026): <https://www.ic3.gov/CSA/2026/261112.pdf>
3. Arctic Wolf (12 Nov 2026): <https://arcticwolf.com/resources/blog/still-in-the-meeting-bluenoroff-six-months-on/>
4. The Hacker News (13 Nov 2026): <https://thehackernews.com/2026/11/fbi-says-north-korean-hackers-stole.html>
5. BleepingComputer (14 Nov 2026): <https://www.bleepingcomputer.com/news/security/us-disrupts-north-korean-campaign-behind-400-million-crypto-theft/>
