---
title: "Intel Drop 41 | Fake \"Microsoft 365 outage\" phishing"
type: intel-drop
drop: 41
motivation: unknown
sectors: [Cross-sector]
regions: []
attack: [T1566.002, T1204.001]
risk: { likelihood: 4, impact: 3 }
tlp: CLEAR
summary: "High-volume email posing as M365 service-health notices claims messages were held during an Exchange Online outage; the RESTORE MESSAGES button leads to a non-Microsoft page assessed as credential harvesting."
date: 2026-11-17
---

On 13 Nov, Microsoft saw high-volume email posing as M365 service-health notices. It claims messages were "held" during an Exchange Online outage and will be deleted within 24 hours unless restored. The "RESTORE MESSAGES" button runs through tracking links to a non-Microsoft page, assessed as credential harvesting. No actor is named and Microsoft reports no confirmed compromise.

Posted together with [Intel Drop 42](/intel/intel-drop-42-autonomous-attackers-gtig/).

## Attack chain

1. **Lure**. Fake service-health notice (T1566.002).
2. **Click**. RESTORE MESSAGES runs through tracking links (T1204.001).
3. **Harvest**. Non-Microsoft page assessed as credential harvesting.

## Risk

**12/25 HIGH** (likelihood 4 × impact 3).

## Confidence

| Assessment | Confidence |
|---|---|
| Campaign existence and lure (Microsoft) | HIGH |
| Objective (credential theft) | MODERATE |
| Actor | NONE (unnamed) |

## Business risk

Phished M365 credentials open mailboxes, files and partner trust, while machine-speed exploitation shrinks the gap between a patch and attacks on unpatched systems.

## What to do now

- Search mail for Microsoft's published sender and URL indicators; review clickers' sign-ins, MFA changes and inbox rules.
- Tell staff that real M365 notices never send them to other sites to recover mail.
- Move to phishing-resistant MFA.

## Sources

1. Microsoft Security Blog (16 Nov 2026): <https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/>
