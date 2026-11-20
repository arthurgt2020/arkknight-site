---
title: "Intel Drop 40 | ARTEX: the FBI's FLASH on AI-driven intrusions"
type: intel-drop
drop: 40
motivation: unknown
sectors: []
regions: []
attack: [T1190, T1505.003, T1098.001, T1558]
risk: { likelihood: 4, impact: 4 }
tlp: CLEAR
summary: "FBI FLASH-20261113-001 says actors have used the ARTEX AI framework since August 2026, in some cases reaching privileged access in under three hours; 1,600+ ARTEX consoles were exposed in early November."
date: 2026-11-15
---

FBI FLASH-20261113-001 says malicious actors have used the ARTEX AI framework since August 2026, in some cases reaching privileged access in under three hours. Agents chain web flaws, web shells, OAuth credential additions and Kerberos abuse. More than 1,600 ARTEX consoles were exposed in early November.

Posted together with [Intel Drop 39](/intel/intel-drop-39-facestealer-bluenoroff/).

## Attack chain

1. **Entry**. Agents exploit web flaws (T1190).
2. **Foothold**. Web shells (T1505.003).
3. **Cloud**. OAuth credentials added to apps (T1098.001).
4. **Escalate**. Kerberos abuse (T1558).

## Risk

**16/25 CRITICAL** (likelihood 4 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (FBI FLASH) | HIGH |
| Time to privilege (under three hours) | MODERATE (some cases) |

## Business risk

Both start where trust is assumed: a familiar face on a call, a forgotten internet-facing app. Expect fast fund loss, tenant takeover and supply-chain exposure across GCC finance, government and critical infrastructure.

## What to do now

- Inventory peripheral internet-facing apps; lock down Kudu/SCM and admin interfaces.
- Review new Entra app credentials and check the FBI's ARTEX indicators.

## Sources

1. FBI FLASH-20261113-001 (13 Nov 2026): <https://www.ic3.gov/CSA/2026/261113.pdf>
2. GBHackers (14 Nov 2026): <https://gbhackers.com/fbi-warns-artex-ai-framework/>
3. Cyber Security News (14 Nov 2026): <https://cybersecuritynews.com/fbi-reveals-hackers-artex-ai-usage/>
