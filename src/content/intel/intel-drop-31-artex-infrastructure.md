---
title: "Intel Drop 31 | ARTEX: an AI pentest tool turned attack platform"
type: intel-drop
drop: 31
actor: ARTEX
motivation: unknown
sectors: [Finance]
regions: [South Korea, GCC]
attack: [T1588.007, T1090]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Follow-up to Intel Drops 10 and 16: the infrastructure behind the South Korean bank intrusions, mapped by Hunt.io and RST Cloud."
date: 2026-11-05
---

Follow-up to Intel Drops 10 and 16. Hunt.io mapped the infrastructure behind the South Korean bank intrusions: a Claude Code harness routed to DeepSeek through a reseller, 19 custom agent skills and a rotating proxy pool. RST Cloud counts 834 exposed ARTEX hosts, and forks outlived the original repository.

## Attack chain

1. **Claude Code harness routed to DeepSeek via a reseller** (T1588.007, Obtain Capabilities: AI).
2. **19 custom agent skills** for recon, WAF bypass and payment logic, with 147 recorded skill invocations.
3. **Proxy pool and a Hong Kong jump host hide the operator** (T1090, Proxy). 79 exit IPs appear in the first 100 identities.
4. **834 verified ARTEX hosts exposed, and forks still live.** The default console port 8787 is open on 65% of hosts.

## Risk

**12/25 HIGH** (likelihood 3 × impact 4), GCC web and mobile apps.

## Confidence

| Assessment | Confidence |
|---|---|
| Infrastructure findings | HIGH |
| Chinese-speaking operator | MODERATE |

## Business risk

Commoditised AI tooling lowers the cost of attack.

## What to do now

- Search attack-surface data for exposed ARTEX consoles.

## Sources

1. Hunt.io (4 Nov 2026): <https://hunt.io/blog/artex-south-korea-bank-infrastructure>
2. RST Cloud (2 Nov 2026): <https://www.rstcloud.com/hunting-ai-harnesses-cairn-artex-pentagi/>
3. CrowdStrike (7 Oct 2026, background): <https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/>
