---
title: "Intel Drop 49 | Chinese-nexus AI agents found and exploited a zero-day on their own"
type: intel-drop
drop: 49
motivation: espionage
sectors: [Education]
regions: [East Asia]
attack: [T1190, T1059.006, T1546.018]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Amazon reports a Chinese-nexus actor misusing the open-source Cairn AI pentest framework against East Asian universities; the agents found a MONAI Label path traversal and reached a root shell in about 11 minutes."
date: 2026-11-22
---

Amazon Threat Intelligence (20 Nov) reports a Chinese-nexus actor misusing Cairn, an open-source autonomous AI pentest framework, against universities in East Asia outside mainland China. The operator supplied target IPs and a goal ("obtain shell access"); the agents planned and adapted with minimal human involvement.

Most attempts failed: 148 actions against an unauthenticated Redis and 30,000+ SSH credential combinations. Then the agents found a path traversal in MONAI Label's upload endpoint and went from API mapping to arbitrary file writes in about 11 minutes, ending in a root reverse shell via sitecustomize.py. AWS assesses a zero-day with high confidence and a Chinese nexus with moderate confidence. A fix and advisory (GHSA-qc22-rmgc-vg94) are out.

Companion hunt: [Hunt Drop 19](/hunting/hunt-drop-19-hunting-the-python-startup-hook-after-an/).

## Attack chain

1. **Target list and goal**. The operator supplies IPs and a goal: "obtain shell access".
2. **Probe and adapt**. Agents run 148 actions against Redis and 30,000+ SSH logins; all fail.
3. **Zero-day found**. A MONAI Label upload path traversal gives a file write in about 11 minutes (T1190).
4. **Root shell**. A sitecustomize.py payload (T1546.018) is triggered through the training API, giving a root reverse shell (T1059.006).

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Campaign activity | MODERATE |
| China-nexus link | MODERATE |
| Zero-day status | HIGH |

## Business risk

Exposed AI/ML and research tooling can fall faster than a SOC triages, and one compromised server can become a tunnel into a partner network. GCC universities, health and research partners running open-source AI tools should assume the same exposure (analyst judgement).

## What to do now

- Inventory internet-exposed AI/ML and data services (MONAI Label, Redis, Qdrant) and remove unauthenticated access.
- Patch MONAI Label per GHSA-qc22-rmgc-vg94.
- Alert on app or API workers writing sitecustomize.py or spawning shells.
- Automate high-confidence containment, with humans overseeing outcomes.

## Sources

1. Amazon Web Services Security Blog (20 Nov 2026): <https://aws.amazon.com/blogs/security/chinese-nexus-actors-cairn-ai-agents-found-a-zero-day-on-their-own/>
2. The Register (20 Nov 2026): <https://www.theregister.com/security/2026/11/20/china-attackers-deployed-ai-agents-that-autonomously-found-and-exploited-a-0-day-to-take-over-a-university-server/5311382>
