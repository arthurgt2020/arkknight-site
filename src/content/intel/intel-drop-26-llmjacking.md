---
title: "Intel Drop 26 | LLMJacking: your AI bill is the payload"
type: intel-drop
drop: 26
motivation: financial
sectors: []
regions: []
attack: [T1078.004, T1136.003, T1098.004, T1496.004]
risk: { likelihood: 4, impact: 3 }
tlp: CLEAR
summary: "Stolen cloud keys drive $100K+ a day in fraudulent LLM charges, with 1-token requests used to test keys under alert thresholds."
date: 2026-11-03
---

Mandiant reports attackers hijacking enterprise LLM access with stolen cloud keys and tokens, running up $100K+ in a single day and testing keys with 1-token requests to evade alerts.

Companion hunt: [Hunt Drop 09](/hunting/hunt-drop-09-llmjacking/).

## Attack chain

1. **Stolen cloud identity** (T1078.004). IAM credentials, service-account keys and GitHub tokens.
2. **Quiet key testing.** Single-token requests stay under volume alerts.
3. **Backdoor accounts and keys** (T1136.003, T1098.004). Fake "billing" service accounts and planted SSH keys.
4. **Resell the access** (T1496.004). "LLM Mixers" sell stolen model quota.

## Risk

**12/25 HIGH** (likelihood 4 × impact 3).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Named actor link | LOW |

## Business risk

Stolen AI keys become direct financial loss.

## What to do now

- Set LLM spending caps.
- Alert on new AI service enablement and on service-account key creation.
- Rotate and scope cloud and AI keys, and scan repos for secrets.

## Sources

1. Google Threat Intelligence Group / Mandiant (2 Nov 2026): <https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models/>
2. The Register (2 Nov 2026): <https://www.theregister.com/security/2026/11/02/token-thieves-costing-companies-100k-per-day-in-illicit-llm-charges/5306967>
3. SiliconANGLE (2 Nov 2026): <https://siliconangle.com/2026/11/02/google-finds-llmjacking-attackers-running-up-100k-a-day-in-fraudulent-cloud-charges/>
