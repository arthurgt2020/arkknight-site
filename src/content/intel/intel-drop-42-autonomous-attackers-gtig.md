---
title: "Intel Drop 42 | Attackers go autonomous"
type: intel-drop
drop: 42
motivation: unknown
sectors: []
regions: []
attack: [T1190, T1587.004, T1588.006]
risk: { likelihood: 4, impact: 4 }
tlp: CLEAR
summary: "Google's threat intelligence group says it saw, for the first time, actors using LLM frameworks to automate vulnerability discovery and exploitation with no human in the loop; zero-days reached 22 in August 2026."
date: 2026-11-17
---

Google's threat intelligence group (16 Nov) says it saw, for the first time, actors using LLM frameworks to automate vulnerability discovery and exploitation with no human in the loop. Multi-agent frameworks such as ARTEX, CAIRN and PentAGI are in use, and zero-days reached 22 in August 2026, against a 2025 average of 8 a month. The "first" claim is Google's alone.

Posted together with [Intel Drop 41](/intel/intel-drop-41-fake-m365-outage-phishing/).

## Attack chain

1. **Find**. LLM agents discover vulnerabilities (T1588.006).
2. **Build**. Agents develop exploits (T1587.004).
3. **Use**. Exploitation of public-facing systems (T1190).

## Risk

**16/25 CRITICAL** (likelihood 4 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Observed use of agent frameworks | MODERATE |
| "First time, no human" claim | LOW (single source) |

## Business risk

Phished M365 credentials open mailboxes, files and partner trust, while machine-speed exploitation shrinks the gap between a patch and attacks on unpatched systems.

## What to do now

- Cut patch windows for internet-facing systems from days to hours.
- Review identity and web-tier detections for fast chains of discovery, exploit and privilege.

## Sources

1. Google Cloud, GTIG AI Threat Tracker (16 Nov 2026): <https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold>
2. Google blog (16 Nov 2026): <https://blog.google/innovation-and-ai/infrastructure-and-cloud/google-cloud/gtig-ai-threat-tracker-q4-2026/>
3. Cybersecurity Dive (16 Nov 2026): <https://www.cybersecuritydive.com/news/ai-agentic-frameworks-artex-google-fbi/874753/>
