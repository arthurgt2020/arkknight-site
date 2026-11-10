---
title: "Intel Drop 35 | Operation Snowball: an AI agent ran a two-week telecom intrusion"
type: intel-drop
drop: 35
motivation: unknown
sectors: [Telecommunications]
regions: [Europe]
attack: [T1190, T1548.003, T1572, T1505.003, T1078.001]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Recovered transcripts show a jailbroken DeepSeek Flash harness, steered by a Chinese-speaking operator, attacking a European telecom and 13 hosted organisations through a BroadWorks XSP XXE flaw."
date: 2026-11-10
---

Malbear Labs recovered transcripts of a jailbroken DeepSeek Flash harness, steered by a Chinese-speaking operator, attacking a European telecom and 13 hosted organisations. It entered through a Cisco BroadWorks XSP XXE flaw (CVE-2026-20320) and, when antivirus blocked its tunnel tool, wrote its own. Outcomes are not independently verified.

Posted together with [Intel Drop 34](/intel/intel-drop-34-n-central-able2shell/): your management plane is the target.

## Attack chain

1. **Entry** (T1190). BroadWorks XSP XXE, CVE-2026-20320.
2. **Escalate** (T1548.003). `sudo vi` escape, then a systemd unit.
3. **Adapt** (T1572). Antivirus blocked suo5, so the agent wrote a Perl tunnel.
4. **C2 and webshells** (T1505.003). Sliver behind Cloudflare, plus JSP webshells.
5. **Impact** (T1078.001). A default database login exposed patient records.

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (recovered transcripts) | MODERATE |
| Nationality or state link | LOW (operator language only) |

## Business risk

AI agents make intrusions faster and more adaptive: blocking one tool no longer stops the operator.

## What to do now

- Patch or isolate BroadWorks XSP and end-of-life app servers.
- Remove default database passwords.
- Hunt for long-lived HTTP connections carrying raw TCP.
