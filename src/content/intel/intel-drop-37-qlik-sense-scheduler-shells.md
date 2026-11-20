---
title: "Intel Drop 37 | Qlik Sense servers hit within three minutes"
type: intel-drop
drop: 37
motivation: unknown
sectors: [Analytics]
regions: [Europe]
attack: [T1190, T1059.001, T1098.004, T1105]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Cynet blocked PowerShell reverse shells spawned by Qlik's scheduler.exe at several EU organisations; the attacker server staged OpenSSH persistence plus ActiveMQ and Veeam exploits."
date: 2026-11-12
---

Cynet blocked PowerShell reverse shells spawned by Qlik's scheduler.exe at several EU organisations. The attacker's server staged OpenSSH persistence plus ActiveMQ and Veeam exploits, echoing 2023 Cactus ransomware tradecraft.

Posted together with [Intel Drop 36](/intel/intel-drop-36-screenconnect-msp-rogue-agents/), [Intel Drop 38](/intel/intel-drop-38-antifox-aws-secrets/).

## Attack chain

1. **Entry**. Exposed Qlik Sense server exploited (T1190).
2. **Execute**. scheduler.exe spawns a PowerShell reverse shell (T1059.001).
3. **Persist**. OpenSSH installed with authorised keys (T1098.004).
4. **Stage**. Tools and ActiveMQ / Veeam exploits fetched from the attacker server (T1105).

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (vendor-blocked intrusions) | HIGH |
| Link to 2023 Cactus tradecraft | LOW (similarity only) |

## Business risk

Your MSP, analytics server and cloud keys each sit one hop from your data and backups. One compromise can mean silent remote control, stolen secrets and a ransomware foothold.

## What to do now

- Patch or isolate exposed Qlik Sense; alert on scheduler.exe spawning PowerShell.
- Check Veeam and ActiveMQ for the CVEs the staged exploits target.

## Sources

1. Cynet (11 Nov 2026): <https://www.cynet.com/security-foundations/attack-techniques/exploiting-Qlik-Sense-servers/>
2. The Hacker News (11 Nov 2026): <https://thehackernews.com/2026/11/hackers-target-qlik-sense-servers-with.html>
