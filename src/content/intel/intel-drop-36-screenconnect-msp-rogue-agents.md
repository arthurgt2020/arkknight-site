---
title: "Intel Drop 36 | Rogue ScreenConnect agents pushed through MSPs"
type: intel-drop
drop: 36
motivation: unknown
sectors: [MSP]
regions: []
attack: [T1199, T1078, T1219]
risk: { likelihood: 4, impact: 4 }
tlp: CLEAR
summary: "Hijacked MSP ScreenConnect consoles used Run Command to install a second, attacker-controlled ScreenConnect instance on downstream machines: six MSPs, 286+ endpoints, 47 organisations."
date: 2026-11-12
---

Since 11 Nov, attackers have used hijacked MSP ScreenConnect consoles' Run Command to install a second, attacker-controlled ScreenConnect instance on downstream machines. Huntress counts six MSPs and 286+ endpoints across 47 organisations so far. ConnectWise suspects third-party extensions; the entry point is unconfirmed.

Posted together with [Intel Drop 37](/intel/intel-drop-37-qlik-sense-scheduler-shells/), [Intel Drop 38](/intel/intel-drop-38-antifox-aws-secrets/).

## Attack chain

1. **Access**. Hijacked MSP ScreenConnect console (T1078), entry unconfirmed.
2. **Pivot**. Run Command on managed endpoints abuses the MSP trust relationship (T1199).
3. **Persist**. A second, attacker-controlled remote-access instance is installed (T1219).

## Risk

**16/25 CRITICAL** (likelihood 4 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (six MSPs, 286+ endpoints) | MODERATE |
| Initial access (third-party extensions) | LOW (unconfirmed) |

## Business risk

Your MSP, analytics server and cloud keys each sit one hop from your data and backups. One compromise can mean silent remote control, stolen secrets and a ransomware foothold.

## What to do now

- Ask your MSP for ScreenConnect Run Command and deployment logs; remove unknown instances.
- Alert on new remote-access tools installed outside change windows.

## Sources

1. Sophos X-Ops (Nov 2026): <https://www.sophos.com/en-us/blog/malicious-screenconnect-deployments-observed>
