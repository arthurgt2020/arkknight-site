---
title: "Intel Drop 48 | COLD RELIC: stolen Workspace data used to register attacker MFA"
type: intel-drop
drop: 48
actor: COLD RELIC
motivation: espionage
sectors: []
regions: [United States]
attack: [T1078.004, T1556.006, T1098.005]
risk: { likelihood: 2, impact: 4 }
tlp: CLEAR
summary: "Google reports the Russia-linked actor (formerly COLDRIVER) used stolen Workspace data to breach a second US organisation, registering its own MFA devices, passkeys and backup codes."
date: 2026-11-19
---

Google reports the Russia-linked actor COLD RELIC (formerly COLDRIVER) is using stolen Workspace data to breach a second US organisation, registering its own MFA devices, passkeys and backup codes.

Posted together with [Intel Drop 46](/intel/intel-drop-46-auditteam-opsagent/), [Intel Drop 47](/intel/intel-drop-47-shadowcloud-gitdoor-graphdoor/).

## Attack chain

1. **Access**. Stolen Workspace data yields valid cloud access (T1078.004).
2. **Persist**. Attacker MFA devices, passkeys and backup codes registered (T1098.005, T1556.006).

## Risk

**8/25 MEDIUM** (likelihood 2 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (Google) | HIGH |
| Russia link (Google) | MODERATE |

## Business risk

Attackers are hiding inside things you already trust: MSI processes, cloud APIs and your own identity provider. Detection gaps mean longer dwell time and data theft before anyone sees damage.

## What to do now

- Review new MFA devices, passkeys and backup-code generation on admin accounts.

## Sources

1. The Hacker News (18 Nov 2026): <https://thehackernews.com/2026/11/russian-cold-relic-hackers-use-stolen.html>
