---
title: "Intel Drop 46 | AuditTeam ransomware: extortion framed as a \"forced audit\""
type: intel-drop
drop: 46
actor: AuditTeam
motivation: financial
sectors: []
regions: [Europe, Asia, Africa]
attack: [T1218.007, T1055, T1562.001, T1486]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Kaspersky details a group whose ransom notes read like audit logs; its OpsAgent framework, likely built with LLM help, has hit dozens of organisations in seven countries since January."
date: 2026-11-19
---

Kaspersky details a group that frames extortion as a "forced audit", with ransom notes written like audit logs. Its OpsAgent framework, likely built with LLM help, has hit dozens of organisations in seven countries since January, injecting into msiexec.exe and killing about 220 security processes before encrypting.

Posted together with [Intel Drop 47](/intel/intel-drop-47-shadowcloud-gitdoor-graphdoor/), [Intel Drop 48](/intel/intel-drop-48-cold-relic-workspace-mfa/).

## Attack chain

1. **Run**. msiexec.exe used to execute the payload (T1218.007).
2. **Inject**. Code injected into msiexec.exe (T1055).
3. **Blind**. About 220 security processes killed (T1562.001).
4. **Impact**. Files encrypted (T1486).

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Campaign (Kaspersky) | HIGH |
| LLM-assisted tooling | LOW (likely) |

## Business risk

Attackers are hiding inside things you already trust: MSI processes, cloud APIs and your own identity provider. Detection gaps mean longer dwell time and data theft before anyone sees damage.

## What to do now

- Alert on remote-thread injection into msiexec.exe and on new security-killing driver loads.

## Sources

1. Kaspersky (18 Nov 2026): <https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-auditteam-ransomware-campaign-spanning-europe-asia-and-africa>
2. Securelist, AuditTeam/OpsAgent (18 Nov 2026): <https://securelist.com/auditteam-opsagent-forced-audit/122031/>
