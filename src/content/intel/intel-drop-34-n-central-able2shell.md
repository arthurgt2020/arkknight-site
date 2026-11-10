---
title: "Intel Drop 34 | N-central \"Able2Shell\": MSPs told to pull the plug"
type: intel-drop
drop: 34
motivation: unknown
sectors: [MSP]
regions: []
attack: [T1190, T1068, T1136, T1072, T1199, T1070]
risk: { likelihood: 4, impact: 5 }
tlp: CLEAR
summary: "33 alleged N-central zero-days with public proof-of-concept code led N-able to take hosted N-central offline on 9 November and tell on-prem operators to do the same."
date: 2026-11-10
---

On 9 November, N-able took hosted N-central offline worldwide and told on-prem operators to do the same. A researcher had published 33 alleged zero-days with proof-of-concept code. Huntress counts four exploit chains: three to remote code execution and one to root. There are no CVEs or fixed versions yet, and N-able had seen no exploitation as of 9 Nov 15:15 UTC. Earlier 2026 N-central attacks pushed scripts into managed networks.

Posted together with [Intel Drop 35](/intel/intel-drop-35-operation-snowball/): your management plane is the target.

## Attack chain

1. **Exploit** (T1190). Unauthenticated XXE chained to RCE (claimed).
2. **Escalate** (T1068, T1136). Root access and new admin accounts (claimed).
3. **Push downstream** (T1072, T1199). Scripts and tools sent to managed endpoints.
4. **Cover tracks** (T1070). Audit record manipulation (claimed).

## Risk

**20/25 CRITICAL** (likelihood 4 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Disclosure and N-able shutdown | HIGH |
| Exploit claims validated | LOW (no CVEs, unverified PoC) |

## Business risk

One compromised management or hosting platform exposes every organisation managed through it.

## What to do now

- Keep N-central offline until N-able clears it.
- Review logins, new admins and script deployments from 8 Nov.
- Rotate N-central credentials if anything looks wrong.
