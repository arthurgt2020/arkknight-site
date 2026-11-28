---
title: "Intel Drop 51 | CERT-In: payment approvals abused, AI agents probing"
type: intel-drop
drop: 51
attack: [T1078, T1565.001]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "A Critical CERT-In advisory (20 Nov) warns of actors altering payee or approval records and paying out through legitimate workflows, and of AI-driven agentic frameworks adapting failed exploits. No actor named."
date: 2026-11-24
---

CERT-In (rated Critical, 20 Nov) warns of actors who alter business records or approval relationships, then pay out through legitimate workflows at providers behind government-linked payments. It also describes AI-driven agentic frameworks running parallel reconnaissance and adapting failed exploits. No actor named.

## Abuse flow (ATT&CK, analyst-mapped)

1. Reach a business app or provider system
2. Valid credentials and admin functions (T1078)
3. Alter payee or approval records (T1565.001)
4. Pay out via the legitimate approval flow
5. AI agents: parallel recon, adapt on block

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Advisory content | HIGH (primary source) |
| Actor link | None made |

## Business risk

Whoever controls the approval record controls the outcome: money can move without tripping classic alerts, and one provider can expose many downstream organisations.

## What to do now

- Reconcile payment records against sources providers cannot alter
- Require independent verification for payee and approval changes

## Sources

1. CERT-In advisory CIAD-2026-0062 (issued 20 Nov 2026, updated 24 Nov): <https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2026-0062>
2. The Hacker News (23 Nov 2026): <https://thehackernews.com/2026/11/ai-assisted-cyberattacks-trigger.html>
