---
title: "Intel Drop 50 | Firewall managers raided: GT13 vs Check Point"
type: intel-drop
drop: 50
attack: [T1190, T1098.004, T1572, T1562.004]
risk: { likelihood: 3, impact: 5 }
tlp: CLEAR
summary: "GreyNoise tracks an unattributed campaign, GT13, that hit at least 22 organisations: a forged HFS admin session, a root SSH key and Chisel tunnels led to Check Point Security Management Servers."
date: 2026-11-24
---

GreyNoise tracks an unattributed campaign (GT13) hitting at least 22 organisations. The actor forged an admin session on an unpatched Rejetto HFS server, planted a root SSH key, tunnelled in with Chisel and abused CVE-2026-16232 to run scripts on Check Point Security Management Servers, copying the firewall database and internal CA and unloading security policies. Confirmed 2 Oct to 2 Nov; likely ongoing. Single source.

Companion hunt: [Hunt Drop 20](/hunting/hunt-drop-20-gt13-hunting-the-hop-behind-the-firewall/).

## Attack chain (ATT&CK, analyst-mapped)

1. Forged admin session on an unpatched HFS server (T1190)
2. Root SSH key planted, relay box set up (T1098.004)
3. Chisel tunnel into management servers (T1572)
4. SmartConsole authentication bypass runs scripts (T1190)
5. Firewall database and CA copied; policies unloaded (T1562.004)

## Risk

**15/25 CRITICAL** (likelihood 3 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Campaign activity | MODERATE (one source) |
| Attribution | None made |

## Business risk

Whoever controls the firewall manager controls the outcome: policy and certificates can change without tripping classic alerts, and one compromised manager can expose many downstream organisations.

## What to do now

- Lock management and SmartConsole access to admin networks; patch CVE-2026-16232 and retire exposed HFS
- Review root SSH keys and unexpected tunnels on management hosts

## Sources

1. GreyNoise (23 Nov 2026): <https://www.greynoise.io/blog/check-point-security-management-servers-intrusion-campaign>
