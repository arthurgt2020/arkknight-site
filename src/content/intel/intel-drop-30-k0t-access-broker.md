---
title: "Intel Drop 30 | Suspected broker k0t walks in through the network edge"
type: intel-drop
drop: 30
actor: k0t
motivation: financial
sectors: []
regions: [GCC]
attack: [T1596.005, T1046, T1190, T1110.003, T1133, T1018, T1135, T1518.001, T1219, T1567.002]
risk: { likelihood: 4, impact: 4 }
tlp: CLEAR
summary: "Group-IB links a campaign that exposed 70,000+ credentials to mass scanning of FortiGate, FortiWeb and GlobalProtect edges."
date: 2026-11-05
---

Group-IB links a campaign that exposed **70,000+ credentials** and LDAP dumps to mass scanning of FortiGate, FortiWeb and GlobalProtect. Operators exploited CVE-2025-64446 and CVE-2026-0257, brute-forced FortiGate, then used VPN access, RMM tools and Rclone exfiltration. Ransomware links remain unconfirmed.

Companion hunt: [Hunt Drop 10](/hunting/hunt-drop-10-edge-to-domain-k0t/).

## Attack chain

1. **Mass scanning of exposed firewalls and VPNs** (T1596.005, T1046).
2. **Exploit FortiWeb and GlobalProtect; brute-force FortiGate** (T1190, T1110.003, CVE-2025-64446, CVE-2026-0257).
3. **OpenConnect VPN foothold, then AD and share discovery** (T1133, T1018, T1135, T1518.001).
4. **RMM persistence (MeshCentral, AnyDesk) and Rclone exfiltration** (T1219, T1567.002).

## Risk

**16/25 CRITICAL** (likelihood 4 × impact 4), GCC edge devices.

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Ransomware or broker link | LOW |

## Business risk

Weak edge credentials lower the cost of attack.

## What to do now

- Patch FortiWeb and PAN-OS, rotate edge and LDAP bind credentials, and enforce MFA.
- Alert on new OpenConnect sessions and unapproved RMM tools.

## Sources

1. Group-IB (21 Oct 2026): <https://www.group-ib.com/blog/stray-cat-network-edge/>
2. The Hacker News (23 Oct 2026): <https://thehackernews.com/2026/10/hackers-breach-enterprise-firewalls-and.html>
