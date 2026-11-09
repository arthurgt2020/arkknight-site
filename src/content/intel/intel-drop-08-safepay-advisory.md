---
title: "Intel Drop 08 | SafePay ransomware: 600+ victims, backups first"
type: intel-drop
drop: 8
actor: SafePay
attack: [T1190, T1110, T1021, T1219, T1567, T1490, T1486]
risk: { likelihood: 3, impact: 5 }
tlp: CLEAR
summary: "Joint US-German-UK advisory AA26-293A (20 Oct 2026): SafePay wipes backups before it encrypts."
date: 2026-10-21
---

On 20 October, CISA, the FBI and the US Secret Service, with German and UK partners, released joint advisory AA26-293A on SafePay ransomware. It reports at least 600 victims across critical infrastructure sectors since August 2024.

The playbook is familiar, and that is the warning. Initial access comes through exposed or phished credentials, brute force, and known edge and backup flaws: Cisco ASA (CVE-2020-3259, CVE-2023-20269), SonicWall (CVE-2024-40766) and Veeam Backup & Replication (CVE-2023-27532, CVE-2024-40711). Operators then move with PsExec, WinRM and RDP, hold access through AnyDesk or TeamViewer, and exfiltrate with RClone or WinSCP. Before encrypting, they stop Volume Shadow Copy and reset backup NAS devices to factory settings.

The advisory lists no Middle East victims. But every entry point it names is common in GCC estates.

## Attack chain

1. Edge/Veeam CVEs, brute force, phishing (T1190, T1110)
2. Lateral movement: PsExec, WinRM, RDP (T1021)
3. Remote access via AnyDesk / TeamViewer (T1219)
4. Exfiltration with Rclone / WinSCP (T1567)
5. Stop VSS, reset backup NAS, encrypt (T1490, T1486)

## Risk

**15/25 CRITICAL** (likelihood 3 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| SafePay activity | HIGH |
| GCC targeting | LOW |

## Business risk

SafePay goes after your ability to recover, not only your data. With the backups gone, a bad week becomes a long outage, followed by leak-site extortion and phone pressure on staff.

## What to do now

- Patch the five listed CVEs and confirm no Veeam server is reachable from the internet.
- Enforce MFA on all VPN and remote access, and alert on brute-force bursts.
- Isolate backup NAS management and keep an offline or immutable copy.
- Hunt for unapproved AnyDesk, TeamViewer, RClone and WinSCP.

## Sources

1. GBHackers (21 Oct 2026): <https://gbhackers.com/safepay-ransomware-attack/>
2. HIPAA Journal (21 Oct 2026): <https://www.hipaajournal.com/feds-issues-advisory-about-safepay-ransomware-group/>
3. TechNadu (advisory dated 20 Oct 2026): <https://www.technadu.com/safepay-ransomware-fbi-cisa-advisory-urges-organizations-to-take-security-measures-warns-of-600-victims/643334/>
4. NVD, CVE-2023-27532 (background): <https://nvd.nist.gov/vuln/detail/CVE-2023-27532>
