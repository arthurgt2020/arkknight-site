---
title: "Intel Drop 06 | Qilin & INC: GlobalProtect bypass to the hypervisor"
type: intel-drop
drop: 6
actor: Qilin and INC
attack: [T1190, T1133, T1219, T1021, T1562, T1003.003]
risk: { likelihood: 4, impact: 5 }
tlp: CLEAR
summary: "PAN-OS CVE-2026-0257 is now used by ransomware crews to get past MFA and reach vCenter."
date: 2026-10-21
---

Unit 42 has updated its threat brief on CVE-2026-0257, the PAN-OS GlobalProtect authentication bypass. It now names two ransomware operations exploiting the flaw: Spikey Scorpius (Qilin) and Tarnished Scorpius (INC).

The chain it describes: exploit the bypass, get around MFA to open a VPN session, run reconnaissance with dual-use RMM tools, move over RDP and SMB, then stage tools for credential theft, exfiltration and ransomware. In one case, the operators pivoted from the VPN gateway to vCenter, disabled the ESXi execInstalledOnly control, and dumped credentials offline from a domain controller's virtual disk. All of that happens outside the guest OS, where in-guest EDR cannot see it.

The flaw is not new. The UAE Cyber Security Council warned of active exploitation in May. What has changed: ransomware crews now use it.

## Attack chain

1. GlobalProtect auth bypass, MFA evaded (T1190, T1133)
2. Recon with dual-use RMM tools (T1219)
3. Lateral movement over RDP and SMB (T1021)
4. vCenter pivot, ESXi controls disabled (T1562)
5. Offline creds from DC virtual disk (T1003.003)

## Risk

**20/25 CRITICAL** (likelihood 4 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Exploitation activity | HIGH |
| Qilin / INC naming | MODERATE |

## Business risk

For an organisation with unpatched GlobalProtect, one VPN gateway can lead to domain-wide credential theft and ransomware at the hypervisor layer. That means an organisation-wide outage, with endpoint controls bypassed.

## What to do now

- Patch PAN-OS and Prisma Access to the fixed builds, and review authentication-override cookie settings.
- Review GlobalProtect logs since late May for successful sessions from unusual hosts.
- Restrict vCenter and ESXi management to an admin network, and alert on execInstalledOnly changes.
- Confirm management interfaces are not exposed on ports 4443 or 3879.

## Sources

1. Palo Alto Networks Unit 42 (updated 20 Oct 2026): <https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/>
2. The Hacker News (20 Oct 2026): <https://thehackernews.com/2026/10/qilin-and-inc-ransomware-groups-exploit.html>
3. Palo Alto Networks advisory (13 May 2026, background): <https://security.paloaltonetworks.com/CVE-2026-0257>
4. UAE Cyber Security Council advisory via ADGM (30 May 2026, background): <https://assets.adgm.com/download/assets/432319039+-+Active+Exploitation+of+PAN-OS+GlobalProtect+Authentication+Bypass+Vulnerability+%28CVE-2026-0257%29.pdf/3b3667445d8d11f1a8a1b2b949d797d7>
5. NVD, CVE-2023-27532 (background): <https://nvd.nist.gov/vuln/detail/CVE-2023-27532>
