---
title: "Intel Drop 01 | Three threats from this week: BeyondTrust, AOMEI, FortiManager"
type: intel-drop
drop: 1
summary: "Three stories, one theme: attackers going after the tools we trust to support, back up and manage our networks."
date: 2026-10-18
tlp: CLEAR
linkedinUrl: "https://www.linkedin.com/feed/update/urn:li:share:7517499867099820032"
---

Three stories, one theme: attackers are going after the tools we trust to support, back up and manage our networks.

## 1. ARMORY CASTLE and the BeyondTrust zero-day

Google Threat Intelligence Group (GTIG) reports that this suspected PRC-nexus actor exploited CVE-2026-102764 in BeyondTrust Remote Support from late August 2026. The activity included a SAWFLY web shell, a targeted credential vault, deleted logs and a BARECLAW tunnel.

**Action:** apply BT26-05 and hunt back to 29 August.

## 2. AOMEI update servers tampered for minutes

GTIG and ManageEngine report that UNC7017 altered AOMEI Backupper's update files in 5 to 10 minute windows (May to July 2026), then reverted them. The chain was the CROSSROAD downloader, then the SHINYROAD backdoor through a signed Radmin binary.

**Action:** hunt across April to July 2026. A vendor fix won't clean infected endpoints.

## 3. One FortiManager, 500+ firewalls exposed

Unit 42 details how CL-STA-0954 (UNC5820) compromised a telecom managed service provider through FortiJump (CVE-2024-47575), then used CVE-2025-61624 and the in-memory PEERSTITCH implant.

**Action:** keep TCP 541 off the internet and rotate every credential the manager held.

## Why it matters

Remote support, backup and management platforms run with high privilege. In the GCC they often sit in front of government and critical-infrastructure networks. Patching closes the door, but it does not evict an intruder who is already inside.

**Attribution:** GTIG assesses ARMORY CASTLE as suspected PRC-nexus. No state is named for UNC7017 or CL-STA-0954.

## Sources

- GTIG: <https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust>
- SecurityWeek: <https://www.securityweek.com/chinese-apt-exploited-beyondtrust-vulnerability-as-zero-day/>
- Cybersecurity Dive: <https://www.cybersecuritydive.com/news/china-espionage-beyondtrust-zero-day-hacker/833240/>
- GTIG: <https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering>
- ManageEngine: <https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html>
- Unit 42: <https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/>
- Security Affairs: <https://securityaffairs.com/201077/malware/peerstitch-malware-how-attackers-compromised-500-firewalls-through-fortimanager.html>
