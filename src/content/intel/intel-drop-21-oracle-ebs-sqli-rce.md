---
title: "Intel Drop 21 | Oracle EBS CVE-2026-101767: probed a week after patch"
type: intel-drop
drop: 21
attack: [T1190, T1059.004]
risk: { likelihood: 3, impact: 5 }
tlp: CLEAR
summary: "Unauthenticated SQL injection to RCE in EBS 12.2.3 to 12.2.15 (CVSS 9.8). Patched 20 Oct."
date: 2026-10-29
---

Oracle fixed CVE-2026-101767 (CVSS 9.8) in its 20 October Critical Patch Update. Horizon3, which found it, describes an unauthenticated SQL injection in the EBS Thin Client Framework servlet that can be chained to remote code execution: SQL as the APPS database user, then OS commands as the EBS application account. EBS 12.2.3 to 12.2.15 are affected.

On 27 October, Defused reported exploratory exploit attempts against its EBS decoys. That is probing, not confirmed compromise: Oracle has not marked the flaw as exploited and no actor has been named. Shadowserver tracks more than 670 internet-exposed EBS instances.

Why it matters here: EBS holds finance, payroll, HR and procurement data, and is common in large government and enterprise estates. In our assessment, a one-week gap between patch and probing leaves little room for quarterly ERP patch cycles.

Companion hunt: [Hunt Drop 7](/hunting/hunt-drop-07-oracle-ebs-tcf-rce/).

## Timeline and attack path

1. 20 Oct: Oracle CPU patch, and Horizon3 publishes its advisory the same day
2. 27 Oct: decoys probed with exploratory attempts and no confirmed breach
3. Unauthenticated SQL injection: POST to the TCF servlet, SQL as the APPS user (T1190)
4. OS commands on the app server: the oracle account spawns a shell (T1059.004)

## Risk

**15/25 CRITICAL** (likelihood 3 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Vulnerability and impact | HIGH |
| Probing in the wild | MODERATE |
| Successful exploitation | NOT REPORTED |

## Business risk

An unauthenticated attacker could read or alter financial and HR records and take over the application server, with fraud, extortion and regulatory exposure to follow.

## What to do now

- Apply the October 2026 CPU to all EBS 12.2 instances, starting with internet-facing ones.
- Until patched, remove /OA_HTML/AppsTCFServer from the EBS URL firewall allowlist.
- Restrict the EBS web tier to trusted networks.
- Monitor for unauthenticated POSTs to the TCF servlet and the oracle account spawning shells.

## Sources

1. Horizon3.ai (20 Oct 2026): <https://horizon3.ai/attack-research/vulnerabilities/cve-2026-101767/>
2. BleepingComputer (28 Oct 2026): <https://www.bleepingcomputer.com/news/security/hackers-now-scanning-systems-for-recently-patched-oracle-flaw/>
3. The Hacker News (28 Oct 2026): <https://thehackernews.com/2026/10/hackers-target-critical-oracle-e.html>
4. The Register (28 Oct 2026): <https://www.theregister.com/security/2026/10/28/oracle-celebrates-end-of-cybersecurity-awareness-month-with-quadruple-trouble/5306121>
