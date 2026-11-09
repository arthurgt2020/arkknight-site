---
title: "Intel Drop 14 | PHP2Shell, week one: a Mirai botnet joins the rush"
type: intel-drop
drop: 14
attack: [T1190, T1059.004, T1105, T1498]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Follow-up to Intel Drop 05: millions of attempts, no confirmed compromise yet."
date: 2026-10-25
---

Follow-up to Intel Drop #05. Days after PHP's emergency patches, the question has moved from "will this be exploited?" to "who is trying?".

Exploit attempts reached the millions by 22 Oct. Researchers have tied part of that traffic to Potassium, a Mirai-derived botnet: a "wget | sh" dropper pulls a bot into /tmp/nfs that carries 24 DDoS flood vectors. Telemetry has not yet proven the bot landed through PHP2Shell, and no successful compromise has been confirmed so far. But a weaponised exploit is now reported to work on default PHP 8.4/8.5 settings, and on 23 Oct PHP flagged a further session flaw (CVE-2026-115560) with the same mitigation: turn off session upload progress.

## Attempted chain (as reported)

1. Upload-progress request, CVE-2026-109618/9 (T1190)
2. Dropper: wget .../s | sh (T1059.004)
3. Bot fetched to /tmp/nfs (Potassium) (T1105)
4. 24 DDoS flood vectors (Mirai fork) (T1498)
5. New PHP session flaw CVE-2026-115560 (Mitigate)

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Mass exploit attempts | HIGH |
| Botnet infections via PHP | LOW |

## Business risk

Public-facing PHP (portals, CMS, hosted apps) is under mass, automated probing. One hit means remote code execution, botnet enrolment and a foothold, and unsupported PHP 5.x–7.x has no fix.

## What to do now

- Patch to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 and restart workers.
- Set session.upload_progress.enabled=0 in php.ini or the pool config, not ini_set().
- Alert on web workers spawning sh, wget or id, or writing to /tmp.
- Inventory end-of-life PHP and isolate what can't be patched.

## Sources

1. The Hacker News (23 Oct 2026): <https://thehackernews.com/2026/10/php2shell-exploit-attempts-hit-millions.html>
2. Sophos (updated 23 Oct 2026): <https://www.sophos.com/en-us/blog/proof-of-concept-exploit-released-for-php-vulnerabilities-109618-109619>
3. Arctic Wolf (updated 23 Oct 2026): <https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/>
4. Cowrai (22 Oct 2026): <https://cowrai.com/research/php2shell-godofthunder/>
5. VulnCheck (21 Oct 2026, updated 23 Oct): <https://www.vulncheck.com/blog/php2shell-vulnerabilities>
6. PHP.net (23 Oct 2026): <https://www.php.net/archive/2026.php#2026-10-23-1>
7. The Hacker News (23 Oct 2026): <https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html>
