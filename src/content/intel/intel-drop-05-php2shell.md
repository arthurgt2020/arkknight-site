---
title: "Intel Drop 05 | PHP2Shell: critical PHP runtime RCE flaws"
type: intel-drop
drop: 5
attack: [T1190, T1059.004]
risk: { likelihood: 4, impact: 5 }
tlp: CLEAR
summary: "CVSS 9.2, unauthenticated, PHP 5.4 onward affected: two chained memory flaws give remote code execution."
date: 2026-10-21
---

On 21 October, PHP shipped emergency fixes for two flaws, both rated CVSS v4.0 9.2: CVE-2026-109618 (out-of-memory corruption) and CVE-2026-109619 (stale global state). The bugs sit in the PHP runtime itself, so a well-written application is still exposed. Nearly every release since PHP 5.4 is affected, across PHP-FPM, Apache mod_php, php-cgi, FrankenPHP and LiteSpeed. The risk is highest on mod_php, where a demonstrated exploit fires from a single unauthenticated request before any application code runs.

The details leaked a day early. That changed the clock. Several security vendors report in-the-wild exploit attempts around the release, but no successful compromise has been confirmed, and neither CVE is in CISA KEV yet. Palo Alto Networks estimates about 22 million exposed instances. Dutch government portals, including DigiD, went offline as a precaution.

Companion hunt: [Hunt Drop 2](/hunting/hunt-drop-02-php2shell/).

## Attack path

1. Unauthenticated request to any PHP app (T1190)
2. Out-of-memory corruption at setup (CVE-2026-109618)
3. Stale state reused by next request (CVE-2026-109619)
4. RCE: web worker spawns a shell (T1059.004)

## Risk

**20/25 CRITICAL** (likelihood 4 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| In-the-wild attempts | HIGH |

## Business risk

Citizen portals, CMS sites and internal PHP apps could hand attackers code execution, or leak secrets from memory, before patching is done. Patching also means restarts, so plan short service windows.

## What to do now

- Inventory every PHP runtime, including containers, appliances and vendor-hosted ones.
- Patch to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your distro's backport), then restart every worker.
- Until then, set session.upload_progress.enabled=0 and enable WAF rules. These are mitigations, not fixes.
- Hunt for PHP workers spawning shells, curl, wget or certutil.

## Sources

1. PHP security release (21 Oct 2026): <https://www.php.net/archive/2026.php#2026-10-21-5>
2. PHP GHSA, CVE-2026-109618 (21 Oct 2026): <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
3. PHP GHSA, CVE-2026-109619 (21 Oct 2026): <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
4. Wiz Research (21 Oct 2026): <https://www.wiz.io/blog/php2shell-php-rce>
5. The Hacker News (21 Oct 2026): <https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html>
6. SecurityWeek (21 Oct 2026): <https://www.securityweek.com/php2shell-patches-land-as-first-exploitation-attempts-hit-sensors/>
7. Huntress (21 Oct 2026): <https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities>
8. Palo Alto Networks (21 Oct 2026): <https://www.paloaltonetworks.com/blog/2026/10/millions-of-php-instances-exposed-what-organizations-need-to-do-right-now/>
9. Cyb3rMonk KQL hunt: <https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/Uncategorized/PHP2Shell.md>
