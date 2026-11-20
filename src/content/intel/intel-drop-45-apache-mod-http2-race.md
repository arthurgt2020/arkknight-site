---
title: "Intel Drop 45 | Apache httpd mod_http2 (CVE-2026-119618): race condition, reported exploitation"
type: intel-drop
drop: 45
motivation: unknown
sectors: []
regions: []
attack: [T1190]
risk: { likelihood: 4, impact: 4 }
tlp: CLEAR
summary: "A race condition in Apache httpd 2.4.55 to 2.4.70 can corrupt the heap; Singapore's CSA reports active exploitation and a public PoC, but Apache has not confirmed it. Fixed in 2.4.71."
date: 2026-11-18
---

A race condition in Apache httpd 2.4.55 to 2.4.70 (mod_http2) can corrupt the heap. Singapore's CSA reports active exploitation and a public PoC, but Apache has not confirmed it. Fixed in 2.4.71.

Posted together with [Intel Drop 43](/intel/intel-drop-43-java4shell-openjdk/), [Intel Drop 44](/intel/intel-drop-44-nginx2root-http2/).

## Attack chain

1. **Reach**. HTTP/2 requests to a public Apache host (T1190).
2. **Race**. Heap corruption in mod_http2.

## Risk

**16/25 CRITICAL** (likelihood 4 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Flaw and fix (Apache) | HIGH |
| Active exploitation (CSA only) | LOW to MODERATE (unconfirmed by Apache) |

## Business risk

One unpatched web or Java layer can expose every service behind it, including identity and collaboration systems. Public PoCs shorten the time to attack.

## What to do now

- Inventory Java runtimes, nginx and Apache hosts, internet-facing first, including bundled copies.
- Patch and restart, then verify the running process, not the package.
- Hunt for web or Java processes spawning shells.
- If delayed: Protocols http/1.1.

## Sources

1. Singapore CSA alert AL-2026-164 (17 Nov 2026): <https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-164/>
2. Apache httpd security advisories (fix 11 Nov 2026): <https://httpd.apache.org/security/vulnerabilities_24.html>
