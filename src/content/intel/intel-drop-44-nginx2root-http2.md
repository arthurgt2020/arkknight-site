---
title: "Intel Drop 44 | nginx2root (CVE-2026-123007, CVE-2026-123633): HTTP/2 RCE"
type: intel-drop
drop: 44
motivation: unknown
sectors: []
regions: []
attack: [T1190, T1203]
risk: { likelihood: 3, impact: 5 }
tlp: CLEAR
summary: "HTTP/2 memory-corruption flaws in nginx, rated 9.2 (CVSS 4.0), allow unauthenticated code execution as the worker process; fixed in 1.30.7 and 1.31.9."
date: 2026-11-18
---

HTTP/2 memory-corruption flaws in nginx, rated 9.2 (CVSS 4.0), allow unauthenticated code execution as the worker process. Wiz and Rapid7 demonstrated it and a Rapid7 PoC is public. Fixed in 1.30.7 and 1.31.9. No exploitation reported.

Posted together with [Intel Drop 43](/intel/intel-drop-43-java4shell-openjdk/), [Intel Drop 45](/intel/intel-drop-45-apache-mod-http2-race/).

## Attack chain

1. **Reach**. Crafted HTTP/2 traffic to a public nginx (T1190).
2. **Corrupt**. Integer underflow leads to memory corruption.
3. **Run**. Code execution as the worker process (T1203).

## Risk

**15/25 CRITICAL** (likelihood 3 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Flaws and fixes (vendor) | HIGH |
| Exploitation in the wild | NONE reported |

## Business risk

One unpatched web or Java layer can expose every service behind it, including identity and collaboration systems. Public PoCs shorten the time to attack.

## What to do now

- Inventory Java runtimes, nginx and Apache hosts, internet-facing first, including bundled copies.
- Patch and restart, then verify the running process, not the package.
- Hunt for web or Java processes spawning shells.
- If delayed: turn http2 off.

## Sources

1. Wiz (18 Nov 2026): <https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities>
2. Rapid7 (18 Nov 2026): <https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/>
3. nginx.org security advisories (Nov 2026): <https://nginx.org/en/security_advisories.html>
