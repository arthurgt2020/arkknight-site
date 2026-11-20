---
title: "Intel Drop 43 | Java4Shell (CVE-2026-114938): pre-login RCE in OpenJDK HotSpot"
type: intel-drop
drop: 43
motivation: unknown
sectors: []
regions: []
attack: [T1190, T1059]
risk: { likelihood: 3, impact: 5 }
tlp: CLEAR
summary: "A Base64 decoder flaw in OpenJDK's x86-64 HotSpot (AVX-512 hardware) is reachable before login; Oracle patched on 17 Nov and CISA urges immediate patching. No exploitation in the wild is reported yet."
date: 2026-11-18
---

A Base64 decoder flaw in OpenJDK's x86-64 HotSpot (AVX-512 hardware) is reachable before login. Oracle patched on 17 Nov and CISA urges immediate patching. Researchers showed pre-login RCE on Keycloak, Jira, Confluence and Jenkins. No in-the-wild exploitation is reported yet.

Posted together with [Intel Drop 44](/intel/intel-drop-44-nginx2root-http2/), [Intel Drop 45](/intel/intel-drop-45-apache-mod-http2-race/).

## Attack chain

1. **Reach**. Pre-login request hits the Base64 decoder (T1190).
2. **Corrupt**. Memory corruption in HotSpot on AVX-512 x86-64.
3. **Run**. Code execution in the Java process (T1059).

## Risk

**15/25 CRITICAL** (likelihood 3 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Flaw and fix (vendor and CISA) | HIGH |
| Exploitation in the wild | NONE reported |

## Business risk

One unpatched web or Java layer can expose every service behind it, including identity and collaboration systems. Public PoCs shorten the time to attack.

## What to do now

- Inventory Java runtimes, nginx and Apache hosts, internet-facing first, including bundled copies.
- Patch and restart, then verify the running process, not the package.
- Hunt for web or Java processes spawning shells.
- If delayed: -XX:-UseBASE64Intrinsics.

## Sources

1. Wiz (17 Nov 2026): <https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk>
2. Tenable (17 Nov 2026): <https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability>
3. The Hacker News on CISA alert (18 Nov 2026): <https://thehackernews.com/2026/11/cisa-urges-immediate-patching-of.html>
4. Oracle JDK 17.0.21.1 release notes (17 Nov 2026): <https://www.oracle.com/java/technologies/javase/17-0-21-1-relnotes.html>
