---
title: "Intel Drop 20 | HTTP2Shell: one Brotli bug, many stacks, now exploited"
type: intel-drop
drop: 20
attack: [T1190]
risk: { likelihood: 4, impact: 4 }
tlp: CLEAR
summary: "CVE-2026-111497 was added to the CISA Known Exploited Vulnerabilities catalogue on 27 Oct 2026."
date: 2026-10-29
---

CISA added CVE-2026-111497 (also called HTTP2Shell, Node2Shell, Broccoli2Shell) to its Known Exploited Vulnerabilities catalogue on 27 October. It is a memory-corruption flaw in Google's Brotli decoder (versions 1.0.3 to 1.2.0), so it travels wherever Brotli is bundled: Node.js, Python packages, Envoy, Istio, Bun, .NET, PAN-OS 12.2/12.1/11.2 and VMware SDDC Manager.

What the evidence says, and what it doesn't. CISA gave no attack details. ELLIO reported in-the-wild exploit traffic from an operator it links to mass exploitation; public proofs of concept exist and Imperva demonstrated code execution against an official Node.js image. Microsoft and Palo Alto Networks said they had no evidence of exploitation of their products. In our assessment, internet-facing Node.js services are the most likely first casualties.

The trap: Brotli is compiled into runtimes and container images, so a patched OS package can still leave vulnerable copies running.

## Where the bug hides

1. Web runtimes and libraries: Node.js, Python brotli, Bun, Express 5 (T1190)
2. Proxies and service mesh: Envoy, Istio with Brotli decompression
3. Vendor products: .NET (opt-in), PAN-OS 12.2/12.1/11.2, SDDC Manager
4. Crash, restart, retry: failed attempts crash the service and restarts allow retries

## Risk

**16/25 CRITICAL** (likelihood 4 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Vulnerability impact | HIGH |
| In-the-wild exploitation | MODERATE |
| Exploitation of named vendors | NOT CONFIRMED |

## Business risk

Customer-facing web services and infrastructure appliances could be taken over remotely, and failed attempts simply crash and restart the service.

## What to do now

- Patch Node.js, Brotli libraries and vendor products; rebuild containers and self-contained apps.
- Apply VMware's workaround for SDDC Manager while its patch is pending.
- Block Brotli-encoded request bodies where clients don't need them.
- Alert on repeated crash-and-restart cycles in web services.

## Sources

1. BleepingComputer (26 Oct 2026): <https://www.bleepingcomputer.com/news/security/critical-http2shell-brotli-vulnerability-triggers-emergency-patches/>
2. SQ Magazine, CISA KEV (28 Oct 2026): <https://sqmagazine.co.uk/cisa-confirms-exploiting-brotli-node2shell-flaw/>
3. Help Net Security (27–28 Oct 2026): <https://www.helpnetsecurity.com/?p=389353>
4. Daily Security Review, Microsoft & Palo Alto (27 Oct 2026): <https://dailysecurityreview.com/?p=44991>
5. Daily CyberSecurity, VMware VMSA-2026-0008 (28 Oct 2026): <https://securityonline.info/vmware-sddc-manager-vulnerability-cve-2026-111497/>
6. Tanium (27 Oct 2026): <https://www.tanium.com/blog/http2shell-brotli-rce-huntiq>
