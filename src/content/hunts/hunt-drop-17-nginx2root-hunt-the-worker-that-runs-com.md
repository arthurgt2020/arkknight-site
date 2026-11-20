---
title: "Hunt Drop 17 | nginx2root: hunt the worker that runs commands"
hypothesis: "An nginx worker process starts a shell or download tool after exploitation of the HTTP/2 flaws."
attack: [T1190, T1059.004, T1105, T1068]
dataSources: ["Linux EDR process events", "Process lineage"]
languages: [KQL, CQL]
drop: 17
risk: { likelihood: 3, impact: 5 }
status: published
date: 2026-11-18
---

Builds on [Intel Drop 44](/intel/intel-drop-44-nginx2root-http2/).

## The hypothesis
If CVE-2026-123007 or CVE-2026-123633 is used against one of our nginx servers, the exploit may leave little in the access log. But an nginx worker has no normal reason to run a shell or download tool.

WHAT TO HUNT (ATT&CK mapping is my own)
- nginx worker spawning sh, bash, curl, wget, python or perl (T1190, T1059.004, T1105)
- Root-level activity after a worker shell, since researchers chained a kernel flaw to reach root (T1068)
- nginx below 1.30.7 stable or 1.31.9 mainline with HTTP/2 enabled
- Non-EDR signals: worker "signal 11" crashes and long-lived HTTP/2 connections with heavy inbound traffic

## Business risk
nginx fronts websites, APIs and reverse proxies, so one unauthenticated flaw reaches many hosts. Researchers report working exploits but have not released them, and no exploitation is reported. Risk score: Likelihood 3 × Impact 5 = 15/25, CRITICAL (analyst judgement, same as the Intel Drop).

## Tune & triage
Check packaged versions against distro advisories, since backports can hide the real fix. A reload does not replace the running binary, so restart. On a hit, isolate and treat the host as root-compromised until proven otherwise.

**Risk: 15/25 CRITICAL** (likelihood 3 × impact 5, analyst judgement). Intel confidence: MODERATE. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// HUNT DROP #17 - nginx2root CVE-2026-123007 / CVE-2026-123633 (builds on Intel Drop #44)
// UNTESTED in a live tenant. Test and tune before use. Default window 14 days.
// ATT&CK: none given by the sources; all IDs below are ANALYST mappings.
// Schema checked in this run (learn.microsoft.com en-us): DeviceProcessEvents, DeviceNetworkEvents, DeviceTvmSoftwareInventory.
// The learn pages do not state Linux support for these tables; confirm Defender for Endpoint on Linux coverage on nginx hosts.
// Other signals (worker crashes, HTTP/2 flood) are NOT visible to EDR: see the non-EDR section in the notes file.

// ===== Hunt 1: nginx worker runs a shell, scripting tool or download tool (core behaviour) =====
// Hunt Drop #17 | ATT&CK: T1190, T1059.004, T1105 (analyst)
// Hypothesis: a successful exploit runs commands as the worker; Xint: "A normal nginx worker has no reason to run external programs".
// Expected noise: very low. Check for custom nginx lua/exec modules or management scripts spawned by nginx.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "nginx"
| where FileName in~ ("sh","bash","dash","zsh","ash","busybox","python","python3","perl","php","ruby","nc","ncat","socat","curl","wget")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc

// ===== Hunt 2: baseline - ANY child process of nginx other than nginx =====
// Hunt Drop #17 | ATT&CK: T1190, T1059.004 (analyst)
// Hypothesis: widens Hunt 1 to unknown tools; legitimate children are rare and become an allow-list.
// Expected noise: low to medium; nginx -s reload via logrotate normally has logrotate/sh as the parent, not nginx.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "nginx"
| where FileName !~ "nginx"
| summarize Execs=count(), Hosts=dcount(DeviceName), Sample=take_any(ProcessCommandLine) by FileName
| order by Execs desc

// ===== Hunt 3: process running as root whose initiating process runs as a typical web account =====
// Hunt Drop #17 | ATT&CK: T1068 (analyst; Xint chained a separate Linux SCTP kernel flaw to root, CIRCL: initial code runs as the worker, not root)
// Hypothesis: after a worker shell, a root-owned process appears under a web-account parent.
// Expected noise: sudo/su helpers, cron; tune account names to your nginx user (nginx, www-data, nobody, www).
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessAccountName in~ ("nginx","www-data","nobody","www","www-run")
| where AccountName =~ "root"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc

// ===== Hunt 4: exposure scoping - nginx versions not yet fixed =====
// Hunt Drop #17 | exposure scoping
// Fixed: 1.30.7 (stable) and 1.31.9 (mainline) per Wiz, Equixly, Cycode (CIRCL names only 1.31.9). CVE-2026-123007 affects 1.9.5 to 1.31.8; other nginx CVEs reach back further (sources disagree on exact first versions).
// Caveat: distro packages backport fixes without changing the upstream number (Xint, Equixly), so check the distro advisory before treating a hit as vulnerable or a miss as safe.
// Also requires HTTP/2 for 123007 and 123633: check nginx -T on each host (listen ... http2 / http2 on).
DeviceTvmSoftwareInventory
| where SoftwareName has "nginx"
| extend Ver = extract(@"^(\d+\.\d+\.\d+)", 1, SoftwareVersion)
| where isnotempty(Ver)
| where parse_version(Ver) < parse_version("1.30.7")
    or (parse_version(Ver) >= parse_version("1.31.0") and parse_version(Ver) < parse_version("1.31.9"))
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion
| order by DeviceName asc

// ===== Hunt 5: exposure scoping - internet-facing nginx listeners =====
// Hunt Drop #17 | exposure scoping | patch order
// ActionType "InboundConnectionAccepted" is not listed on the official page (values not documented there); it appears in a community Java4Shell query (screenshot of a LinkedIn post) - verify in your tenant.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName =~ "nginx"
| where RemoteIPType in ("Public","FourToSixMapping")
| summarize Conns=count(), RemoteIPs=dcount(RemoteIP), LastSeen=max(Timestamp) by DeviceName, LocalPort
| order by Conns desc
```

## CrowdStrike Falcon (CQL)

```
// HUNT DROP #17 - nginx2root CVE-2026-123007 / CVE-2026-123633 (builds on Intel Drop #44)
// UNTESTED. Set the time picker to the last 14 days. ATT&CK IDs are ANALYST mappings (sources give none).
// CQL double-check: cqlsearch.com NOT reachable this run (URL_NOT_ON_ALLOWLIST). Fallback: CrowdStrike Log4Shell blog + community mirrors. See notes.
// Worker crash and HTTP/2-flood signals are not Falcon endpoint events: see the non-EDR section in the notes file.

// ===== Hunt 1: nginx parent -> shell / scripting tool / download tool =====
// Hunt Drop #17 | ATT&CK: T1190, T1059.004, T1105 (analyst)
// Hypothesis: a successful exploit runs commands as the nginx worker (Xint).
// Expected noise: very low. Check custom modules or scripts that nginx legitimately launches.
// Time picker: 14 days
#event_simpleName=ProcessRollup2 event_platform=Lin
| ParentBaseFileName=nginx
| FileName=/^(sh|bash|dash|zsh|ash|busybox|python[0-9.]*|perl|php|ruby|nc|ncat|socat|curl|wget)$/i
| groupBy([aid, ComputerName, FileName], function=[count(aid, as=Execs), collect([CommandLine])])
| sort(Execs, order=desc)

// ===== Hunt 2: baseline - ANY child of nginx other than nginx =====
// Hunt Drop #17 | ATT&CK: T1190, T1059.004 (analyst)
// Hypothesis: finds unknown tools; whatever remains after tuning is the allow-list.
// Expected noise: low to medium.
// Time picker: 14 days
#event_simpleName=ProcessRollup2 event_platform=Lin ParentBaseFileName=nginx
| FileName!=/^nginx$/i
| groupBy([FileName], function=[count(aid, as=Execs), count(aid, distinct=true, as=Hosts)])
| sort(Execs, order=desc)
```

Queries are untested: tune before use.

## Sources

1. Xint (discoverer) (18 Nov 2026): <https://xint.io/blog/nginx2root-remote-code-execution>
2. Wiz (co-discoverer) (18 Nov 2026): <https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities>
3. CIRCL (Luxembourg CERT) (18 Nov 2026): <https://www.circl.lu/pub/tr-105/>
4. Equixly (18 Nov 2026): <https://equixly.com/blog/2026/11/18/nginx2root-disabling-http-2-stops-two-of-five-nginx-rce-flaws/>
5. Cycode via Security Boulevard (18 Nov 2026): <https://securityboulevard.com/2026/11/nginx2root-cve-2026-123007-and-four-more-unauthenticated-remote-code-execution-in-nginx/>
