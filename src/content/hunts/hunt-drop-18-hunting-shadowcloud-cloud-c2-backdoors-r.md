---
title: "Hunt Drop 18 | Hunting ShadowCloud: cloud-C2 backdoors riding MeshCentral"
hypothesis: "A MeshCentral agent drops a legitimate EXE, a rogue DLL and an encrypted payload, then the loader talks to GitHub, SharePoint or Ably."
attack: [T1219, T1105, T1574.002, T1102, T1056.001]
dataSources: ["Process events", "Image-load events", "File events", "Network and DNS events"]
languages: [KQL, CQL]
drop: 18
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-20
---

Builds on [Intel Drop 47](/intel/intel-drop-47-shadowcloud-gitdoor-graphdoor/).

## The hypothesis
If ShadowCloud-style tradecraft reached our estate, a MeshCentral agent will have dropped a legitimate EXE, a rogue DLL and an encrypted payload, and the loader will then talk to GitHub, SharePoint or Ably instead of obvious attacker infrastructure.

## What to hunt
- Mesh agent writing EXE/DLL/config.ini into user-writable folders (T1219, T1105)
- Sideload pairs such as start.exe + SbieDll.dll or pythonw.exe + python39.dll outside Program Files (T1574.002, analyst mapping)
- Those binaries calling GitHub, SharePoint or Ably (T1102, analyst mapping)
- Keylog and staging artefacts: logs.dat under SystemCertificates\Cache, Intel_Log (T1056.001, analyst mapping)

## Business risk
Government-focused targeting makes this relevant to GCC public-sector and critical-infrastructure networks. Cloud C2 over trusted SaaS blends into allowed traffic, so a foothold can sit unseen while credentials are harvested. Risk score: Likelihood 3 × Impact 4 = 12/25, HIGH (analyst judgement, consistent with the Intel Drop).

## Tune & triage
Allow-list your sanctioned MeshCentral and genuine Sandboxie/Python paths. On a hit: isolate, preserve the loader folder, review the Mesh server, revoke cloud tokens, and escalate to IR if a rogue loader pair is confirmed.

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: MODERATE. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// ===== Hunt Drop #18 | Defender XDR Advanced Hunting (KQL) =====
// Builds on Intel Drop #47 (Operation ShadowCloud: GitDoor / GraphDoor). UNTESTED in a live tenant: test and tune before use.
// Window: 14 days. Analyst-mapped ATT&CK unless the source states it (Kaspersky sources give no ATT&CK IDs).

// ---- H1 | T1219, T1105 | Hypothesis: a MeshCentral agent drops a legit EXE + rogue DLL + encrypted payload (config.ini) into a writable folder
// Expected noise: legitimate MeshCentral admin/software pushes. Tune: allow-list your own Mesh server's tooling.
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName has "mesh"   // analyst assumption: agent binary name contains "mesh"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName =~ "config.ini"
| where FolderPath !startswith @"C:\Windows\" and FolderPath !startswith @"C:\Program Files"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath
| order by Timestamp desc

// ---- H2 | T1574.002 (analyst) | Hypothesis: named loader EXEs load named rogue DLLs from outside Program Files/Windows
// Expected noise: real Sandboxie, Python 3.9 apps, CEF apps (libcef.dll), ZoomIt. Tune: allow-list by path + signer.
let loaders = dynamic(["start.exe","pythonw.exe","zoomit.exe"]);
let rogueDlls = dynamic(["jli.dll","sbiedll.dll","python39.dll","winmm.dll","libcef.dll"]);
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where tolower(FileName) in (rogueDlls)
| where tolower(InitiatingProcessFileName) in (loaders)
| where FolderPath !startswith @"C:\Windows\" and FolderPath !startswith @"C:\Program Files"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath
| order by Timestamp desc

// ---- H3 | T1102, T1071.001 (analyst) | Hypothesis: those loaders talk to GitHub / SharePoint / Microsoft sign-in / Ably
// Expected noise: Python scripts using GitHub. Tune: allow-list known dev hosts. "ably" match is an analyst assumption.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where tolower(InitiatingProcessFileName) in ("start.exe","pythonw.exe","zoomit.exe")
| where InitiatingProcessFolderPath !startswith @"C:\Windows\" and InitiatingProcessFolderPath !startswith @"C:\Program Files"
| where RemoteUrl has_any ("api.github.com","githubusercontent.com","sharepoint.com","login.microsoftonline.com","ably")
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| order by Hits desc

// ---- H3b | IOC sweep (published by THN): ShadowCloud MeshCentral C2 host 27.102.66.162:443 (agent.ashx)
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP == "27.102.66.162"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl

// ---- H4 | T1056.001 (analyst) | Hypothesis: keylog / staging artefacts named in the reporting
// Expected noise: low (logs.dat under SystemCertificates\Cache is unusual). Intel_Log path per THN/Gridinsoft.
DeviceFileEvents
| where Timestamp > ago(14d)
| where (FileName =~ "logs.dat" and FolderPath has @"\Microsoft\SystemCertificates\Cache")
    or FolderPath has @"\Intel_Log"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath

// Promotion note: after tuning, H2 (loader+rogue DLL outside standard paths) and H3b could become a Defender custom detection, threshold: any single hit on H3b, or H2 on >=1 device with unsigned/unknown loader folder.
```

## CrowdStrike Falcon (CQL)

```
// ===== Hunt Drop #18 | CrowdStrike Falcon (CQL / Advanced Event Search) =====
// Builds on Intel Drop #47 (Operation ShadowCloud: GitDoor / GraphDoor). UNTESTED in a live tenant: test and tune before use.
// Time picker: set to last 14 days. Analyst-mapped ATT&CK unless the source states it.
// "UNVERIFIED" marks syntax or fields not confirmed in docs fetched this run (cqlsearch.com was blocked).

// ---- H1 | T1219 (analyst), T1105 | Hypothesis: children of a Mesh agent running from writable folders
// Expected noise: legitimate MeshCentral admin actions. Tune: allow-list your Mesh server's tooling.
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/mesh/i
| ImageFileName!=/\\(Program Files|Program Files \(x86\)|Windows)\\/i   // UNVERIFIED: negated regex form
| groupBy([aid, ComputerName, ParentBaseFileName, ImageFileName], function=[count(as=runs), collect([CommandLine])])
| sort(runs, order=desc)

// ---- H2 | T1574.002 (analyst) | Hypothesis: named loader EXEs executing outside standard paths
// Expected noise: real Sandboxie / Python / ZoomIt installs. Tune: allow-list path + signer.
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(start|pythonw|zoomit)\.exe$/i
| ImageFileName!=/\\(Program Files|Program Files \(x86\)|Windows)\\/i   // UNVERIFIED: negated regex form
| groupBy([aid, ComputerName, ImageFileName, ParentBaseFileName], function=[count(as=runs), collect([CommandLine])])
| sort(runs, order=desc)

// ---- H3 | T1102 (analyst) | Hypothesis: loader processes resolving GitHub / SharePoint / Ably names
// Expected noise: Python scripts using GitHub. UNVERIFIED: ContextBaseFileName on DnsRequest; "ably" match is an analyst assumption.
#event_simpleName=DnsRequest event_platform=Win
| ContextBaseFileName=/^(start|pythonw|zoomit)\.exe$/i
| DomainName=/(api\.github\.com|githubusercontent\.com|sharepoint\.com|login\.microsoftonline\.com|ably)/i
| groupBy([aid, ComputerName, ContextBaseFileName, DomainName], function=[count(as=lookups)])
| sort(lookups, order=desc)

// ---- H3b | IOC sweep (published by THN): ShadowCloud MeshCentral C2 27.102.66.162
// UNVERIFIED: event name NetworkConnectIP4 not seen on pages read this run (RemoteAddressIP4 field is shown in the LogScale Query Primer).
#event_simpleName=NetworkConnectIP4 event_platform=Win RemoteAddressIP4="27.102.66.162"
| table([@timestamp, aid, ComputerName, ContextBaseFileName, RemoteAddressIP4, RemotePort])

// Promotion note: after tuning, H3b (any hit) and H2 (loader in a non-standard folder, rare parent) could become a Falcon correlation rule / custom IOA.
```

Queries are untested: tune before use.

## Sources

1. Kaspersky (2026-11-17): <https://kaspersky.com/about/press-releases/kaspersky-operation-shadowcloud-targets-government-networks-across-asia-and-africa>
2. The Hacker News (2026-11-17): <https://thehackernews.com/2026/11/new-gitdoor-and-graphdoor-backdoors.html>
3. Gridinsoft (2026-11-17 (mod. 18 Nov)): <https://blog.gridinsoft.com/shadowcloud-gitdoor-graphdoor-cloud-backdoors/>
4. Security MEA (2026-11-17): <https://securitymea.com/?p=69432>
