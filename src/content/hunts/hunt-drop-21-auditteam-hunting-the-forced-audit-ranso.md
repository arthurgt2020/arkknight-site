---
title: "Hunt Drop 21 | AuditTeam: Hunting the Forced-Audit Ransomware"
hypothesis: "A signed antivirus driver kills security tools, then backup and database services are stopped and shadow copies deleted."
attack: [T1543.003, T1562.001, T1490, T1489, T1102, T1071.001]
dataSources: ["Process events", "File events", "Network events"]
languages: [KQL, CQL]
drop: 21
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-27
---

Builds on [Intel Drop 46](/intel/intel-drop-46-auditteam-opsagent/).

Threat Intelligence · Arkknight
https://arkknight.si

HUNT DROP 🧠 21 | AuditTeam: Hunting the "Forced Audit" Ransomware
Builds on Intel Drop 🧠 46

## The hypothesis
If AuditTeam's OpsAgent framework reached our estate, the loudest traces sit just before encryption: a signed antivirus driver killing security tools, then backup and database services stopped and shadow copies deleted.

## What to hunt
- New kernel driver service or .sys drop followed by security-tool failures (T1543.003, T1562.001, analyst mapping)
- Shadow-copy deletion plus stopped backup/database services in one window (T1490, T1489)
- Non-browser processes fetching from GitHub or CloudFront, the reported C2 lookup path (T1102, T1071.001)

## Business risk
Kaspersky reports dozens of victims in at least seven countries and a ransom note styled as an "audit" for executives and legal teams. For a GCC SOC the exposure is lost backups, disclosure threats and downtime. Risk score: Likelihood 3 × Impact 4 = 12/25, HIGH (analyst judgement, consistent with Intel Drop 🧠 46).

## Tune & triage
Allow-list backup and patch agents by signer and parent. On a hit: isolate, keep the driver and memory, verify offline backups, review GitHub/CloudFront egress from the same host.

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: MODERATE. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #21 - AuditTeam / OpsAgent "forced audit" ransomware (builds on Intel Drop #46)
// UNTESTED in a live tenant. Test and tune before use. Window: 14 days (Timestamp > ago(14d)).
// ATT&CK mappings are ANALYST mappings: the Kaspersky release gives no ATT&CK IDs.
// =====================================================================

// ---- H1: signed driver installed to kill security tools ----
// Hypothesis: OpsAgent add-on installs a signed AV driver (GridinSoft names kvcore.sys, Beijing Jiangmin) and kills ~220 security/backup/DB processes.
// ATT&CK: T1543.003, T1562.001 (analyst). Expected noise: legitimate AV/EDR/backup driver installers, imaging tools. Allow-list by signer/parent/path.
// H1a - .sys written outside driver locations by a non-system, non-Program Files process
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName endswith ".sys"
| where not(FolderPath startswith @"C:\Windows\System32\drivers" or FolderPath startswith @"C:\Windows\System32\DriverStore" or FolderPath startswith @"C:\Windows\WinSxS")
| where not(InitiatingProcessFolderPath startswith @"C:\Windows\" or InitiatingProcessFolderPath startswith @"C:\Program Files")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine

// H1b - kernel-driver service created from the command line
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "sc.exe" and ProcessCommandLine has "create" and ProcessCommandLine has_any ("type= kernel","type=kernel","type= kernel ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath

// H1c - IOC-style sweep for the secondary-source driver name (GridinSoft lead, not primary)
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName =~ "kvcore.sys"
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine

// ---- H2: pre-encryption impact (shadow copies, backup/DB service stops) ----
// ATT&CK: T1490, T1489 (analyst). Expected noise: backup software maintenance, DBA patching windows. Tune: allow-list by parent and admin account; keep the Hits threshold.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ((FileName in~ ("vssadmin.exe","wbadmin.exe","bcdedit.exe") or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy"))
    and ProcessCommandLine has_any ("delete shadows","delete catalog","delete backup","shadowcopy delete","recoveryenabled no"))
  or (FileName in~ ("net.exe","net1.exe","sc.exe") and ProcessCommandLine has " stop "
    and ProcessCommandLine has_any ("sql","oracle","veeam","backup","postgres","mysql"))
| summarize Hits=count(), Cmds=make_set(ProcessCommandLine,5), Parents=make_set(InitiatingProcessFileName,5) by DeviceName, bin(Timestamp,15m)
| where Hits >= 3

// ---- H3: C2 address lookup via GitHub / CloudFront by a non-browser process ----
// ATT&CK: T1102, T1071.001 (analyst). Kaspersky: C2 address fetched from a public GitHub repo; GridinSoft: later traffic via CloudFront subdomains.
// Expected noise: developer tools, updaters, CI agents. Tune: allow-list by signer/folder; rank by rarity per device.
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any ("raw.githubusercontent.com","api.github.com") or RemoteUrl endswith ".cloudfront.net"
| where InitiatingProcessFileName !in~ (browsers)
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files" or InitiatingProcessFolderPath startswith @"C:\Windows\")
| summarize Conns=count(), Urls=make_set(RemoteUrl,5), First=min(Timestamp), Last=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Conns desc

// Proactive note (hunting, not detection): once tuned, H2 (Hits >= 3 in 15 min outside backup/DBA parents) could be promoted to a Defender custom detection.
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #21 - AuditTeam / OpsAgent "forced audit" ransomware (builds on Intel Drop #46)
// UNTESTED in a live Falcon tenant. Test and tune before use. Time picker: last 14 days.
// ATT&CK mappings are ANALYST mappings (the Kaspersky release gives none).
// Lines marked UNVERIFIED use a field/event not confirmed in the public docs fetched this run.
// =====================================================================

// ---- H1: signed driver installed to kill security tools (T1543.003, T1562.001) ----
// Noise: legitimate AV/EDR/backup driver installers. Tune by parent/path.
// H1a - kernel-driver service created from the command line
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\sc\.exe$/i
| CommandLine=/\bcreate\b/i CommandLine=/type=\s*kernel/i
| table([@timestamp, aid, ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)

// H1b - secondary-source driver name sweep (GridinSoft lead, not primary). PeFileWritten + TargetFileName confirmed in CrowdStrike Query Primer.
#event_simpleName=PeFileWritten event_platform=Win
| TargetFileName=/kvcore\.sys$/i
| table([@timestamp, aid, ComputerName, TargetFileName, ContextBaseFileName], limit=200)
// UNVERIFIED: ContextBaseFileName on PeFileWritten (not seen in fetched docs).

// ---- H2: pre-encryption impact (T1490, T1489) ----
// Noise: backup software maintenance, DBA patch windows. Keep the hits threshold; allow-list by parent/admin account.
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(vssadmin|wbadmin|bcdedit|wmic|net1?|sc)\.exe$/i
| CommandLine=/(delete\s+shadows|shadowcopy\s+delete|delete\s+(catalog|backup)|recoveryenabled\s+no|\s+stop\s+\S*(sql|oracle|veeam|backup|postgres|mysql))/i
| groupBy([aid, ComputerName], function=([count(as=hits), collect([CommandLine, ParentBaseFileName])]))
| hits >= 3
| sort(hits, order=desc)

// ---- H3: C2 address lookup via GitHub / CloudFront by a non-browser process (T1102, T1071.001) ----
// Noise: developer tools, updaters, CI agents. Tune by process/path.
#event_simpleName=DnsRequest event_platform=Win
| DomainName=/(^|\.)(raw\.githubusercontent\.com|api\.github\.com)$|\.cloudfront\.net$/i
| ContextBaseFileName!=/^(chrome|msedge|firefox|brave|iexplore|opera)\.exe$/i
| groupBy([aid, ComputerName, ContextBaseFileName], function=([count(as=lookups), collect(DomainName)]))
| sort(lookups, order=desc)
// UNVERIFIED: ContextBaseFileName on DnsRequest (not seen in fetched docs). DnsRequest + DomainName confirmed in the Query Primer.

// Proactive note (hunting, not detection): once tuned, H2 (hits >= 3 outside backup/DBA parents) could become a Falcon correlation rule / custom IOA.
```

Queries are untested: tune before use.

## Sources

1. Kaspersky uncovers AuditTeam ransomware campaign spanning Europe, Asia and Africa <https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-auditteam-ransomware-campaign-spanning-europe-asia-and-africa>
2. AuditTeam Ransomware Calls Its Ransom an Audit Fee <https://blog.gridinsoft.com/auditteam-opsagent-ransomware-audit-fee/>
