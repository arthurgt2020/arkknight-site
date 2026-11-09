---
title: "Hunt Drop 04 | Hiding in plain System32"
hypothesis: "Trusted software spawns a LOLBin host, then a renamed Windows binary side-loads a DLL."
attack: [T1055, T1543.003, T1036.005, T1574.001, T1087.002, T1102.002]
dataSources: ["Process events", "Image-load events", "File events", "Network and DNS events"]
languages: [KQL, CQL]
drop: 4
risk: { likelihood: 1, impact: 4 }
status: published
date: 2026-10-23
---

Builds on [Intel Drop 11](/intel/intel-drop-11-lazarus-flashhole/).

## The hypothesis
If Lazarus FlashHole-style tradecraft reached our endpoints, we expect a trusted process launching fsquirt.exe as an injection host, then a renamed Windows binary running as a service from a new System32 sub-folder and side-loading a DLL.

## What to hunt
- fsquirt.exe (Bluetooth file transfer wizard) with an unusual parent or internet traffic (T1055)
- New services pointing into System32 sub-folders, run by a Microsoft binary whose name doesn't match its original file name (T1543.003, T1036.005)
- mscoree.dll loaded or written outside System32/SysWOW64 (T1574.001)
- LDAP queries and GitHub/Dropbox API calls from those masqueraded processes (T1087.002, T1102.002)

## Business risk
FlashHole's entry point is Korean banking security software, so direct exposure in the GCC is low. The value is the tradecraft: trusted software, signed binaries and cloud-service C2 all blend into normal noise.
Risk score (analyst judgement): Likelihood 1 × Impact 4 = 4/25, LOW

## Tune & triage
Baseline services in System32 sub-folders once, then allow-list by path and signer. On fsquirt.exe egress or a non-standard mscoree.dll: pull the process tree, check for timestomping, contain the host.
Queries are untested in your environment: test and tune them before use.

**Risk: 4/25 LOW** (likelihood 1 × impact 4, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM-HIGH.

## Microsoft Defender (KQL)

```kusto
// Microsoft Defender (KQL) | Hunt Drop #04 | UNTESTED: tune before use

// T1055: fsquirt.exe talking to the internet
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "fsquirt.exe" and RemoteIPType == "Public"
| summarize Conns=count(), Urls=make_set(RemoteUrl,20) by DeviceName, InitiatingProcessParentFileName

// T1036.005: renamed MS binary run as a service from a System32 sub-folder
DeviceProcessEvents
| where Timestamp > ago(14d) and InitiatingProcessFileName =~ "services.exe"
| where FolderPath matches regex @"(?i)^c:\\windows\\system32\\[^\\]+\\[^\\]+\.exe$"
| extend Orig = replace_regex(ProcessVersionInfoOriginalFileName, @"(?i)\.mui$", "")
| where isnotempty(Orig) and FileName !~ Orig
| summarize Hosts=dcount(DeviceId) by FileName, Orig, FolderPath

// T1574.001: mscoree.dll loaded from a non-standard path
DeviceImageLoadEvents
| where Timestamp > ago(14d) and FileName =~ "mscoree.dll"
| where not(FolderPath matches regex @"(?i)^c:\\windows\\(system32|syswow64|winsxs\\.+)\\mscoree\.dll$")
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName

T1543.003, T1087.002, T1102.002 + IOC sweep in the files.
```

## CrowdStrike Falcon (CQL)

```
// CrowdStrike Falcon (CQL) | Hunt Drop #04 | UNTESTED: tune before use
Time picker: last 14 days

// T1055: fsquirt.exe with an unusual parent
#event_simpleName=ProcessRollup2
| ImageFileName=/\\fsquirt\.exe$/i
| !in(field="ParentBaseFileName", ignoreCase=true, values=["explorer.exe","SystemSettings.exe"])
| table([@timestamp, aid, UserName, ParentBaseFileName, CommandLine])

// T1543.003: service created with a binary in a System32 sub-folder
#event_simpleName=CreateService
| ServiceImagePath=/system32\\[^\\]+\\[^\\]+\.exe/i
| groupBy([ServiceImagePath, ServiceDisplayName], function=[count(), collect([aid])])
| _count < 20

// T1036.005: services.exe child running from a System32 sub-folder
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^services\.exe$/i
| ImageFileName=/\\Windows\\System32\\[^\\]+\\[^\\]+\.exe$/i
| groupBy([ImageFileName, CommandLine], function=[count(), collect([aid])])
| _count < 20
```

Queries are untested: tune before use.

## Sources

1. Kaspersky Securelist (21 Oct 2026): https://securelist.com/lazarus-operation-flashhole/121541/
2. BleepingComputer (21 Oct 2026): https://www.bleepingcomputer.com/news/security/lazarus-hackers-use-post-quantum-cryptography-for-malware-delivery/
3. MITRE ATT&CK T1574.001: https://attack.mitre.org/techniques/T1574/001/
