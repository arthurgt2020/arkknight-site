---
title: "Hunt Drop 12 | Hunting Operation Snowball: AI-run relays and shells"
hypothesis: An AI-driven operator is relaying TCP through WMI-spawned PowerShell and planting web shells on Java and IIS servers.
attack: [T1047, T1059.001, T1105, T1090, T1505.003, T1548.003, T1543.002]
dataSources: [EDR process events, Network events, File events]
languages: [KQL, CQL]
drop: 12
risk: { likelihood: 3, impact: 5 }
status: published
date: 2026-11-11
---

Builds on [Intel Drop 35](/intel/intel-drop-35-operation-snowball/).

Malbear Labs recovered the workspace of a jailbroken AI harness that spent more than two weeks inside a European telecom and 13 organisations it hosts. The exploits were old; the tradecraft was quiet and script-only. GCC telcos, data-centre operators and MSSPs run the same Java app servers, management agents and legacy databases.

## The hypothesis

If an AI-driven operator reached our estate, we expect hidden, encoded PowerShell spawned by WMI relaying TCP to an outside host on port 21, plus Java app servers or editors spawning shells on Linux.

## What to hunt

Analyst ATT&CK mapping; the source report lists no technique IDs.

- `WmiPrvSE.exe` spawning hidden `powershell -enc` relays (T1047, T1059.001)
- `certutil` pulling binaries over HTTP (T1105)
- PowerShell or Perl connecting out to a public host on port 21 (T1090)
- `java` spawning `sh` or `perl`, a `sudo vi` shell escape, and a new systemd unit (T1505.003, T1548.003, T1543.002)

## Business risk

Subscriber, billing and hosted-organisation data, plus the private keys that protect them. One telecom foothold opened a path to 13 hosted organisations, exactly the exposure MSSPs and hosting providers carry.

**Risk score:** likelihood 3 × impact 5 = **15/25, CRITICAL** (analyst judgement).

## Tune and triage

Allow-list SCCM, Intune and RMM PowerShell by parent and command-line prefix. Baseline Java children per app server. On a hit: decode the script, isolate the host, sweep for web shells and rotate keys found in configs.

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (single primary source, recovered workspace) | MODERATE |
| Detection fidelity | MEDIUM |

## Microsoft Defender (KQL)

Untested: run as hunts and tune before use as detections.

```kql
// H1 WMI → hidden/encoded PowerShell relay (T1047, T1059.001)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where ProcessCommandLine matches regex @"(?i)\s-(e|enc|encodedcommand)\s|\s-w(indowstyle)?\s+hidden"
| summarize Execs=count(), Cmds=make_set(ProcessCommandLine,5) by DeviceName

// H2 PowerShell/Perl → public TCP 21 (T1090)
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 21 and RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe") or InitiatingProcessFileName startswith "perl"
| summarize Conns=count(), IPs=make_set(RemoteIP,10) by DeviceName, InitiatingProcessFileName

// H3 java/w3wp → shell (T1505.003)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName =~ "java" and FileName in~ ("sh","bash","dash","perl"))
   or (InitiatingProcessFileName =~ "w3wp.exe" and FileName in~ ("cmd.exe","powershell.exe"))
| summarize Execs=count(), Cmds=make_set(ProcessCommandLine,5) by DeviceName, FileName
```

## CrowdStrike Falcon (CQL)

Untested: set the time picker to 14 days and tune before use. The port-21 relay and `sudo vi` hunts are in the full pack.

```
// H1 WMI → hidden/encoded PowerShell relay (T1047, T1059.001)
#event_simpleName=ProcessRollup2 event_platform=Win
| in(field="FileName", values=["powershell.exe","pwsh.exe"], ignoreCase=true)
| ParentBaseFileName=/^wmiprvse\.exe$/i
| CommandLine=/\s-(e|enc|encodedcommand)\s|\s-w(indowstyle)?\s+hidden/i
| groupBy([aid, ComputerName], function=[count(as=execs), collect([CommandLine])])

// H3 java/w3wp → shell (T1505.003)
#event_simpleName=ProcessRollup2
| case {
  event_platform=Lin | ParentBaseFileName=/^java$/ | FileName=/^(sh|bash|dash|perl.*)$/;
  event_platform=Win | ParentBaseFileName=/^w3wp\.exe$/i | FileName=/^(cmd|powershell)\.exe$/i;
  }
| groupBy([aid, ComputerName, ParentBaseFileName, FileName], function=[count(as=execs), collect([CommandLine])])

// H2 (port-21 relay, selfJoinFilter) and the sudo vi hunt are in the full pack.
```

## Sources

1. Malbear Labs (8 Nov 2026): <https://malbearlabs.com/posts/operation-snowball-inside-an-autonomous-ai-intrusion-campaign>
2. Cyber Security News (9 Nov 2026): <https://cybersecuritynews.com/jailbroken-deepseek-ai-agent-breach/>
