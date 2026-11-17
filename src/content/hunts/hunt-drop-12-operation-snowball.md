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

```kql
// =====================================================================
// Hunt Drop #12 | Operation Snowball: AI-run relays and shells
// Builds on Intel Drop #35 (Malbear Labs, 8 Nov 2026)
// Platform: Microsoft Defender XDR Advanced Hunting (Defender for Endpoint P2)
// UNTESTED in a live tenant. Test and tune before any use.
// ATT&CK mappings are ANALYST mappings (the source report lists no ATT&CK IDs).
// Tables/columns verified against Microsoft Learn schema pages (DeviceProcessEvents,
// DeviceNetworkEvents, DeviceFileEvents) on 11 Nov 2026.
// =====================================================================


// ---------------------------------------------------------------------
// H1a | WMI-spawned hidden / encoded PowerShell (TCP relay spawner)
// ATT&CK (analyst): T1047, T1059.001, T1027
// Hypothesis: the operator's spawner created two hidden PowerShell processes via
//   WMI Win32_Process.Create, each carrying a base64-encoded relay. On Windows that
//   shows as WmiPrvSE.exe -> powershell.exe with -enc / -w hidden.
// Expected noise: MEDIUM. SCCM/ConfigMgr, Intune, RMM and some backup/monitoring
//   agents launch PowerShell through WMI. Allow-list by command-line prefix and host role.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where ProcessCommandLine matches regex @"(?i)\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s"
     or ProcessCommandLine matches regex @"(?i)\s-w(in|indow|indowstyle)?\s+hidden"
| summarize Execs = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Accounts = make_set(AccountName, 5), SampleCmds = make_set(ProcessCommandLine, 5)
            by DeviceName, DeviceId
| sort by Execs desc


// ---------------------------------------------------------------------
// H1b | certutil used as a downloader
// ATT&CK (analyst): T1105
// Hypothesis: after JuicyPotato was deleted the operator went script-only and used
//   certutil to download custom binaries.
// Expected noise: LOW-MEDIUM. Some legacy scripts and PKI admins use -urlcache.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("urlcache", "verifyctl")
| where ProcessCommandLine contains "http"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProcessCommandLine
| sort by Timestamp desc


// ---------------------------------------------------------------------
// H2a | Script interpreter talking to a PUBLIC host on TCP 21 (relay channel)
// ATT&CK (analyst): T1090, T1572
// Hypothesis: the decoded relay connects to the harness host on port 21, receives a
//   host:port target and bridges the two. PowerShell (Windows) or Perl (Linux, custom
//   HTTP-to-TCP bridge) making public port-21 connections is rare.
// Expected noise: LOW. Legit FTP clients are not usually powershell/perl.
// ---------------------------------------------------------------------
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 21
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "perl.exe")
     or InitiatingProcessFileName startswith "perl"
| summarize Conns = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            RemoteIPs = make_set(RemoteIP, 10), Cmds = make_set(InitiatingProcessCommandLine, 5)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName
| sort by Conns desc


// ---------------------------------------------------------------------
// H2b | IOC sweep (published by Malbear Labs; infrastructure may already be rotated)
// Note: the Sliver domain is Cloudflare-fronted, so match on RemoteUrl, not IP.
// 146.70.53.182 comes from the report's later section (lower confidence).
// ---------------------------------------------------------------------
let iocDomains = dynamic(["tablacysexplorer.com"]);
let iocIPs = dynamic(["113.23.212.15", "212.46.38.73", "146.70.53.182"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (iocIPs) or RemoteUrl has_any (iocDomains)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc


// ---------------------------------------------------------------------
// H3a | App-server / web-server process spawning a shell or interpreter
// ATT&CK (analyst): T1505.003, T1059.004, T1059.001
// Hypothesis: Behinder/suo5 JSP shells on JBoss/Liferay (java) and an ASPX shell on
//   IIS (w3wp.exe) give command execution, so the server process spawns shells.
// Expected noise: MEDIUM-HIGH on some app servers (health scripts, report jobs).
//   Baseline children per server and allow-list known scripts by full command line.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName =~ "java"
         and (FileName in~ ("sh", "bash", "dash", "curl", "wget") or FileName startswith "perl" or FileName startswith "python"))
     or (InitiatingProcessFileName =~ "w3wp.exe"
         and FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "whoami.exe"))
| summarize Execs = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleCmds = make_set(ProcessCommandLine, 10)
            by DeviceName, InitiatingProcessFileName, FileName, AccountName
| sort by Execs asc   // rare first


// ---------------------------------------------------------------------
// H3b | sudo vi shell escape (Linux privilege escalation after PwnKit was blocked)
// ATT&CK (analyst): T1548.003
// Expected noise: LOW. Admins rarely shell out of vi launched via sudo.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("vi", "vim")
| where InitiatingProcessParentFileName =~ "sudo"
| where FileName in~ ("sh", "bash", "dash")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine


// ---------------------------------------------------------------------
// H3c | New systemd unit written outside package management
// ATT&CK (analyst): T1543.002
// Hypothesis: the operator created a systemd unit for persistent elevated execution.
// Expected noise: MEDIUM. Config-management tools (Ansible, Puppet, Chef) write units:
//   allow-list them by InitiatingProcessFileName.
// ---------------------------------------------------------------------
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath startswith "/etc/systemd/system/" or FolderPath startswith "/lib/systemd/system/"
     or FolderPath startswith "/usr/lib/systemd/system/"
| where FileName endswith ".service"
| where InitiatingProcessFileName !in~ ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "systemd", "packagekitd")
| project Timestamp, DeviceName, ActionType, FolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// Hunt Drop #12 | Operation Snowball: AI-run relays and shells
// Builds on Intel Drop #35 (Malbear Labs, 8 Nov 2026)
// Platform: CrowdStrike Falcon Next-Gen SIEM / Advanced Event Search (CQL)
// Licensing: Falcon Insight XDR (EDR telemetry) + NG-SIEM / Event Search access
// TIME WINDOW: set the time picker to "Last 14 days" before running each query.
// UNTESTED in a live tenant. Test and tune before any use.
// ATT&CK mappings are ANALYST mappings (the source report lists no ATT&CK IDs).
// CQL double-check: cqlsearch.com was NOT reachable from this run (sandbox allowlist);
// checked against CrowdStrike logscale-community-content + library.humio.com instead.
// Lines marked [UNVERIFIED] use syntax/fields not confirmed in a page fetched this run.
// =====================================================================


// ---------------------------------------------------------------------
// H1a | WMI-spawned hidden / encoded PowerShell (TCP relay spawner)
// ATT&CK (analyst): T1047, T1059.001, T1027
// Expected noise: MEDIUM (SCCM/Intune/RMM via WMI). Allow-list by CommandLine prefix.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| in(field="FileName", values=["powershell.exe", "pwsh.exe"], ignoreCase=true)
| ParentBaseFileName=/^wmiprvse\.exe$/i
| CommandLine=/\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s|\s-w(in|indow|indowstyle)?\s+hidden/i
| groupBy([aid, ComputerName], function=[count(as=execs), collect([UserName, CommandLine])])
| sort(execs)   // [UNVERIFIED] default sort order (descending) not confirmed this run


// ---------------------------------------------------------------------
// H1b | certutil used as a downloader
// ATT&CK (analyst): T1105
// Expected noise: LOW-MEDIUM.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^certutil\.exe$/i
| CommandLine=/urlcache|verifyctl/i
| CommandLine=/https?:\/\//i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])


// ---------------------------------------------------------------------
// H2a | PowerShell / Perl connecting to a PUBLIC host on TCP 21 (relay channel)
// ATT&CK (analyst): T1090, T1572
// Pattern follows the community "Listening Programs with low port numbers" query
// (falconPID normalisation + selfJoinFilter).
// Expected noise: LOW.
// ---------------------------------------------------------------------
(#event_simpleName=NetworkConnectIP4 RemotePort=21) OR (#event_simpleName=ProcessRollup2 FileName=/^(powershell\.exe|pwsh\.exe|perl.*)$/i)
| case {
    #event_simpleName=NetworkConnectIP4 | !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]);
    * ;
  }
| falconPID := TargetProcessId | falconPID := ContextProcessId
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=NetworkConnectIP4}, {#event_simpleName=ProcessRollup2}])   // [UNVERIFIED] where= parameter form
| groupBy([aid, ComputerName, falconPID], function=[collect([FileName, CommandLine, RemoteAddressIP4, RemotePort])])
// [UNVERIFIED] RemotePort field name on NetworkConnectIP4 in NG-SIEM (community FDR queries show RemotePort_decimal)


// ---------------------------------------------------------------------
// H2b | IOC sweep (published by Malbear Labs; may already be rotated)
// Sliver domain is Cloudflare-fronted: match DNS, not IP.
// 146.70.53.182 is from the report's later section (lower confidence).
// ---------------------------------------------------------------------
#event_simpleName=/^(DnsRequest|NetworkConnectIP4)$/
| case {
    #event_simpleName=DnsRequest | DomainName=/tablacysexplorer\.com$/i | ioc := "domain";
    #event_simpleName=NetworkConnectIP4 | in(field="RemoteAddressIP4", values=["113.23.212.15", "212.46.38.73", "146.70.53.182"]) | ioc := "ip";
  }
| table([@timestamp, aid, ComputerName, #event_simpleName, DomainName, RemoteAddressIP4, RemotePort, ioc])


// ---------------------------------------------------------------------
// H3a | App-server / web-server process spawning a shell or interpreter
// ATT&CK (analyst): T1505.003, T1059.004, T1059.001
// Expected noise: MEDIUM-HIGH on some app servers; baseline per host.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| case {
    event_platform=Lin | ParentBaseFileName=/^java$/ | FileName=/^(sh|bash|dash|curl|wget|perl.*|python.*)$/ | hunt := "java_child";
    event_platform=Win | ParentBaseFileName=/^w3wp\.exe$/i | FileName=/^(cmd|powershell|pwsh|certutil|whoami)\.exe$/i | hunt := "iis_child";
  }
| groupBy([aid, ComputerName, ParentBaseFileName, FileName, hunt], function=[count(as=execs), collect([UserName, CommandLine])])


// ---------------------------------------------------------------------
// H3b | sudo vi shell escape (Linux)
// ATT&CK (analyst): T1548.003
// Expected noise: LOW.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Lin
| ParentBaseFileName=/^vim?$/
| GrandParentBaseFileName=/^sudo$/   // [UNVERIFIED] field seen in community primer without platform filter
| FileName=/^(sh|bash|dash)$/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])

// H3c (systemd unit write) is Defender-only in this pack: the Falcon Linux file-write
// event name was not verified in this run. Pivot manually from H3b hits instead.
```

Queries are untested: tune before use.

## Sources

1. Malbear Labs (8 Nov 2026): <https://malbearlabs.com/posts/operation-snowball-inside-an-autonomous-ai-intrusion-campaign>
2. Cyber Security News (9 Nov 2026): <https://cybersecuritynews.com/jailbroken-deepseek-ai-agent-breach/>
