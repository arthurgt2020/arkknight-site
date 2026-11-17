---
title: "Hunt Drop 13 | Qlik Sense to Reverse Shell: Hunting the Scheduler Chain"
hypothesis: Qlik Sense scheduler.exe ran a PowerShell reverse shell, then OpenSSH was installed for persistence.
attack: [T1190, T1059.001, T1053.005, T1543.003, T1562.004, T1098.004, T1571, T1105]
dataSources: [EDR process events, Scheduled task events, File events, Network events]
languages: [KQL, CQL]
drop: 13
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-13
---

Builds on Intel Drop 37.

Analytics servers sit next to finance, ERP and backup data, yet rarely get hunted. This campaign targeted several European Qlik Sense estates in just over three minutes, with ActiveMQ and Veeam exploits staged on its server for the next step.

## The hypothesis

If this reached our Qlik Sense servers, `scheduler.exe` launched PowerShell with a one-line reverse shell, then installed OpenSSH with a "WinUpdCheck" task for persistence.

## What to hunt

- `scheduler.exe` spawning `powershell.exe` or `cmd.exe` (T1190, T1059.001)
- Task "WinUpdCheck" running `C:\ProgramData\ssh\winc.ps1` every five minutes (T1053.005)
- `sshd` set to automatic, a new inbound TCP 22 rule, `authorized_keys` changes (T1543.003, T1562.004, T1098.004)
- Egress to TCP 4455, 4456 or 8012 (T1571, T1105)

## Business risk

A foothold here is a short hop to Veeam, which is exactly what ransomware crews want to break before encrypting. The entry flaw is still unconfirmed, so patch level alone is not reassurance.

**Risk score:** likelihood 3 × impact 4 = **12/25, HIGH** (analyst judgement).

## Tune and triage

Baseline approved PowerShell in Qlik tasks by command line and service account. On a hit, isolate the host, check `ProgramData\ssh` and task history, and confirm your backup console is clean.

## Confidence

| Assessment | Confidence |
|---|---|
| Intel confidence | MODERATE |
| Detection fidelity | MEDIUM |

## Microsoft Defender (KQL)

```kql
// =====================================================================
// Hunt Drop #13 | Qlik Sense scheduler.exe -> reverse shell -> OpenSSH persistence
// Builds on Intel Drop #37 (Cynet "ZeroQlik Returns" campaign, as reported 11 Nov 2026)
// Platform: Microsoft Defender XDR Advanced Hunting (requires Defender for Endpoint P2)
// UNTESTED in a live tenant. Table/column names follow the Microsoft Learn advanced
// hunting schema; the schema pages could not be fetched in this run (sandbox allowlist),
// so test every query and tune before use. Default window: 14 days.
// =====================================================================


// ---------------------------------------------------------------------
// H1 | Qlik Sense scheduler.exe spawning a shell or LOLBin
// ATT&CK: T1190 (source), T1059.001 (source: PowerShell one-line reverse shell)
// Hypothesis: if this campaign reached our Qlik Sense servers, scheduler.exe will have
//   launched powershell.exe (or cmd.exe) with a one-line TCP reverse shell or a
//   download/persistence script.
// Expected noise: LOW-MEDIUM. Some Qlik admins run PowerShell/CLI from Qlik tasks;
//   baseline by command line and service account before acting.
// Note: the "qlik" folder filter is an analyst assumption (default install path);
//   remove it if Qlik Sense is installed to a custom path.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "scheduler.exe"
| where InitiatingProcessFolderPath has "qlik"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe",
                      "certutil.exe", "curl.exe", "bitsadmin.exe", "mshta.exe")
// Analyst-selected strings: TCPClient/GetStream are typical of public one-line
// PowerShell reverse shells; winc.ps1 / install-sshd / OpenSSH are from the source.
| extend Suspicious = ProcessCommandLine has_any ("TCPClient", "GetStream", "-enc",
                      "EncodedCommand", "DownloadString", "Invoke-WebRequest", "IEX",
                      "winc.ps1", "install-sshd", "OpenSSH", ":4455", ":4456", ":8012")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine, Suspicious
| order by Timestamp desc


// ---------------------------------------------------------------------
// H2 | OpenSSH-based persistence on Windows servers
// ATT&CK: T1053.005 (scheduled task "WinUpdCheck", source), T1098.004 (SSH authorized
//   keys, Helix summary), T1543.003 and T1562.004 (sshd set to auto start and inbound
//   TCP 22 firewall rule: analyst mapping), T1021.004 (SSH remote access: analyst mapping)
// Hypothesis: the follow-on PowerShell installs OpenSSH, creates task "WinUpdCheck" that
//   runs C:\ProgramData\ssh\winc.ps1 every five minutes, sets sshd to automatic start
//   and opens inbound TCP 22.
// Expected noise: MEDIUM. Legitimate OpenSSH Server rollouts will match the sshd and
//   firewall branches; WinUpdCheck / winc.ps1 hits should be treated as high priority.
// ---------------------------------------------------------------------
let lookback = 14d;
union
(DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where ProcessCommandLine has_any ("WinUpdCheck", "winc.ps1", "install-sshd.ps1",
                                        "OpenSSH-Win64.zip", "administrators_authorized_keys")
        or (ProcessCommandLine has "sshd" and ProcessCommandLine has_any ("Automatic", "start= auto", "start=auto"))
        or (ProcessCommandLine has_any ("New-NetFirewallRule", "netsh")
            and ProcessCommandLine has_any ("Inbound", "dir=in")
            and ProcessCommandLine has "22")
    | project Timestamp, DeviceName, Source = "Process", Detail = ProcessCommandLine,
              Actor = InitiatingProcessFileName),
(DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "ScheduledTaskCreated"
    | where AdditionalFields has_any ("WinUpdCheck", "winc.ps1", @"ProgramData\ssh")
    | project Timestamp, DeviceName, Source = "ScheduledTask", Detail = tostring(AdditionalFields),
              Actor = InitiatingProcessFileName),
(DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where ActionType in ("FileCreated", "FileModified")
    | where FolderPath has @"\ProgramData\ssh\"
    | where FileName endswith ".ps1" or FileName =~ "administrators_authorized_keys"
    | project Timestamp, DeviceName, Source = "File", Detail = FolderPath,
              Actor = InitiatingProcessFileName)
| order by Timestamp desc


// ---------------------------------------------------------------------
// H3 | Egress to the reported staging/C2 ports + IOC sweep
// ATT&CK: T1571 (non-standard port: analyst mapping), T1105 (tool transfer from the
//   :8012 open directory: analyst mapping), T1071.001 (analyst mapping)
// Hypothesis: a compromised server connects out to TCP 4455/4456 (reverse shells) or
//   8012 (staging server hosting OpenSSH-Win64.zip, Go backdoor, ActiveMQ/Veeam tools).
// IOC from public reporting: 45.115.26.23 (defanged in notes: 45.115.26[.]23).
// Expected noise: LOW for the IP; MEDIUM for the ports alone (8012 is used by some apps).
// ---------------------------------------------------------------------
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt", "ConnectionFailed")
| where RemoteIPType == "Public"
| where RemoteIP == "45.115.26.23" or RemotePort in (4455, 4456, 8012)
| summarize Connections = count(), Ports = make_set(RemotePort),
            Processes = make_set(InitiatingProcessFileName),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, RemoteIP
| extend IOCMatch = iff(RemoteIP == "45.115.26.23", 1, 0)
| order by IOCMatch desc, Connections desc


// ---------------------------------------------------------------------
// H3b (optional) | New inbound SSH accepted on Windows servers
// ATT&CK: T1021.004 (analyst mapping)
// Expected noise: depends on whether OpenSSH Server is approved in your estate.
// ---------------------------------------------------------------------
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort == 22 and InitiatingProcessFileName =~ "sshd.exe"
| summarize Sessions = count(), Sources = make_set(RemoteIP, 50),
            FirstSeen = min(Timestamp) by DeviceName
| order by FirstSeen desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// Hunt Drop #13 | Qlik Sense scheduler.exe -> reverse shell -> OpenSSH persistence
// Builds on Intel Drop #37 (Cynet "ZeroQlik Returns" campaign, as reported 11 Nov 2026)
// Platform: CrowdStrike Falcon Next-Gen SIEM / Advanced Event Search (Falcon Insight data)
// Set the time picker to Last 14 days for every query.
// UNTESTED in a live tenant. CQL double-check could NOT be completed this run:
// cqlsearch.com, github.com (CrowdStrike/logscale-community-content) and library.humio.com
// were all blocked by the sandbox allowlist. Lines marked [UNVERIFIED] use fields whose
// names were not confirmed against a fetched document in this run. Test and tune before use.
// =====================================================================


// ---------------------------------------------------------------------
// H1 | Qlik Sense scheduler.exe spawning a shell or LOLBin
// ATT&CK: T1190, T1059.001 (source)
// Hypothesis: scheduler.exe launched PowerShell/cmd with a one-line TCP reverse shell or
//   a download/persistence script.
// Expected noise: LOW-MEDIUM (Qlik admins may run PowerShell from tasks; baseline first).
// Note: ParentBaseFileName holds no path, so other products' scheduler.exe can match;
//   scope by host group or ComputerName for your Qlik servers.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^scheduler\.exe$/i
| FileName=/^(powershell|pwsh|cmd|rundll32|certutil|curl|bitsadmin|mshta)\.exe$/i
| case {
    CommandLine=/(TCPClient|GetStream|-enc|EncodedCommand|DownloadString|Invoke-WebRequest|IEX|winc\.ps1|install-sshd|OpenSSH|:4455|:4456|:8012)/i | Suspicious := "yes" ;
    * | Suspicious := "no" ;
  }
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, Suspicious])


// ---------------------------------------------------------------------
// H2 | OpenSSH-based persistence on Windows servers (process command lines)
// ATT&CK: T1053.005 (source), T1098.004 (Helix summary), T1543.003, T1562.004, T1021.004 (analyst)
// Expected noise: MEDIUM (legit OpenSSH rollouts); WinUpdCheck / winc.ps1 = high priority.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(WinUpdCheck|winc\.ps1|install-sshd\.ps1|OpenSSH-Win64\.zip|administrators_authorized_keys)/i
    or (CommandLine=/sshd/i and CommandLine=/(StartupType\s+Automatic|start=\s*auto)/i)
    or (CommandLine=/(New-NetFirewallRule|netsh)/i and CommandLine=/(Inbound|dir=in)/i and CommandLine=/\b22\b/)
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])


// H2b | Scheduled task named WinUpdCheck or running winc.ps1
// [UNVERIFIED] event ScheduledTaskRegistered and fields TaskName / TaskExecCommand
#event_simpleName=ScheduledTaskRegistered event_platform=Win
| TaskName=/WinUpdCheck/i or TaskExecCommand=/winc\.ps1/i
| table([@timestamp, aid, ComputerName, TaskName, TaskExecCommand])


// ---------------------------------------------------------------------
// H3 | Egress to reported reverse-shell/staging ports + IOC sweep
// ATT&CK: T1571, T1105, T1071.001 (analyst mapping)
// IOC from public reporting: 45.115.26.23 (defanged in notes: 45.115.26[.]23)
// Expected noise: LOW for the IP; MEDIUM for the ports alone.
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4 event_platform=Win
| RemoteAddressIP4="45.115.26.23" or RemotePort=/^(4455|4456|8012)$/
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"], negate=true)
// [UNVERIFIED] ContextBaseFileName may be absent in some tenants; fall back to ContextProcessId + ProcessRollup2 join
| groupBy([aid, ComputerName, RemoteAddressIP4], function=[count(as=Connections), collect([RemotePort, ContextBaseFileName])])
| sort(Connections, order=desc)
```

Queries are untested: tune before use.

## Sources

1. The Hacker News: Hackers Target Qlik Sense Servers With Reverse Shells, Stage ActiveMQ and Veeam Exploits (11 Nov 2026) <https://thehackernews.com/2026/11/hackers-target-qlik-sense-servers-with.html>
2. The IT Nerd: Cynet Uncovers Qlik Sense Attack Campaign Targeting Multiple Companies Within Minutes (11 Nov 2026) <https://itnerd.blog/2026/11/11/cynet-uncovers-qlik-sense-attack-campaign-targeting-multiple-companies-within-minutes/>
3. Helix Threat Watch: Qlik Sense: PowerShell reverse shells via scheduler.exe, staged ActiveMQ and Veeam tools (11 Nov 2026) <https://helix.ml/threat-watch/i/cactus-linked-qlik-sense-intrusions-qlik-sense-reverse-shell-attacks-staging-activemq-and-veeam-exploits-cve-2023-41265>
