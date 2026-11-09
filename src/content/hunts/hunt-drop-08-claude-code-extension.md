---
title: "Hunt Drop 08 | Trojanised Claude Code extension: hunt the reverse SSH backdoor"
hypothesis: "An editor loader plants an SSH key and a reverse tunnel."
attack: [T1572, T1098.004, T1053.005, T1543.001, T1547.001, T1053.003, T1071.001]
dataSources: ["Endpoint process and file events"]
languages: [KQL, CQL]
drop: 8
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-02
---

Builds on [Intel Drop 24](/intel/intel-drop-24-claude-code-extension-cursor/).

## The hypothesis
If the trojanised Claude Code 2.1.312/2.1.313 build from Cursor's marketplace ran on one of our developer machines, we expect an editor-spawned loader to plant an SSH key, write look-alike persistence, and loop an outbound reverse SSH tunnel back to the workstation's own port 22.

## What to hunt
- ssh/autossh with "-R *:0:localhost:22" and no host-key checking, relaunched about every 60 seconds (T1572)
- A new "svc-telemetry" key in authorized_keys, plus attempts to switch on the local SSH server (T1098.004)
- A "SysMon" scheduled task, a com.apple.sysmond LaunchAgent, a Startup sysmon.cmd or an @reboot cron entry pointing at ~/.config/.smt (T1053.005, T1543.001, T1547.001, T1053.003)
- Editor/Node processes posting host recon to port 8099 (T1071.001)

## Business risk
Developer laptops hold source code, cloud keys and downstream MSP access. An outbound tunnel gets past perimeter controls that only watch inbound traffic.
Risk score (analyst judgement): Likelihood 3 × Impact 4 = 12/25, HIGH

## Tune & triage
Allow-list known admin tunnels by user and destination. Check what a "SysMon" task actually runs, not just its name; real Sysinternals Sysmon exists.
On a hit: isolate the host, remove the key and persistence, and rotate every credential the host could reach.

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #08 | Trojanised Claude Code extension (Cursor marketplace)
// Builds on Intel Drop #24 | Microsoft Defender XDR Advanced Hunting (KQL)
// Telemetry: Defender for Endpoint P2 (Windows + macOS + Linux onboarded)
// STATUS: UNTESTED in a live tenant. Test and tune in a lab/tenant before
//         any production use or promotion to a custom detection rule.
// Default window: 14 days (exposure window was 29 Oct 2026 09:27-20:35 UTC)
// =====================================================================


// ---------------------------------------------------------------------
// H1a | Reverse SSH tunnel from a workstation to the internet
// ATT&CK: T1572 Protocol Tunneling; T1021.004 Remote Services: SSH (analyst)
// Hypothesis: if the trojanised build ran, we expect ssh/autossh with a
//   remote forward to the host's own port 22 ("-R '*:0:localhost:22'")
//   plus non-interactive options (StrictHostKeyChecking=no, BatchMode=yes,
//   ExitOnForwardFailure=yes, autossh -M 0), relaunched about every 60 s.
// Expected noise: LOW-MEDIUM. Admins/devs may use -R legitimately; the
//   "forward to own :22 + no host-key check + batch" combination is rare.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("ssh", "ssh.exe", "autossh")
| where ProcessCommandLine contains_cs "-R"
| where ProcessCommandLine contains "localhost:22" or ProcessCommandLine contains "127.0.0.1:22"
| extend Signals = toint(ProcessCommandLine has "StrictHostKeyChecking=no")
                 + toint(ProcessCommandLine has "UserKnownHostsFile=/dev/null")
                 + toint(ProcessCommandLine has "BatchMode=yes")
                 + toint(ProcessCommandLine has "ExitOnForwardFailure=yes")
                 + toint(ProcessCommandLine has "IdentitiesOnly=yes")
                 + toint(FileName =~ "autossh" or ProcessCommandLine contains_cs "-M 0")
| where Signals >= 2
| summarize Launches = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Parents = make_set(InitiatingProcessFileName, 10),
            SampleCmd = take_any(ProcessCommandLine)
          by DeviceName, AccountName, FileName, Signals
// Many launches at a steady cadence = retry loop (source: ~60 s retry)
| order by Launches desc


// ---------------------------------------------------------------------
// H1b | SSH server enablement + look-alike persistence
// ATT&CK: T1053.005 Scheduled Task; T1053.003 Cron (Microsoft);
//         T1543.001 Launch Agent; T1547.001 Startup Folder;
//         T1036.004 Masquerade Task or Service (analyst mapping)
// Hypothesis: the loader tries to turn on the local SSH service and
//   registers persistence with monitoring-style names ("SysMon",
//   "com.apple.sysmond") that point at ~/.config/.smt or smt.cmd.
// Expected noise: MEDIUM. Real Sysinternals Sysmon tasks and IT scripts
//   that enable OpenSSH exist; check the task ACTION, not just the name.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (ProcessCommandLine has "systemsetup" and ProcessCommandLine has "setremotelogin")
     or (ProcessCommandLine has "Add-WindowsCapability" and ProcessCommandLine has "OpenSSH.Server")
     or (ProcessCommandLine has "systemctl" and ProcessCommandLine has "enable" and ProcessCommandLine has "sshd")
     or (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create" and ProcessCommandLine has "SysMon")
     or (ProcessCommandLine has "com.apple.sysmond")
     or (ProcessCommandLine matches regex @"(?i)\.config[\\/]\.?smt|smt\.cmd|sysmon\.cmd")
| extend Behaviour = case(
      ProcessCommandLine has_any ("setremotelogin", "OpenSSH.Server", "sshd"), "ssh-server-enable",
      ProcessCommandLine has "SysMon", "schtask-SysMon",
      ProcessCommandLine has "com.apple.sysmond", "launchagent-sysmond",
      "smt-script")
| extend EditorChain = InitiatingProcessFileName has_any ("Cursor", "Code", "node")
                    or InitiatingProcessParentFileName has_any ("Cursor", "Code", "node")
| project Timestamp, DeviceName, AccountName, Behaviour, EditorChain, FileName,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by EditorChain desc, Timestamp desc


// ---------------------------------------------------------------------
// H1c | Persistence and key artefacts on disk
// ATT&CK: T1098.004 SSH Authorized Keys (Microsoft); T1543.001; T1547.001
// Hypothesis: we expect ~/.config/.smt|.smtk (or %USERPROFILE%\.config\
//   smt.cmd|smtk), a temp ".stk_<10 hex>" tunnel key, a
//   com.apple.sysmond.plist LaunchAgent or a Startup sysmon.cmd, and an
//   authorized_keys write by an editor / Node process.
// Expected noise: LOW for named artefacts; MEDIUM for authorized_keys
//   writes (configuration-management tools also write them).
// ---------------------------------------------------------------------
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where (FileName in~ (".smt", ".smtk", "smt.cmd", "smtk") and FolderPath has ".config")
     or (FileName =~ "sysmon.cmd" and FolderPath has @"Start Menu\Programs\Startup")
     or (FileName =~ "com.apple.sysmond.plist")
     or (FileName matches regex @"^\.stk_[0-9a-f]{10}$")
     or (FileName in~ ("authorized_keys", "administrators_authorized_keys")
         and InitiatingProcessFileName has_any ("Cursor", "Code", "node", "powershell", "cmd.exe", "bash", "zsh", "sh"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc


// ---------------------------------------------------------------------
// H1d | Scheduled task / LaunchAgent telemetry (pattern from Microsoft blog)
// ATT&CK: T1053.005; T1543.001
// Note: ActionType values "ScheduledTaskCreated" and "PlistPropertyModified"
//   are the ones Microsoft used in its 30 Oct 2026 hunting queries.
// Expected noise: LOW with both "SysMon" and "smt" required.
// ---------------------------------------------------------------------
DeviceEvents
| where Timestamp > ago(14d)
| where (ActionType == "ScheduledTaskCreated" and AdditionalFields has "SysMon" and AdditionalFields has "smt")
     or (ActionType == "PlistPropertyModified" and FolderPath has "com.apple.sysmond.plist")
| project Timestamp, DeviceName, ActionType, FolderPath, AdditionalFields,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc


// ---------------------------------------------------------------------
// H2  | Recon beacon from the extension host (behaviour) + IOC sweep
// ATT&CK: T1195.002 Software Supply Chain; T1082; T1033;
//         T1071.001 Web Protocols (analyst mapping)
// Hypothesis: ~1.5 s after the extension loads, Node inside the editor
//   POSTs host/user/env-var-name recon to :8099/beacon on the C2 and on
//   127.0.0.1, then ssh connects as "tunnel" to the same IP on TCP 22.
// IOCs are from Cursor / Microsoft / StepSecurity (C2 reported offline).
// Expected noise: LOW. Port 8099 from an editor process is unusual.
// ---------------------------------------------------------------------
let c2 = dynamic(["134.209.82.225"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (c2)
     or (RemotePort == 8099 and InitiatingProcessFileName has_any ("Cursor", "Code", "node"))
     or (RemoteUrl has "/beacon" and RemotePort == 8099)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #08 | Trojanised Claude Code extension (Cursor marketplace)
// Builds on Intel Drop #24 | CrowdStrike Falcon CQL (NG-SIEM / Advanced Event Search)
// Telemetry: Falcon Insight XDR sensors on Win/Mac/Lin; NG-SIEM or Event Search
// STATUS: UNTESTED in a live tenant. Test and tune before production use or
//         promotion to a custom IOA / correlation rule.
// TIME: set the time picker to "Last 14 days" (exposure window was
//       29 Oct 2026 09:27-20:35 UTC).
// CQL double-check: cqlsearch.com was blocked by this run's network allowlist;
//   fallback checks recorded in hunt-drop-08 markdown. Lines marked
//   [UNVERIFIED] use names not confirmed against a page opened this run.
// =====================================================================


// ---------------------------------------------------------------------
// H1a | Reverse SSH tunnel to own :22 with non-interactive options
// ATT&CK: T1572; T1021.004 (analyst)
// Expected noise: LOW-MEDIUM
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ImageFileName=/(\\|\/)(ssh|ssh\.exe|autossh)$/i
| CommandLine=/-R\s+'?[^\s']*(localhost|127\.0\.0\.1):22/
| CommandLine=/StrictHostKeyChecking=no|BatchMode=yes|ExitOnForwardFailure=yes|-M\s+0/i
| groupBy([ComputerName, UserName, ImageFileName, CommandLine], function=[count(), collect([ParentBaseFileName])])  // ParentBaseFileName [UNVERIFIED this run]
| sort(_count, limit=200)


// ---------------------------------------------------------------------
// H1b | SSH server enablement + look-alike persistence names
// ATT&CK: T1053.005; T1053.003 (Microsoft); T1543.001; T1547.001;
//         T1036.004 (analyst)
// Expected noise: MEDIUM (real Sysinternals Sysmon tasks, IT OpenSSH scripts)
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/systemsetup.+setremotelogin\s+on|Add-WindowsCapability.+OpenSSH\.Server|systemctl.+enable.+sshd|schtasks.+\/create.+SysMon|com\.apple\.sysmond|\.config[\\\/]\.?smt|smt\.cmd|sysmon\.cmd/i
| case {
    CommandLine=/setremotelogin|OpenSSH\.Server|sshd/i | Behaviour := "ssh-server-enable";
    CommandLine=/SysMon/ | Behaviour := "schtask-SysMon";
    CommandLine=/com\.apple\.sysmond/i | Behaviour := "launchagent-sysmond";
    * | Behaviour := "smt-script";
  }
| table([@timestamp, ComputerName, UserName, Behaviour, ImageFileName, CommandLine, ParentBaseFileName])  // ParentBaseFileName [UNVERIFIED this run]


// ---------------------------------------------------------------------
// H1c | Scheduled task registered with the "SysMon" name (Windows)
// ATT&CK: T1053.005
// [UNVERIFIED] event ScheduledTaskRegistered and field TaskName were not
//   confirmed against a page opened this run; validate in Event Search first.
// ---------------------------------------------------------------------
#event_simpleName=ScheduledTaskRegistered   // [UNVERIFIED]
| TaskName=/SysMon/i                         // [UNVERIFIED]
| table([@timestamp, ComputerName, UserName, TaskName])


// ---------------------------------------------------------------------
// H2  | Beacon / tunnel IOC sweep + unusual port 8099 egress
// ATT&CK: T1195.002; T1071.001; T1572 (analyst for 1195.002/1071.001)
// IOC from Cursor / Microsoft / StepSecurity; C2 reported offline.
// Expected noise: LOW
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4="134.209.82.225" OR RemotePort="8099"
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[count(), collect([aid])])
| sort(_count, limit=200)
```

Queries are untested: tune before use.

## Sources

1. Security notice — malicious version of Anthropic.claude-code (2.1.312 and 2.1.313) identified in the Cursor VS Code Extension Marketplace <https://cursor.com/blog/claude-code-extension-security-notice>
2. Inside a malicious Claude Code-branded extension and its persistent SSH backdoor <https://www.microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/>
3. Trojanized Claude Code Extension Delivered Persistent SSH Backdoor to Developer Machines <https://www.stepsecurity.io/blog/claude-code-extension-trojanized>
