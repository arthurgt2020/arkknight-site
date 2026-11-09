---
title: "Hunt Drop 10 | Edge-to-Domain: Hunting the k0t Post-VPN Playbook"
hypothesis: A VPN edge foothold has been turned into domain access.
attack: [T1569.002, T1053.005, T1059.001, T1219, T1567.002]
dataSources: [EDR process events, Network events, DNS events]
languages: [KQL, CQL]
drop: 10
risk: { likelihood: 4, impact: 4 }
status: draft
date: 2026-11-06
---

Builds on [Intel Drop 30](/intel/intel-drop-30-k0t-access-broker/).

Group-IB tracked a suspected access broker turning FortiWeb, FortiGate and GlobalProtect footholds into domain-wide access. Patching the edge won't tell you who already walked through. Endpoint telemetry can.

## The hypothesis

If k0t-style operators reached us through a VPN edge, we expect Impacket or NetExec-style remote execution, PowerShell pulling a fake installer, and unapproved remote monitoring and management (RMM) tools plus Rclone moving data to cloud storage.

## What to hunt

- `cmd.exe /Q /c` from `services.exe`, or `cmd.exe /C` from the Task Scheduler, redirecting output to `C$` or `Windows\Temp` (T1569.002, T1053.005)
- PowerShell launching `curl` to fetch an `.exe`, then egress to the default AdaptixC2 port 4321 (T1059.001, T1219)
- New MeshAgent, AnyDesk, Atera, Teramind or ngrok binaries (T1219)
- Rclone, or DNS lookups for Wasabi and MEGA storage (T1567.002)

## Business risk

Broker access gets resold. For GCC government and critical infrastructure, one weak edge device can become domain admin, data theft and a possible ransomware handoff.

**Risk: 16/25 CRITICAL** (likelihood 4 x impact 4, analyst judgement). Intel confidence: moderate. Detection fidelity: medium.

## Tune and triage

Allow-list sanctioned RMM by signer and path, and scope first to hosts reached from VPN address pools. On a hit: isolate the host, pull the VPN logs for that window, and rotate service and LDAP bind credentials.

## Microsoft Defender (KQL)

```kusto
// k0t post-VPN hunt: NetExec/Impacket exec + RMM/Rclone. Untested: tune before use.
DeviceProcessEvents
| where Timestamp > ago(14d)
| extend Hit = case(
  FileName =~ "cmd.exe" and InitiatingProcessFileName =~ "services.exe"
   and ProcessCommandLine contains "/Q"
   and (ProcessCommandLine contains @"\\127.0.0.1\" or ProcessCommandLine contains "__output"), "smbexec",
  FileName =~ "cmd.exe" and InitiatingProcessCommandLine contains "-k netsvcs"
   and ProcessCommandLine contains @"Windows\Temp\" and ProcessCommandLine contains "&1", "atexec",
  InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe") and FileName =~ "curl.exe"
   and ProcessCommandLine matches regex @"(?i)https?://\S+\.exe", "ps-curl-exe",
  FileName has_any ("meshagent","anydesk","atera","teramind","ngrok"), "rmm",
  FileName =~ "rclone.exe" or ProcessCommandLine has_any ("wasabisys.com","userstorage.mega.co.nz"), "rclone",
  "")
| where Hit != ""
| summarize First=min(Timestamp), Last=max(Timestamp), N=count(), Cmd=take_any(ProcessCommandLine)
  by DeviceName, AccountName, Hit, FileName
| order by Last desc
```

## CrowdStrike Falcon (CQL)

```
// k0t post-VPN hunt. Time picker: last 14 days. Untested: tune before use.
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
  FileName=/^cmd\.exe$/i ParentBaseFileName=/^services\.exe$/i CommandLine=/\/Q\s+\/c/i CommandLine=/(\\\\127\.0\.0\.1\\|__output)/i | Hit:="smbexec";
  FileName=/^cmd\.exe$/i ParentBaseFileName=/^svchost\.exe$/i CommandLine=/Windows\\Temp\\/i CommandLine=/&1/ | Hit:="atexec";
  ParentBaseFileName=/^(powershell|pwsh)\.exe$/i FileName=/^curl\.exe$/i CommandLine=/https?:\/\/\S+\.exe/i | Hit:="ps-curl-exe";
  FileName=/(meshagent|anydesk|atera|teramind|ngrok)/i | Hit:="rmm";
  FileName=/rclone/i | Hit:="rclone";
  CommandLine=/(wasabisys\.com|userstorage\.mega\.co\.nz)/i | Hit:="rclone";
  * | Hit:="";
}
| Hit!=""
| groupBy([ComputerName, UserName, Hit, FileName], function=[count(), collect([CommandLine])], limit=max)
```

## Sources

1. Group-IB (21 Oct 2026): <https://www.group-ib.com/blog/stray-cat-network-edge/>
2. The Hacker News (23 Oct 2026): <https://thehackernews.com/2026/10/hackers-breach-enterprise-firewalls-and.html>
3. SigmaHQ via Detection.FYI: <https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement/>
4. Cyber Triage (20 Sep 2024): <https://www.cybertriage.com/blog/dfir-breakdown-impacket-remote-execution-activity-smbexec/>
5. NCC Group (27 May 2021): <https://www.nccgroup.com/research/detecting-rclone-an-effective-tool-for-exfiltration/>
