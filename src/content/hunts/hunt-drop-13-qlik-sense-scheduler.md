---
title: "Hunt Drop 13 | Qlik Sense to Reverse Shell: Hunting the Scheduler Chain"
hypothesis: Qlik Sense scheduler.exe ran a PowerShell reverse shell, then OpenSSH was installed for persistence.
attack: [T1190, T1059.001, T1053.005, T1543.003, T1562.004, T1098.004, T1571, T1105]
dataSources: [EDR process events, Scheduled task events, File events, Network events]
languages: [KQL]
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

Simplified query from the Hunt Drop graphic. Untested: tune before use. The full KQL and Falcon CQL queries are in the LinkedIn post comments.

```kql
// scheduler.exe → PowerShell / cmd (T1190, T1059.001)
DeviceProcessEvents
| where InitiatingProcessFileName =~ "scheduler.exe"
| where FileName in~ ("powershell.exe", "cmd.exe")
| project DeviceName, ProcessCommandLine
```
