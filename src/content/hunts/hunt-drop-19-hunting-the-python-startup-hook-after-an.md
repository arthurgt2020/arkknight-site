---
title: "Hunt Drop 19 | Hunting the Python startup hook after an AI-agent zero-day"
hypothesis: "A MONAI Label upload path traversal drops a sitecustomize.py startup hook, then a Python process becomes a root reverse shell."
attack: [T1546.018, T1059.004, T1071, T1190]
dataSources: ["File events", "Process events", "Network events"]
languages: [KQL, CQL]
drop: 19
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-23
---

Builds on [Intel Drop 49](/intel/intel-drop-49-cairn-ai-agents-zero-day/).

## The hypothesis
If Cairn-style AI agents reached one of our MONAI Label servers, we expect an upload path traversal to drop a sitecustomize.py startup hook, then a Python process that turns into a root reverse shell.

## What to hunt
- New sitecustomize.py, usercustomize.py or .pth files in Python package paths, written by something other than a package manager (T1546.018, analyst mapping)
- Python parents spawning interactive shells or reverse-shell idioms (T1059.004, analyst mapping)
- Python egress to rare public IPs on unusual ports, plus a sweep of the two published source IPs (T1071 analyst mapping, T1190 per source)

## Business risk
Research and imaging servers often run authentication-off by default and may run as root. Per secondary reporting the fix is not yet in a tagged release. One compromised box can become a pivot into the wider network. Worth checking in GCC university, hospital and research AI labs.
Risk score: Likelihood 3 × Impact 4 = 12/25, HIGH (analyst judgement, consistent with Intel Drop 🧠 49)

## Tune & triage
Allow-list pip, conda and OS installers. On a hit: isolate the host, preserve the file and web logs, look for PUT requests to /datastore/ with ../ in them, and rebuild rather than clean.

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: MODERATE. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// ===== Hunt Drop #19 | MONAI Label / Cairn AI-agent zero-day (builds on Intel Drop #49) =====
// UNTESTED in a live tenant. Test and tune before any use. Window: last 14 days.
// Telemetry: Defender for Endpoint (Linux sensor for Linux research/GPU hosts).
// Schema checked against Microsoft Learn: DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents.

// ---- H1 Q1: Python startup hook written to a package path -----------------------------
// Hunt: MONAI Label startup hook | Hunt Drop #19 | ATT&CK: T1546.018 (analyst mapping), T1190 (source-aligned)
// Hypothesis: path traversal on /datastore/image|label writes sitecustomize.py (per CSA note relaying Amazon).
// Expected noise: pip/conda/OS package installs, legitimate site customisation, venv builds.
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sitecustomize.py", "usercustomize.py") or FileName endswith ".pth"
| where FolderPath has_any ("site-packages", "dist-packages")
| where InitiatingProcessFileName !in~ ("pip", "pip3", "dpkg", "apt", "apt-get", "rpm", "yum", "dnf", "conda", "mamba")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

// ---- H1 Q2: any MONAI Label host (exposure scoping) -----------------------------------
// Hunt: MONAI Label server inventory | Hunt Drop #19 | ATT&CK: T1190 | scoping, not malicious by itself
// Hypothesis: you cannot assess exposure until you know which hosts run monailabel.
// Expected noise: none (inventory). Check auth setting (MONAI_LABEL_AUTH_ENABLE) and reachability separately.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "monailabel" or InitiatingProcessCommandLine has "monailabel"
| summarize Starts = count(), LastSeen = max(Timestamp), Users = make_set(AccountName, 5)
          by DeviceName
| order by LastSeen desc

// ---- H2 Q3: Python spawning a shell with reverse-shell idioms --------------------------
// Hunt: python-to-shell | Hunt Drop #19 | ATT&CK: T1059.004 (analyst mapping)
// Hypothesis: a training API call spawns a new Python process that becomes a (root) reverse shell.
// Expected noise: admin scripts using subprocess with shells, Jupyter terminals, conda activate scripts.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName startswith "python"
| where FileName in~ ("sh", "bash", "dash", "zsh")
| where ProcessCommandLine has_any (" -i", "/dev/tcp", "socat", "ncat", "pty.spawn")
| extend RunAsRoot = (AccountName == "root")
| project Timestamp, DeviceName, AccountName, RunAsRoot, FileName, ProcessCommandLine,
          InitiatingProcessCommandLine
| order by RunAsRoot desc, Timestamp desc

// ---- H2 Q4: Python egress to public IPs on unusual ports -------------------------------
// Hunt: rare python egress | Hunt Drop #19 | ATT&CK: T1071 (analyst mapping)
// Hypothesis: a reverse shell or proxy tunnel shows as python connecting out to a rare public IP.
// Expected noise: package downloads, ML dataset pulls, cloud SDK traffic on custom ports. Tune with allow-lists.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName startswith "python"
| where ipv4_is_private(RemoteIP) == false
| where RemotePort !in (80, 443, 53)
| summarize Conns = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort
| where Conns >= 3
| order by Conns desc

// ---- IOC sweep: source IPs published for 8-10 Sep 2026 (CSA note relaying Amazon) -----------
// Hunt: Cairn source-IP sweep | Hunt Drop #19 | ATT&CK: T1190
// Expected noise: low; indicators are 2+ months old and may have rotated.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in ("142.4.98.145", "142.4.107.34")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName,
          InitiatingProcessCommandLine
// Note: 14d will not reach September; extend the window to your retention limit for the IOC sweep.
```

## CrowdStrike Falcon (CQL)

```
// ===== Hunt Drop #19 | MONAI Label / Cairn AI-agent zero-day (builds on Intel Drop #49) =====
// UNTESTED in a live tenant. Test and tune before any use.
// Time picker: set Falcon search to the last 14 days (7-14d default). Telemetry: Falcon Insight / NG-SIEM, Linux sensor.
// Linux file-write telemetry is not assumed here; the startup-hook file hunt is covered in Defender KQL.
// Unverified: UserName / ComputerName on Linux events (not confirmed in fetched docs) -> not used; resolve aid to hostname manually.
// Unverified: NetworkConnectIP4 exact name confirmed only via the NetworkConnect* wildcard in community content.

// ---- H2 C1: Python parent spawning a shell with reverse-shell idioms ---------------------
// Hunt: python-to-shell | Hunt Drop #19 | ATT&CK: T1059.004 (analyst mapping)
// Hypothesis: training API call spawns a Python process that becomes a reverse shell.
// Expected noise: admin scripts using subprocess shells, Jupyter terminals.
#event_simpleName=ProcessRollup2 event_platform=Lin
| ParentBaseFileName=/^python[0-9.]*$/i
| FileName=/^(sh|bash|dash|zsh)$/i
| CommandLine=/(\s-i(\s|$)|\/dev\/tcp|ncat|socat|pty\.spawn)/i
| table([@timestamp, aid, ParentBaseFileName, FileName, CommandLine], limit=1000)

// ---- H2 C2: Python one-liner reverse-shell idioms in the command line ----------------------
// Hunt: python reverse-shell one-liners | Hunt Drop #19 | ATT&CK: T1059.006 (analyst mapping)
// Hypothesis: agent-delivered payloads often use socket + dup2/pty. Idioms are analyst heuristics, not from the source.
// Expected noise: dev/test scripts, remote-debugging helpers.
#event_simpleName=ProcessRollup2 event_platform=Lin
| FileName=/^python[0-9.]*$/i
| CommandLine=/(socket.*connect|pty\.spawn|os\.dup2)/i
| table([@timestamp, aid, ParentBaseFileName, FileName, CommandLine], limit=1000)

// ---- C3: rare Python parents of shells, aggregated (stack count) -------------------------
// Hunt: python shell-spawn frequency | Hunt Drop #19 | ATT&CK: T1059.004 (analyst mapping)
// Expected noise: high on dev hosts; use to find rare hosts (low count) rather than alerting.
#event_simpleName=ProcessRollup2 event_platform=Lin
| ParentBaseFileName=/^python[0-9.]*$/i
| FileName=/^(sh|bash|dash|zsh)$/i
| groupBy([aid], function=[count(as=shell_spawns), collect([CommandLine])], limit=max)
| sort(shell_spawns, order=asc, limit=200)

// ---- IOC sweep: source IPs published for 8-10 Sep 2026 (CSA note relaying Amazon) -----------
// Hunt: Cairn source-IP sweep | Hunt Drop #19 | ATT&CK: T1190
// Expected noise: low; indicators are 2+ months old. Extend the time picker to your retention limit.
#event_simpleName=NetworkConnectIP4
| in(field="RemoteAddressIP4", values=["142.4.98.145", "142.4.107.34"])
| groupBy([aid], function=[count(as=conns), collect([RemoteAddressIP4, RemotePort])], limit=max)
```

Queries are untested: tune before use.

## Sources

1. SecurityWeek (21 Nov 2026): <https://www.securityweek.com/amazon-china-linked-hackers-ai-agents-exploited-medical-software-zero-day/>
2. Cloud Security Alliance AI Safety Initiative (21 Nov 2026): <https://labs.cloudsecurityalliance.org/research/csa-research-note-monai-label-agent-discovered-zero-day-2026/>
