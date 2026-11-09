---
title: "Hunt Drop 05 | Hunting the LiteLLM 1.107.0 startup-hook stealer"
hypothesis: "Python itself runs the stealer on every start."
attack: [T1546.018, T1195.001, T1027.013, T1552.001, T1082, T1016, T1102.001, T1552.005]
dataSources: ["Process events", "File events", "Network events"]
languages: [KQL, CQL]
drop: 5
risk: { likelihood: 2, impact: 5 }
status: published
date: 2026-10-26
---

Builds on [Intel Drop 13](/intel/intel-drop-13-litellm-supply-chain/).

The poisoned LiteLLM release was live for roughly two hours, and its payload never needed anyone to import LiteLLM. Python startup hooks ran it whenever the interpreter started. If AI teams, build agents or gateway containers pulled it, the evidence sits in endpoint telemetry.

## The hypothesis
If the 1.107.0 build reached our estate, Python itself will have written startup-hook files into site-packages and spawned openssl, inline database queries and discovery commands a normal interpreter never needs.

## What to hunt
- cook.pth / sitecustomize.py written into site-packages outside the litellm folder (T1546.018, T1195.001)
- Python → openssl using ".pc_e_" staging directories: loot encrypted before upload (T1027.013)
- Python -c querying LiteLLM's credentials table; Windows discovery bursts (T1552.001, T1082, T1016)
- Python reaching a raw GitHub dead-drop, or instance metadata from a laptop (T1102.001, T1552.005)

## Business risk
A LiteLLM gateway concentrates model-provider keys; the stealer also takes cloud, CI/CD, SSH and AI-tool credentials from the host. For GCC government and critical-infrastructure teams adopting AI, that is a direct path to cloud and pipeline compromise.
Risk score (analyst judgement): Likelihood 2 × Impact 5 = 10/25, HIGH

## Tune & triage
Allow-list .pth files by prevalence; scope exposure first. Treat any hit as live credential theft: isolate, don't run Python on the host, rebuild, rotate secrets from a clean machine.

**Risk: 10/25 HIGH** (likelihood 2 × impact 5, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM-HIGH.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #05 | LiteLLM 1.107.0 startup-hook stealer (PRIVCOLLECT)
// Builds on Intel Drop #13 | Microsoft Defender XDR - Advanced Hunting (KQL)
// Author: Arthur Thomas (draft) | TLP:CLEAR
// STATUS: UNTESTED in a live tenant. Run as hunts first; test and tune
//         before promoting anything to a custom detection rule.
// Window: 14 days by default (covers the 21 Oct 2026 exposure window).
// Tables used (schema checked on Microsoft Learn, 26 Oct 2026):
//   DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
// =====================================================================


// ---------------------------------------------------------------------
// H0 - Exposure scoping: who pulled LiteLLM during / around the window
// ATT&CK: T1195.001 (Compromise Software Dependencies and Dev Tools)
// Hypothesis: Hosts that ran pip/uv/poetry/docker for litellm on 21 Oct
//   (approx. 11:39-14:20 UTC) or pinned 1.107.0 may hold the bad build.
// Expected noise: Low-Medium (AI/dev teams install LiteLLM legitimately;
//   presence = exposure, not compromise).
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "litellm"
| where ProcessCommandLine has_any ("pip", "pip3", "uv", "poetry", "pipx", "docker", "podman")
     or ProcessCommandLine contains "ghcr.io/berriai"
| extend PinnedBad = ProcessCommandLine has "1.107.0"
| extend InWindow = Timestamp between (datetime(2026-10-21 11:00:00) .. datetime(2026-10-21 15:00:00))
| where PinnedBad or InWindow or ProcessCommandLine has_any ("latest", "main-stable", "main-latest")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, PinnedBad, InWindow
| order by Timestamp asc


// ---------------------------------------------------------------------
// H1 - Python startup-hook implant written into a library directory
// ATT&CK: T1546.018 (Python Startup Hooks), T1195.001
// Hypothesis: If the 1.107.0 wheel was installed, cook.pth / cook.py /
//   sitecustomize.py land in site-packages/dist-packages OUTSIDE the
//   litellm folder, written by pip/uv/python.
// Expected noise: Medium - package managers write legitimate .pth files.
//   Allow-list below is a starting point; build your own by prevalence.
// ---------------------------------------------------------------------
let knownPth = dynamic(["distutils-precedence.pth", "easy-install.pth", "_virtualenv.pth", "pywin32.pth"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any ("site-packages", "dist-packages", "purelib")
| where FileName in~ ("cook.pth", "cook.py", "sitecustomize.py")
     or (FileName endswith ".pth"
         and not(FileName in~ (knownPth))
         and not(FileName startswith "__editable__")
         and not(FileName endswith "-nspkg.pth"))
| extend Signal = case(FileName in~ ("cook.pth", "cook.py"), "1-LiteLLM implant file name",
                       FileName =~ "sitecustomize.py", "2-sitecustomize.py written",
                       "3-Uncommon .pth startup hook")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Files = make_set(FileName, 20), Paths = make_set(FolderPath, 20),
            Writers = make_set(InitiatingProcessCommandLine, 10)
            by DeviceName, Signal
| order by Signal asc, FirstSeen desc
// Rarity tip: for Signal 3, keep only .pth names seen on <= 2 devices:
// | join kind=inner (DeviceFileEvents | where Timestamp > ago(30d) and FileName endswith ".pth"
//     | summarize Devices = dcount(DeviceId) by FileName | where Devices <= 2) on FileName


// ---------------------------------------------------------------------
// H2 - Python spawning crypto staging, inline DB theft or discovery
// ATT&CK: T1059.006, T1027.013, T1552.001, T1082, T1016
// Hypothesis: The collector runs inside Python and spawns (a) openssl
//   using ".pc_e_" staging paths (enc -aes-256-cbc / pkeyutl / rsautl),
//   (b) an inline python -c Prisma query of LiteLLM_CredentialsTable /
//   LiteLLM_ProxyModelTable, (c) on Windows a burst of systeminfo,
//   ipconfig, route, arp, netstat.
// Expected noise: Low for (a) and (b); Medium for (c) (dev tooling and
//   IT scripts run network commands from Python - require >= 3 distinct).
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName matches regex @"(?i)^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$"
| extend Cmd = tolower(ProcessCommandLine)
| extend Signal = case(
      FileName in~ ("openssl", "openssl.exe") and Cmd contains ".pc_e_", "OpenSSL .pc_e_ staging (T1027.013)",
      (Cmd contains "litellm_credentialstable" or Cmd contains "litellm_proxymodeltable") and Cmd contains "query_raw", "Inline LiteLLM DB pull (T1552.001)",
      FileName in~ ("systeminfo.exe", "ipconfig.exe", "route.exe", "arp.exe", "netstat.exe"), "Discovery child (T1082/T1016)",
      "")
| where isnotempty(Signal)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            HighSignals = countif(Signal !startswith "Discovery"),
            DiscoveryKinds = dcountif(FileName, Signal startswith "Discovery"),
            Signals = make_set(Signal), Samples = make_set(ProcessCommandLine, 5)
            by DeviceName, InitiatingProcessId, InitiatingProcessCommandLine
| where HighSignals > 0 or DiscoveryKinds >= 3
| order by HighSignals desc, FirstSeen asc


// ---------------------------------------------------------------------
// H3 - Python interpreter egress: dead-drop, exfil host, metadata API
// ATT&CK: T1102.001 (Dead Drop Resolver), T1105, T1552.005
// Hypothesis: An infected interpreter reaches raw.githubusercontent.com
//   (dead-drop pointer), the exfil host, and on workstations the
//   169.254.169.254 instance-metadata address it should never need.
// Expected noise: Medium-High for raw GitHub and metadata on cloud VMs
//   and build agents; treat those as context, pivot from H1/H2 hits.
// ---------------------------------------------------------------------
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName matches regex @"(?i)^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$"
| extend U = tolower(RemoteUrl)
| extend Signal = case(
      U contains "litellm.dev", "1-IOC exfil host",
      U contains "letters9813", "1-IOC dead-drop repo",
      U contains "raw.githubusercontent.com", "2-Python to raw GitHub (dead-drop pattern)",
      RemoteIP == "169.254.169.254", "3-Python to instance metadata",
      "")
| where isnotempty(Signal)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Conns = count(),
            Urls = make_set(RemoteUrl, 10), Cmds = make_set(InitiatingProcessCommandLine, 5)
            by DeviceName, Signal
| order by Signal asc, Conns desc


// ---------------------------------------------------------------------
// IOC SWEEP (published by Microsoft and Socket, Oct 2026)
// Low noise; indicators expire fast - use for retro-scoping only.
// ---------------------------------------------------------------------
let startupHashes = dynamic([
  "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25",
  "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea",
  "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa",
  "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465",
  "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb",
  "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d"]);
let markerFiles = dynamic([".pc_once_72129118c59f5636c0bb", "remote_code_loader.lock"]);
union
  (DeviceFileEvents | where Timestamp > ago(14d)
     | where SHA256 in (startupHashes) or FileName in (markerFiles)
     | project Timestamp, DeviceName, Hit = strcat("File: ", FolderPath), InitiatingProcessCommandLine),
  (DeviceNetworkEvents | where Timestamp > ago(14d)
     | where RemoteUrl contains "litellm.dev" or RemoteUrl contains "letters9813"
     | project Timestamp, DeviceName, Hit = strcat("Net: ", RemoteUrl), InitiatingProcessCommandLine)
| order by Timestamp asc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #05 | LiteLLM 1.107.0 startup-hook stealer (PRIVCOLLECT)
// Builds on Intel Drop #13 | CrowdStrike Falcon - CQL (NG-SIEM / Advanced Event Search)
// Author: Arthur Thomas (draft) | TLP:CLEAR
// STATUS: UNTESTED in a live tenant. Run as hunts first; test and tune
//         before promoting anything to a custom IOA / correlation rule.
// TIME PICKER: set to "Last 14 days" for every query below.
// Field notes (see schema-validation log in the .md):
//   Verified this run: ProcessRollup2, DnsRequest, NetworkConnectIP4, FileName,
//     ImageFileName, CommandLine, DomainName, RemoteAddressIP4, RemotePort,
//     aid, ComputerName, UserName, ContextProcessId, TargetProcessId.
//   NOT verified this run (marked "UNVERIFIED"): ParentBaseFileName,
//     file-write events (*Written) and TargetFileName. Check in your
//     Falcon event data dictionary before use.
// =====================================================================


// ---------------------------------------------------------------------
// H0 - Exposure scoping: LiteLLM installs / pulls (T1195.001)
// Hypothesis: pip/uv/poetry/docker runs for litellm on 21 Oct or pinned
//   to 1.107.0 identify hosts that may hold the bad build.
// Expected noise: Low-Medium (presence = exposure, not compromise).
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/litellm/i
| CommandLine=/(pip3?|uv|poetry|pipx|docker|podman)(\.exe)?\s/i
| CommandLine=/1\.107\.0|latest|main-stable|main-latest|ghcr\.io\/berriai/i
| table([@timestamp, aid, ComputerName, UserName, FileName, CommandLine], limit=1000)


// ---------------------------------------------------------------------
// H1 - Python startup-hook implant in a library directory
// ATT&CK: T1546.018, T1195.001
// Hypothesis: cook.pth / cook.py / sitecustomize.py written into
//   site-packages / dist-packages outside the litellm folder.
// Expected noise: Low for these names; sitecustomize.py has rare
//   legitimate uses (distro / conda builds).
// UNVERIFIED: whether your sensor emits a *Written event for .py/.pth
//   files, and the TargetFileName field. If no results, pivot with
//   Falcon RTR / Falcon Forensics file listing of site-packages instead.
// ---------------------------------------------------------------------
#event_simpleName=/Written$/                                  // UNVERIFIED event coverage
| TargetFileName=/(site|dist)-packages/i                      // UNVERIFIED field
| TargetFileName=/[\\\/](cook\.pth|cook\.py|sitecustomize\.py)$/i
| table([@timestamp, aid, ComputerName, #event_simpleName, TargetFileName, ContextProcessId], limit=1000)


// ---------------------------------------------------------------------
// H2 - Python spawning crypto staging, inline DB theft or discovery
// ATT&CK: T1059.006, T1027.013, T1552.001, T1082, T1016
// Hypothesis: openssl with ".pc_e_" staging, python -c querying
//   LiteLLM_CredentialsTable / LiteLLM_ProxyModelTable with query_raw,
//   or a Windows discovery burst, all with a Python parent.
// Expected noise: Low for openssl/DB; Medium for discovery (need >= 3).
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$/i   // UNVERIFIED field
| case {
    FileName=/^openssl(\.exe)?$/i CommandLine=/\.pc_e_/ | Signal := "OpenSSL .pc_e_ staging";
    CommandLine=/LiteLLM_(Credentials|ProxyModel)Table/i CommandLine=/query_raw/ | Signal := "Inline LiteLLM DB pull";
    FileName=/^(systeminfo|ipconfig|route|arp|netstat)\.exe$/i | Signal := "Discovery child";
    * | Signal := "none" }
| Signal!="none"
| groupBy([aid, ComputerName, Signal], function=[count(as=Hits), count(field=FileName, distinct=true, as=Kinds), collect([CommandLine])])
| case { Signal!="Discovery child" | Keep := "y";            // keep all high-signal rows
         test(Kinds >= 3) | Keep := "y" }                    // discovery only if >= 3 distinct tools
| sort(Hits, order=desc, limit=500)


// ---------------------------------------------------------------------
// H3a - Python DNS: dead-drop pointer and exfil host (T1102.001, T1105)
// Expected noise: Medium for raw GitHub (pip/tools); Low for IOC host.
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest
| DomainName=/(^|\.)litellm\.dev$|^raw\.githubusercontent\.com$/i
| join(query={#event_simpleName=ProcessRollup2 | FileName=/^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$/i},
       field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine], mode=inner)
| groupBy([aid, ComputerName, DomainName], function=[count(as=Lookups), collect([CommandLine])])


// ---------------------------------------------------------------------
// H3b - Python to instance metadata from non-cloud hosts (T1552.005)
// Expected noise: High on cloud VMs / build agents - exclude by host group.
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4="169.254.169.254"
| join(query={#event_simpleName=ProcessRollup2 | FileName=/^(python|pythonw|platform-python|python3(\.\d+)?)(\.exe)?$/i},
       field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine], mode=inner)
| groupBy([aid, ComputerName, RemotePort], function=[count(as=Conns), collect([CommandLine])])


// ---------------------------------------------------------------------
// IOC SWEEP (Microsoft / Socket, Oct 2026) - retro-scoping only
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest
| in(field="DomainName", ignoreCase=true, values=["litellm.dev", "www.litellm.dev"])
| table([@timestamp, aid, ComputerName, DomainName, ContextProcessId], limit=1000)
```

Queries are untested: tune before use.

## Sources

1. Microsoft Threat Intelligence (23 Oct 2026): <https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/>
2. Socket (21 Oct 2026): <https://socket.dev/blog/litellm-compromise>
3. LiteLLM (BerriAI) (23 Oct 2026): <https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain>
