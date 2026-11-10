---
title: "Hunt Drop 01 | ROMULUS ClickFix: hunt the paste-to-loader chain"
hypothesis: "Run-box PowerShell leads to a silent MSI or passworded 7-Zip, then a loader on the host."
attack: [T1204.004, T1059.001, T1218.007, T1574.002, T1027.013, T1027.001]
dataSources: ["Process events", "Image-load events", "File events", "Registry events"]
languages: [KQL, CQL]
drop: 1
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-10-21
---

Hunt Drop turns Intel Drop into hunts you can run today.

ROMULUS needs no exploit, just a user who pastes one line into the Run box. Its infrastructure rotates, so hunt the behaviour, not the IOCs.

## The hypothesis
If a ROMULUS lure landed, expect PowerShell pulling a script (often from a decimal IP), then a silent MSI or passworded 7-Zip extraction dropping a loader.

## What to hunt
- PowerShell started by explorer.exe with a download cradle, hidden/bypass flags or a decimal-IP host (T1204.004, T1059.001)
- msiexec /qn on an MSI in %TEMP%, launched by PowerShell or with a GUID-prefixed name (T1218.007)
- A signed binary started by msiexec from %LOCALAPPDATA%\Programs\ side-loading a patched DLL (T1574.002)
- PowerShell → 7-Zip with -p<password> -y, then an ~880 MB padded EXE (T1027.013, T1027.001)

## Business risk
One paste can give an attacker browser credentials and a foothold in GCC government and critical-infrastructure estates.
Risk score (analyst judgement): Likelihood 3 × Impact 4 = 12/25, HIGH

## Tune & triage
Allow-list admin and deployment tooling by parent and signer. Multi-signal hosts first.
On a match: isolate, pull script-block logs, check Run keys and scheduled tasks, reset browser-saved credentials.

## Proactive next step
Once tuned and quiet in your estate, promote the multi-signal hunts to custom detection rules so the next attempt raises an alert.

Defender KQL and Falcon CQL hunts are in the comments (each H1 spans Part 1 + Part 2).

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #01 | ROMULUS ClickFix delivery platform -> MSI sideload / LegionLoader
// Builds on Intel Drop #03/#04 (posted 20 Oct 2026)
// Platform : Microsoft Defender XDR - Advanced Hunting (KQL)
// Telemetry: Defender for Endpoint P2 (DeviceProcessEvents, DeviceFileEvents,
//            DeviceImageLoadEvents, DeviceRegistryEvents, DeviceNetworkEvents)
// STATUS   : Reviewed v2 (21 Oct 2026). Not yet run in a live tenant - test
//            and tune allow-lists before running across your estates. Hunt queries only.
// USAGE    : Independent queries separated by banner comments. Run ONE block
//            at a time in Advanced Hunting.
// NOTE     : Flag regexes accept "-", "/" and the en/em/horizontal-bar dashes
//            that PowerShell also accepts (Sigma "windash" equivalent).
// Author   : Arthur T. (draft) | TLP:CLEAR
// =====================================================================


// ---------------------------------------------------------------------
// H1 | ClickFix PowerShell stager -> silent MSI -> signed-binary side-load host
// ATT&CK  : T1204.004, T1059.001, T1105, T1218.007, T1574.002
// Hypothesis: If ROMULUS (Route A) reached our users, we expect powershell.exe
//   (often launched by explorer.exe from the Win+R box) with hidden/bypass
//   flags and a download - Huntress saw "irm <decimal-IP>/<n>" - then
//   msiexec /i %TEMP%\<32-hex>_<name>.msi /qn /norestart launched by
//   PowerShell, then a signed host (DeElevate64.exe / COTFileReadApp.exe)
//   started by msiexec from %LOCALAPPDATA%\Programs\.
// Expected noise: Medium for PS-only hits; Low when Types >= 2.
// Mirrors the Falcon CQL H1 branch-for-branch (case() = first match wins).
// ---------------------------------------------------------------------
let Cradle = @"(?i)(https?://|irm\s|iwr\s|iex|invoke-(restmethod|webrequest|expression)|net\.webclient|download(string|file|data))";
let PS = dynamic(["powershell.exe","pwsh.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("powershell.exe","pwsh.exe","msiexec.exe") or FolderPath contains @"\AppData\Local\Programs\"
| extend S = case(
 FileName in~ (PS) and ProcessCommandLine matches regex @"(?i)(irm|iwr|curl|https?://)\s*\d{8,10}(/|:|\s|$)", "1 PS decimal-IP",
 FileName in~ (PS) and InitiatingProcessFileName =~ "explorer.exe" and ProcessCommandLine matches regex Cradle, "1 PS cradle, explorer parent",
 FileName in~ (PS) and ProcessCommandLine matches regex @"(?i)[-/–—―](w[a-z]*\s+h|e[a-z]*\s+bypass|e[a-z]*\s+[a-z0-9+/=]{40,})" and ProcessCommandLine matches regex Cradle, "1 PS hidden/bypass+download",
 FileName =~ "msiexec.exe" and ProcessCommandLine matches regex @"(?i)[-/–—―](qn|quiet)" and ProcessCommandLine matches regex @"(?i)\\[0-9a-f]{32}_[^\\]+\.msi", "2 MSI GUID name",
 FileName =~ "msiexec.exe" and InitiatingProcessFileName in~ (PS) and ProcessCommandLine matches regex @"(?i)[-/–—―](qn|quiet)" and ProcessCommandLine matches regex @"(?i)(\\AppData\\Local\\Temp\\|%temp%)", "2 MSI TEMP via PS",
 FileName in~ ("DeElevate64.exe","COTFileReadApp.exe") and FolderPath contains @"\AppData\Local\Programs\" and InitiatingProcessFileName =~ "msiexec.exe", "3 host via msiexec",
 FolderPath matches regex @"(?i)\\AppData\\Local\\Programs\\(Stardock Smart DeElevation Tool|Advanced Printer Configuration Reader)\\", "3 lure folder",
 "")
| where isnotempty(S)
| summarize Types=dcount(S), Hits=count(), Signals=make_set(S), Cmds=make_set(ProcessCommandLine,5), First=min(Timestamp), Last=max(Timestamp) by DeviceId, DeviceName
| order by Types desc, Hits desc


// ---------------------------------------------------------------------
// H1b | Side-load confirmation: signed host loading the patched/malicious DLLs
// ATT&CK  : T1574.002
// Expected noise: Low (check Stardock DeElevation / Canon reader against
//   your software inventory). Note: generic public side-load rules (e.g.
//   Elastic "Unsigned DLL Side-Loading from a Suspicious Folder") do not
//   list %LOCALAPPDATA%\Programs, so this gap is worth covering explicitly.
// ---------------------------------------------------------------------
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("DeElevate64.exe", "COTFileReadApp.exe")
| where InitiatingProcessFolderPath contains @"\AppData\Local\Programs\"
| where FileName in~ ("DeElevator64.dll", "I++u.dll", "ceiinfolog.dll", "rdCore.dll", "WMPCL.dll")
| project Timestamp, DeviceName, InitiatingProcessFolderPath, LoadedDll = FolderPath, SHA256,
    InitiatingProcessAccountName
| order by Timestamp desc


// ---------------------------------------------------------------------
// H1c | Persistence named after the lure software (Huntress, background)
// ATT&CK  : T1547.001 (Run key; analyst mapping). Huntress also reports a
//   scheduled task with the same name - check Task Scheduler on any hit.
// Expected noise: Low unless the real software is deployed.
// ---------------------------------------------------------------------
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType =~ "RegistryValueSet"
| where RegistryKey contains @"\CurrentVersion\Run"
| where RegistryValueName in~ ("Stardock DeElevation Tool", "Canon Configuration Reader")
    or RegistryValueData contains @"\AppData\Local\Programs\Stardock Smart DeElevation Tool\"
    or RegistryValueData contains @"\AppData\Local\Programs\Advanced Printer Configuration Reader\"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc


// ---------------------------------------------------------------------
// H1d | ClickFix paste evidence: Win+R RunMRU entries written by explorer.exe
// ATT&CK  : T1204.004
// Pattern follows Microsoft's published ClickFix hunting query
// (ActionType "RegistryValueSet", initiating explorer.exe, RunMRU key).
// Expected noise: Low-Medium (admins do use Win+R for PowerShell).
// ---------------------------------------------------------------------
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType =~ "RegistryValueSet"
| where InitiatingProcessFileName =~ "explorer.exe"
| where RegistryKey has @"\CurrentVersion\Explorer\RunMRU"
| where RegistryValueName != "MRUList"
| where RegistryValueData has_any ("powershell", "pwsh", "mshta", "msiexec", "curl", "✅", "captcha", "verify", "verification")
| where RegistryValueData matches regex @"(?i)(https?://|\birm\b|\biwr\b|\biex\b|bypass|hidden|\d{8,10}/)"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryValueName, RegistryValueData
| order by Timestamp desc


// ---------------------------------------------------------------------
// H2 | LegionLoader route: PowerShell -> 7zr.exe passworded extraction -> oversized EXE
// ATT&CK  : T1105, T1027.013, T1027.001, T1140, T1059.001
// Hypothesis: If ROMULUS (Route B) reached our users, we expect PowerShell to
//   download 7zr.exe and an archive, run 7zr.exe with -p<password> and -y,
//   then launch a random-named executable padded to ~880 MB.
// Expected noise: Low. 7-Zip spawned by PowerShell with an inline password is
//   unusual (Sigma's generic 7-Zip password rule is Medium/noisy because it
//   has no parent condition); >500 MB EXEs in user paths are rare - allow-list
//   by signer.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("7zr.exe","7za.exe","7z.exe") or ProcessVersionInfoProductName has "7-Zip"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"\s-p\S+"
| extend Variant = iff(ProcessCommandLine matches regex @"\s-y(\s|$)", "-p and -y", "-p only")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, ProcessCommandLine, Variant


// ---------------------------------------------------------------------
// H2b (optional) | ~880 MB padded loader: oversized EXE written/executed from
//   user-writable paths (T1027.001). Allow-list large signed installers.
// ---------------------------------------------------------------------
let UserPath = @"(?i)\\(AppData|Users\\Public|ProgramData|Temp)\\";
union
 (DeviceFileEvents | where Timestamp > ago(14d) | where FileName endswith ".exe" and FileSize > 500000000 and FolderPath matches regex UserPath
  | extend Signal = "EXE >500MB written"),
 (DeviceProcessEvents | where Timestamp > ago(14d) | where FileSize > 500000000 and FolderPath matches regex UserPath
  | extend Signal = "EXE >500MB executed")
| project Timestamp, DeviceName, Signal, FolderPath, FileSize, InitiatingProcessFileName
| order by Timestamp desc


// ---------------------------------------------------------------------
// IOC SWEEP (optional) | Published ROMULUS / campaign infrastructure
// Sources: Forescout Vedere Labs (15 Oct 2026), Huntress (28 Sep 2026, upd. 14 Oct)
// Infrastructure rotates - a clean result here does NOT clear H1/H2.
// Verify each indicator against the original IOC tables before blocking.
// ---------------------------------------------------------------------
let iocDomains = dynamic(["orbitflownetwork.lol", "smashshape.com", "novatrafficcore.lol", "gptverification.com"]);
let iocIPs = dynamic(["96.62.224.81", "86.109.75.7", "151.240.151.223", "23.94.145.224",
                      "93.152.224.118", "2.27.248.127", "45.140.205.28"]);
let iocDecimal = dynamic(["1614733393", "1450003207"]);   // decimal forms of 96.62.224.81 / 86.109.75.7
union
  (DeviceNetworkEvents
   | where Timestamp > ago(14d)
   | where RemoteIP in (iocIPs) or RemoteUrl has_any (iocDomains)
   | project Timestamp, DeviceName, Hit = iff(isnotempty(RemoteUrl), RemoteUrl, RemoteIP),
       RemoteIP, RemotePort, Process = InitiatingProcessFileName, Cmd = InitiatingProcessCommandLine),
  (DeviceProcessEvents
   | where Timestamp > ago(14d)
   | where ProcessCommandLine has_any (iocDecimal) or ProcessCommandLine has_any (iocDomains)
   | project Timestamp, DeviceName, Hit = "cmdline IOC", RemoteIP = "", RemotePort = int(null),
       Process = FileName, Cmd = ProcessCommandLine)
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
CrowdStrike Falcon (CQL) | H1 multi-signal | PART 1 of 2
// Paste Part 1 + Part 2 together as ONE query. Time picker: last 14 days.
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/(irm|iwr|curl|https?:\/\/)\s*\d{8,10}(\/|:|\s|$)/i
      | Signal := "1-PS stager decimal-IP download";
    FileName=/^(powershell|pwsh)\.exe$/i ParentBaseFileName=/^explorer\.exe$/i CommandLine=/(https?:\/\/|irm\s|iwr\s|iex|invoke-(restmethod|webrequest|expression)|net\.webclient|download(string|file|data))/i
      | Signal := "1-PS download cradle; explorer.exe parent";
    FileName=/^(powershell|pwsh)\.exe$/i CommandLine=/[-\/–—―](w[a-z]*\s+h|e[a-z]*\s+bypass|e[a-z]*\s+[a-z0-9+\/=]{40,})/i CommandLine=/(https?:\/\/|irm\s|iwr\s|iex|invoke-(restmethod|webrequest|expression)|net\.webclient|download(string|file|data))/i
      | Signal := "1-PS stager hidden/bypass + download";
    FileName=/^msiexec\.exe$/i CommandLine=/[-\/–—―](qn|quiet)/i CommandLine=/\\[0-9a-f]{32}_[^\\]+\.msi/i
      | Signal := "2-Silent MSI with GUID-prefixed name";

CrowdStrike Falcon (CQL) | H1 multi-signal | PART 2 of 2
// Continues directly from Part 1.
    FileName=/^msiexec\.exe$/i ParentBaseFileName=/^(powershell|pwsh)\.exe$/i CommandLine=/[-\/–—―](qn|quiet)/i CommandLine=/(\\AppData\\Local\\Temp\\|%temp%)/i
      | Signal := "2-Silent MSI from TEMP launched by PowerShell";
    FileName=/^(DeElevate64|COTFileReadApp)\.exe$/i ImageFileName=/\\AppData\\Local\\Programs\\/i ParentBaseFileName=/^msiexec\.exe$/i
      | Signal := "3-Candidate host started by msiexec from user Programs";
    ImageFileName=/\\AppData\\Local\\Programs\\(Stardock Smart DeElevation Tool|Advanced Printer Configuration Reader)\\/i
      | Signal := "3-Process from lure install folder";
  }
| Signal=*
| groupBy(
    [aid, ComputerName],
    function=[
      count(Signal, distinct=true, as=signalTypes),
      count(as=hits),
      collect([Signal, UserName, CommandLine]),
      min(@timestamp, as=firstSeen),
      max(@timestamp, as=lastSeen)
    ],
    limit=max
  )
| sort(field=[signalTypes, hits], order=desc, limit=200)
```

Queries are untested: tune before use.

## Sources

1. Forescout Vedere Labs (15 Oct 2026): https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/
2. Huntress (28 Sep 2026, updated 14 Oct 2026): https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat
3. The Hacker News (20 Oct 2026): https://thehackernews.com/2026/10/romulus-clickfix-platform-tricks-users.html
4. Microsoft Threat Intelligence (21 Aug 2025): https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique
