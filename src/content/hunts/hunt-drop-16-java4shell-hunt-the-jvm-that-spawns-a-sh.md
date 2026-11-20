---
title: "Hunt Drop 16 | Java4Shell: hunt the JVM that spawns a shell"
hypothesis: "An internet-facing Java process starts a shell or download tool after exploitation of CVE-2026-114938."
attack: [T1190, T1059.004, T1059.001, T1105, T1505.003]
dataSources: ["Linux EDR process events", "Process lineage"]
languages: [KQL, CQL]
drop: 16
risk: { likelihood: 3, impact: 5 }
status: published
date: 2026-11-18
---

Builds on [Intel Drop 43](/intel/intel-drop-43-java4shell-openjdk/).

## The hypothesis
If someone exploits CVE-2026-114938 on one of our internet-facing Java servers, the memory corruption itself is hard to see. What the attacker does next is not: a Java process starting a shell or download tool.

WHAT TO HUNT (ATT&CK mapping is my own)
- java / javaw spawning sh, bash, curl, wget, cmd or PowerShell (T1190, T1059.004, T1059.001, T1105)
- New script or JSP files written by the Java process (T1505.003)
- Fresh hs_err_pid crash files and unexpected JVM restarts
- Java servers with no -XX:-UseBASE64Intrinsics or -XX:UseAVX=2 mitigation visible

## Business risk
Researchers report pre-auth RCE proofs against apps such as Jenkins, Confluence and Tomcat on AVX-512 x86-64 hosts. A public trigger exists, but no exploitation is reported yet. Risk score: Likelihood 3 × Impact 5 = 15/25, CRITICAL (analyst judgement, same as the Intel Drop).

## Tune & triage
Allow-list build servers: Jenkins and Maven legitimately spawn shells. On a hit, isolate the host, patch and restart the JVM, and rotate secrets the process could read.

**Risk: 15/25 CRITICAL** (likelihood 3 × impact 5, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// HUNT DROP #16 - Java4Shell CVE-2026-114938 (builds on Intel Drop #43)
// UNTESTED in a live tenant. Test and tune before use. Default window 14 days.
// ATT&CK: none given by the sources; all IDs below are ANALYST mappings.
// Schema checked in this run (learn.microsoft.com en-us): DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceTvmSoftwareInventory.
// Note: the learn.microsoft.com pages do not state Linux support for these tables; confirm Defender for Endpoint on Linux coverage for your Java hosts.

// ===== Hunt 1: Java server process spawns a shell or download tool (core behaviour) =====
// Hunt Drop #16 | ATT&CK: T1190, T1059.004, T1059.001, T1105 (analyst)
// Hypothesis: after exploitation, a Java server process runs a shell, scripting host or download tool (SentinelOne and Qualys both list this as a signal).
// Expected noise: HIGH on CI/build servers (Jenkins, Maven, Gradle) and some Atlassian apps; allow-list by InitiatingProcessCommandLine and path.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("java","java.exe","javaw.exe")
| where FileName in~ ("sh","bash","dash","zsh","ash","busybox","python","python3","perl","php","ruby","nc","ncat","socat","curl","wget",
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","certutil.exe","bitsadmin.exe")
| summarize Execs=count(), Cmds=make_set(ProcessCommandLine, 5), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName
| order by Execs desc

// ===== Hunt 2: new script / web-shell style files written by a Java process =====
// Hunt Drop #16 | ATT&CK: T1505.003 (analyst; SentinelOne lists JSP web shells and second-stage binaries as post-exploitation files)
// Hypothesis: the exploited JVM writes .jsp/.jspx/script/binary files.
// Expected noise: HIGH (plugin installs, deployments, temp files). Tune with FolderPath allow-lists.
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("java","java.exe","javaw.exe")
| where FileName matches regex @"(?i)\.(jsp|jspx|sh|ps1|exe|dll)$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc

// ===== Hunt 3: JVM crash artefacts (attempt indicator, not proof) =====
// Hunt Drop #16 | ATT&CK: T1190 (analyst)
// Hypothesis: failed or unstable exploitation crashes the JVM and leaves hs_err_pid files (security.com, Qualys: unexpected crashes/restarts).
// Expected noise: any ordinary JVM crash; look for clusters on internet-facing hosts.
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName startswith "hs_err_pid"
| summarize Files=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, FolderPath, InitiatingProcessCommandLine
| order by Files desc

// ===== Hunt 4: exposure scoping - internet-facing Java with no visible mitigation flag =====
// Hunt Drop #16 | ATT&CK: T1190 (analyst) | exposure scoping, not detection
// Hypothesis: Java servers that accept public connections and show neither mitigation flag are the patch/mitigate-first list.
// Caveats: flags may be set via JAVA_TOOL_OPTIONS or option files not visible in the command line; the CPU must also support AVX-512 VBMI (check /proc/cpuinfo, not visible here).
// ActionType "InboundConnectionAccepted" is not listed on the official page (values are not documented there); it appears in a community Java4Shell query (screenshot of a LinkedIn post) - verify in your tenant.
// RemoteIPType "FourToSixMapping" is a documented example value; IPv4-mapped IPv6 clients can show it.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType == "InboundConnectionAccepted"
| where InitiatingProcessFileName in~ ("java","java.exe","javaw.exe")
| where RemoteIPType in ("Public","FourToSixMapping")
| extend MitigationFlag = iff(InitiatingProcessCommandLine contains "-XX:-UseBASE64Intrinsics" or InitiatingProcessCommandLine contains "-XX:UseAVX=2", "flag-present", "NO-FLAG-VISIBLE")
| summarize Conns=count(), RemoteIPs=dcount(RemoteIP), LastSeen=max(Timestamp) by DeviceName, LocalPort, MitigationFlag, InitiatingProcessFolderPath
| order by MitigationFlag asc, Conns desc

// ===== Hunt 5: Java runtime inventory (match against vendor fixed builds) =====
// Hunt Drop #16 | exposure scoping
// Fixed builds per Qualys / security.com: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 (Oracle Java SE 8 -perf: 8u513-perf). Vendor build strings differ (Corretto, Temurin, etc.): match per vendor advisory.
// Affected only on x86-64 with AVX-512 VBMI; ARM64 not affected.
DeviceTvmSoftwareInventory
| where SoftwareName has_any ("jdk","jre","java","openjdk","temurin","corretto","zulu","liberica","sapmachine")
| project DeviceName, OSPlatform, OSArchitecture, SoftwareVendor, SoftwareName, SoftwareVersion
| order by SoftwareVendor asc, SoftwareName asc, SoftwareVersion asc
```

## CrowdStrike Falcon (CQL)

```
// HUNT DROP #16 - Java4Shell CVE-2026-114938 (builds on Intel Drop #43)
// UNTESTED. Set the time picker to the last 14 days. ATT&CK IDs are ANALYST mappings (sources give none).
// CQL double-check: cqlsearch.com NOT reachable this run (URL_NOT_ON_ALLOWLIST). Fallback: CrowdStrike Log4Shell blog + community mirrors. See notes.
// Falcon has no verified file-write event for hs_err_pid files in this run, so crash files are covered only in the Defender file.

// ===== Hunt 1: Java parent -> shell / scripting host / download tool =====
// Hunt Drop #16 | ATT&CK: T1190, T1059.004, T1059.001, T1105 (analyst)
// Hypothesis: an exploited Java server process runs a shell or download tool.
// Expected noise: HIGH on CI/build servers (Jenkins, Maven); allow-list by ComputerName and CommandLine.
// Time picker: 14 days
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^javaw?(\.exe)?$/i
| FileName=/^(sh|bash|dash|zsh|ash|busybox|python[0-9.]*|perl|php|nc|ncat|socat|curl|wget|cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe|certutil\.exe|bitsadmin\.exe)$/i
| groupBy([aid, ComputerName, ParentBaseFileName, FileName], function=[count(aid, as=Execs), collect([CommandLine])])
| sort(Execs, order=desc)

// ===== Hunt 2: Java launched without a visible mitigation flag (exposure scoping) =====
// Hunt Drop #16 | ATT&CK: T1190 (analyst) | scoping, not detection
// Caveat: flags set through JAVA_TOOL_OPTIONS or option files are not visible in CommandLine; this lists candidates, not vulnerable hosts.
// Time picker: 14 days
#event_simpleName=ProcessRollup2 FileName=/^javaw?(\.exe)?$/i
| CommandLine!=/-XX:-UseBASE64Intrinsics|-XX:UseAVX=2/
| groupBy([aid, ComputerName], function=[count(aid, as=Launches), collect([ImageFileName])])
| sort(Launches, order=desc)
```

Queries are untested: tune before use.

## Sources

1. Datadog Security Labs (17 Nov 2026): <https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/>
2. Wiz (17 Nov 2026): <https://www.wiz.io/blog/cve-2026-114938-rce-java4shell-openjdk>
3. Qualys (17 Nov 2026): <https://blog.qualys.com/vulnerabilities-threat-research/2026/11/17/how-to-find-mitigate-and-patch-the-critical-java4shell-flaw-cve-2026-114938-now>
4. SentinelOne (17 Nov 2026): <https://www.sentinelone.com/blog/java4shell-vulnerability-in-openjdk-enables-rce-on-avx-512-cpus/>
5. Symantec (security.com) (18 Nov 2026): <https://www.security.com/blog-post/java4shell-cve2026114938-patch-now>
