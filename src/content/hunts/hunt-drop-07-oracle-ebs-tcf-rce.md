---
title: "Hunt Drop 07 | Oracle EBS: hunting the TCF servlet RCE"
hypothesis: "An EBS Java process or app account starts a shell."
attack: [T1190, T1059.004, T1082, T1016, T1049, T1071.001, T1571]
dataSources: ["Linux EDR process, file and network events"]
languages: [KQL, CQL]
drop: 7
risk: { likelihood: 3, impact: 5 }
status: published
date: 2026-10-30
---

Builds on [Intel Drop 21](/intel/intel-drop-21-oracle-ebs-sqli-rce/).

Oracle's October CPU fixed CVE-2026-101767, an unauthenticated SQL injection in the EBS Thin Client Framework servlet that chains to OS command execution. Decoy EBS systems were already being probed on 27 Oct. ERP is where GCC ministries and operators keep finance, payroll, HR and procurement data.

## The hypothesis
If an EBS 12.2.x app tier was hit, the EBS Java process or application account will start a shell, run host recon, leave files in $APPLPTMP and reach out to the internet.

## What to hunt
- Java spawning sh/bash on the EBS app tier (T1190, T1059.004)
- EBS account running ip addr, netstat, arp, /etc/hosts reads or a /dev/tcp shell (T1082, T1016, T1049)
- New or executed files in $APPLPTMP
- EBS servers talking to public IPs (T1071.001, T1571)

## Business risk
Exposure or tampering of ERP finance, payroll and HR data, with regulatory and reputational fallout if staff or citizen records leak. No confirmed compromise reported yet.
Risk score (analyst judgement): Likelihood 3 × Impact 5 = 15/25, CRITICAL

## Tune & triage
Baseline Concurrent Manager host programs per server and allow-list exact command lines. Any Java-to-shell with recon or /dev/tcp: isolate, pull web-tier logs for POSTs to /OA_HTML/AppsTCFServer, escalate to IR. Once quiet, tuned hunts can be promoted to detection rules.

**Risk: 15/25 CRITICAL** (likelihood 3 × impact 5, analyst judgement). Intel confidence: MODERATE (flaw); LOW (exploitation: decoys only). Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #07 | Oracle EBS CVE-2026-101767 (TCF servlet SQLi -> RCE)
// Builds on Intel Drop #21 | Microsoft Defender XDR Advanced Hunting
// Author: Arthur Thomas (draft) | TLP:CLEAR
// STATUS: UNTESTED in a live tenant. Test and tune before any use as a
// detection. Requires Defender for Endpoint P2 sensors on the Linux EBS
// application-tier hosts (no sensor = no telemetry = no result).
// Default window: 14 days (Timestamp > ago(14d)).
// EDIT FIRST: EbsAccounts, EbsHosts, ApplPtmp to match your estate.
// =====================================================================


// ---------------------------------------------------------------------
// H1 | EBS Java tier spawns a shell
// ATT&CK: T1190 (Exploit Public-Facing Application), T1059.004 (Unix Shell)
// Hypothesis: if CVE-2026-101767 (or another EBS RCE) was used against us,
//   the EBS Java process starts sh/bash on the app tier.
// Expected noise: Low-Medium. Some admin/WebLogic scripts may do this;
//   baseline per host and allow-list by exact command line.
// ---------------------------------------------------------------------
let EbsHosts = dynamic(["ebs-app01","ebs-app02"]);   // EDIT: EBS app-tier DeviceName values
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName has_any (EbsHosts)
| where InitiatingProcessFileName =~ "java"
| where FileName in~ ("sh","bash","dash","ksh")
| extend Suspicious = ProcessCommandLine has_any ("/dev/tcp","bash -i","base64","curl","wget","whoami","uname","ifconfig","ip addr","netstat","/proc/net/arp","/etc/hosts","/etc/fstab")
| summarize Hits = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Cmds = make_set(ProcessCommandLine, 25)
            by DeviceName, InitiatingProcessAccountName, AccountName, Suspicious
| order by Suspicious desc, Hits asc


// ---------------------------------------------------------------------
// H2 | EBS OS account runs host recon or a reverse shell
// ATT&CK: T1059.004, T1082 (System Information Discovery),
//         T1016 (System Network Configuration Discovery),
//         T1049 (System Network Connections Discovery), T1057 (Process Discovery)
// Hypothesis: after SQLi -> OS command execution, the EBS application
//   account (e.g. oracle / applmgr) runs recon commands or opens a
//   /dev/tcp reverse shell. Horizon3 says the oracle account spawns
//   /bin/sh via the Concurrent Manager, so do NOT filter on parent.
// Expected noise: Medium. Concurrent Manager host programs and DBA
//   scripts run under these accounts; triage by rarity per host.
// ---------------------------------------------------------------------
let EbsAccounts = dynamic(["oracle","applmgr"]);     // EDIT: your EBS OS accounts
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName in~ (EbsAccounts) or InitiatingProcessAccountName in~ (EbsAccounts)
| where ProcessCommandLine matches regex @"(?i)(/dev/tcp/|bash\s+-i|\bip\s+addr\b|\bifconfig\b|netstat\s+-an|\barp\s+-a\b|/proc/net/arp|cat\s+/etc/(hosts|fstab)|ps\s+-?aux|\bwhoami\b)"
| summarize Hits = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Parents = make_set(InitiatingProcessFileName, 10),
            Cmds = make_set(ProcessCommandLine, 25)
            by DeviceName, AccountName
| order by Hits asc


// ---------------------------------------------------------------------
// H3a | New files dropped in $APPLPTMP by EBS accounts
// ATT&CK: T1190 (post-exploitation artefact; analyst mapping)
// Hypothesis: exploitation leaves unexpected files in $APPLPTMP
//   (Horizon3 indicator).
// Expected noise: High. $APPLPTMP is a working temp dir for EBS; use as
//   a pivot around H1/H2 hits, not as a standalone alert.
// NOTE: ActionType value "FileCreated" not listed on the MS Learn schema
//   page; confirm in the in-portal schema reference.
// ---------------------------------------------------------------------
let ApplPtmp = "/CHANGE/ME/applptmp/";               // EDIT: value of $APPLPTMP on your app tier
let EbsAccounts = dynamic(["oracle","applmgr"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath startswith ApplPtmp
| where ActionType == "FileCreated"
| where InitiatingProcessAccountName in~ (EbsAccounts)
| summarize Files = make_set(FileName, 50), Writers = make_set(InitiatingProcessFileName, 10),
            Count = count() by DeviceName, bin(Timestamp, 1h)
| order by Timestamp desc


// ---------------------------------------------------------------------
// H3b | EBS app tier talks to the internet (Java or shell)
// ATT&CK: T1071.001 (Web Protocols), T1571 (Non-Standard Port) - analyst mapping
// Hypothesis: a foothold on EBS calls out for a second stage or a reverse
//   shell. Background: in the 2025 EBS campaign, Google/Mandiant saw Java
//   implants beaconing on 443 and a bash reverse shell to TCP/53.
// Expected noise: Low if EBS egress is already restricted; Medium otherwise
//   (licence checks, patch downloads, integrations - allow-list them).
// NOTE: RemoteIPType value "Public" not listed on the MS Learn schema page;
//   confirm in-portal.
// ---------------------------------------------------------------------
let EbsHosts = dynamic(["ebs-app01","ebs-app02"]);   // EDIT
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where DeviceName has_any (EbsHosts)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("java","sh","bash","dash","ksh","curl","wget","nc","ncat")
| summarize Conns = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Ports = make_set(RemotePort, 20), Urls = make_set(RemoteUrl, 20)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP
| order by Conns asc


// ---------------------------------------------------------------------
// IOC SWEEP: none. Oracle, Horizon3 and the reporting reviewed publish no
// IOCs for CVE-2026-101767 (as of 30 Oct 2026). The 2025 CL0P/EBS IOCs are
// a different campaign and are deliberately NOT swept here.
// ---------------------------------------------------------------------
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #07 | Oracle EBS CVE-2026-101767 (TCF servlet SQLi -> RCE)
// Builds on Intel Drop #21 | CrowdStrike Falcon CQL (NG-SIEM / Advanced Event Search)
// Author: Arthur Thomas (draft) | TLP:CLEAR
// STATUS: UNTESTED in a live tenant. Test and tune before any use as a
// detection. Requires Falcon Insight sensors on the Linux EBS app-tier hosts.
// TIME PICKER: set to Last 14 days for every query below.
// EDIT FIRST: host names, accounts and the $APPLPTMP path.
// FIELD CAVEATS (could not be verified against public docs this run):
//   [UNVERIFIED-1] UserName population on Linux ProcessRollup2 events.
//   [UNVERIFIED-2] RemotePort field name in NG-SIEM (legacy: RemotePort_decimal).
// =====================================================================


// ---------------------------------------------------------------------
// H1 | EBS Java tier spawns a shell
// ATT&CK: T1190, T1059.004 | Noise: Low-Medium
// Hypothesis: EBS Java process starts sh/bash after exploitation.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| in(ComputerName, ignoreCase=true, values=["ebs-app01","ebs-app02"])   // EDIT
| ParentBaseFileName=/^java$/i
| FileName=/^(sh|bash|dash|ksh)$/i
| case {
    CommandLine=/(\/dev\/tcp|bash -i|base64|curl|wget|whoami|uname|ifconfig|ip addr|netstat|\/proc\/net\/arp|\/etc\/hosts|\/etc\/fstab)/i | Suspicious:="yes";
    * | Suspicious:="no";
  }
| groupBy([ComputerName, UserName, Suspicious], function=[count(as=Hits), collect([CommandLine])])   // [UNVERIFIED-1]
| sort(Hits, order=asc, limit=1000)


// ---------------------------------------------------------------------
// H2 | EBS OS account runs host recon or a reverse shell
// ATT&CK: T1059.004, T1082, T1016, T1049, T1057 | Noise: Medium
// Hypothesis: EBS account (oracle/applmgr) runs recon or /dev/tcp shell.
// Parent not filtered: Horizon3 says the shell comes via Concurrent Manager.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| in(UserName, ignoreCase=true, values=["oracle","applmgr"])   // EDIT; [UNVERIFIED-1]
| CommandLine=/(\/dev\/tcp\/|bash\s+-i|\bip\s+addr\b|\bifconfig\b|netstat\s+-an|\barp\s+-a\b|\/proc\/net\/arp|cat\s+\/etc\/(hosts|fstab)|ps\s+-?aux|\bwhoami\b)/i
| groupBy([ComputerName, UserName, ParentBaseFileName], function=[count(as=Hits), collect([CommandLine])])
| sort(Hits, order=asc, limit=1000)


// ---------------------------------------------------------------------
// H3a | Execution from $APPLPTMP
// ATT&CK: T1190 (post-exploitation artefact; analyst mapping) | Noise: Medium
// Hypothesis: a dropped file in $APPLPTMP is executed. Falcon has no
// verified generic Linux file-write event for this hunt, so this hunts
// EXECUTION from the path instead (telemetry gap noted).
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| ImageFileName=/^\/CHANGE\/ME\/applptmp\//i     // EDIT: your $APPLPTMP path
| groupBy([ComputerName, ImageFileName, ParentBaseFileName], function=[count(as=Execs), collect([CommandLine])])
| sort(Execs, order=asc, limit=1000)


// ---------------------------------------------------------------------
// H3b | EBS app tier connects to public IPs
// ATT&CK: T1071.001, T1571 (analyst mapping) | Noise: Low if egress restricted
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4
| in(ComputerName, ignoreCase=true, values=["ebs-app01","ebs-app02"])   // EDIT
| !cidr(RemoteAddressIP4, subnet="10.0.0.0/8")
| !cidr(RemoteAddressIP4, subnet="172.16.0.0/12")
| !cidr(RemoteAddressIP4, subnet="192.168.0.0/16")
| !cidr(RemoteAddressIP4, subnet="127.0.0.0/8")
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count(as=Conns))   // [UNVERIFIED-2]
| sort(Conns, order=asc, limit=1000)


// ---------------------------------------------------------------------
// IOC SWEEP: none. No IOCs published for CVE-2026-101767 as of 30 Oct 2026.
// ---------------------------------------------------------------------
```

Queries are untested: tune before use.

## Sources

1. CVE-2026-101767: Oracle EBS SQL Injection RCE <https://horizon3.ai/attack-research/vulnerabilities/cve-2026-101767/>
2. Oracle Critical Patch Update Advisory – October 2026 <https://www.oracle.com/security-alerts/cpuoct2026.html>
3. Hackers Actively Exploiting New Oracle EBS RCE Vulnerability <https://cybersecuritynews.com/oracle-ebs-rce-exploited/>
4. Oracle E-Business Suite CVE-2026-101767: Critical (CVSS 9.8) Unauthenticated Flaw <https://www.rescana.com/post/oracle-e-business-suite-cve-2026-101767-prepare-now>
5. Oracle's October 2026 update: an unauthenticated E-Business Suite RCE sat behind a servlet the default firewall allows <https://r3konx.asia/oracle-october-2026-cpu-ebs-cve-2026-101767-default-allowlisted-servlet/>
6. Oracle E-Business Suite Zero-Day Exploited in Widespread Extortion Campaign <https://cloud.google.com/blog/topics/threat-intelligence/oracle-ebusiness-suite-zero-day-exploitation>
7. Threat-hunting-queries.md <https://github.com/amjcyber/crowdstrike/blob/main/Threat-hunting-queries.md>
