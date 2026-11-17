---
title: "Hunt Drop 14 | ARTEX: Hunting the AI-Run Intrusion Chain"
hypothesis: An ARTEX operator turned an internet-facing app into a web shell, then stole AD credentials and tunnelled out.
attack: [T1505.003, T1059.001, T1105, T1558.003, T1003.006, T1572, T1090, T1071.001]
dataSources: [EDR process events, File events, Network and DNS events, Directory service events]
languages: [KQL, CQL]
drop: 14
risk: { likelihood: 4, impact: 5 }
status: published
date: 2026-11-16
---

Builds on Intel Drop 40.

The FBI says some ARTEX intrusions went from first targeting to privileged access in under three hours. At that speed, hunt the attack chain, not an IP list.

## The hypothesis

If an ARTEX operator reached one of our internet-facing apps, we expect a web server process spawning shells, new ASPX/JSP/PHP files in web paths, then AD credential theft and tunnelled or LLM-API egress from servers that never talk to AI services.

## What to hunt

- `w3wp` / `java` / `php` spawning cmd, PowerShell, sh or recon tools (T1505.003, T1059.001)
- New `.aspx` / `.jsp` / `.php` files written by web or database processes (T1505.003, T1105)
- Replication requests from a non-DC, Kerberoasting, LAPS reads (T1558.003, T1003.006, analyst mapping)
- Chisel / SoftEther, webhook.site and non-browser LLM API calls (T1572, T1090, T1071.001)

## Business risk

Government, energy and telecom are among the sectors named in reporting on the FLASH, and researchers count 1,600+ exposed ARTEX consoles. One forgotten app can become domain compromise before a shift handover.

**Risk score:** likelihood 4 × impact 5 = **20/25, CRITICAL** (analyst judgement).

## Tune and triage

Baseline web-server child processes per host; allow-list deploy accounts and AD sync servers. On a hit: isolate, pull web and app logs, review new admin accounts and OAuth app credentials, and plan a double krbtgt reset if replication abuse is confirmed.

## Confidence

| Assessment | Confidence |
|---|---|
| Intel confidence (FBI FLASH, TLP:CLEAR) | HIGH |
| Detection fidelity | MEDIUM |

## Microsoft Defender (KQL)

```kql
// =====================================================================
// HUNT DROP #14 | ARTEX agentic intrusions: web shell -> AD -> tunnel
// Builds on Intel Drop #40 (FBI FLASH-20261113-001, TLP:CLEAR, 13 Nov 2026)
// Platform: Microsoft Defender XDR Advanced Hunting (KQL)
// STATUS: UNTESTED in a live tenant. Test and tune in a lab/tenant before use.
// Default window: 14 days (Timestamp > ago(14d)).
// =====================================================================

// ---------------------------------------------------------------------
// H1a | Web shell execution: web server process spawns shell / recon
// ATT&CK: T1505.003, T1059, T1059.001 (FLASH); T1190 (FLASH, initial access)
// Hypothesis: if ARTEX planted an ASPX/JSP/PHP web shell on one of our
//   internet-facing apps, the web server worker will spawn cmd/PowerShell/
//   sh and discovery binaries it never normally runs.
// Expected noise: MEDIUM - app health checks, deployment scripts, Java apps
//   that shell out legitimately. Baseline per host, allow-list by
//   ProcessCommandLine and parent folder.
// Licence: Defender for Endpoint P2 (Windows + Linux server onboarding).
// ---------------------------------------------------------------------
let WebParents = dynamic(["w3wp.exe","tomcat.exe","tomcat8.exe","tomcat9.exe","tomcat10.exe",
                          "java.exe","javaw.exe","php-cgi.exe","php.exe","httpd.exe","nginx.exe",
                          "java","php-fpm","php","httpd","apache2","nginx"]);
let Children  = dynamic(["cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe",
                          "nltest.exe","certutil.exe","curl.exe","bitsadmin.exe","systeminfo.exe",
                          "ipconfig.exe","tasklist.exe","sh","bash","dash","whoami","id","uname",
                          "curl","wget","nc","ncat"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (WebParents)
| where FileName in~ (Children)
| summarize Executions = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Children = make_set(FileName, 20), SampleCmds = make_set(ProcessCommandLine, 10)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Executions asc   // rare first: a few odd children beat a noisy baseline

// ---------------------------------------------------------------------
// H1b | Web shell drop: new .aspx/.jsp/.jspx/.php written by a web/shell process
// ATT&CK: T1505.003, T1105 (FLASH: "*.aspx or *.jsp files in unexpected web
//   application paths"; "JSP and PHP web shells (including via MySQL log poisoning)")
// Expected noise: MEDIUM-HIGH during deployments. Allow-list deployment
//   accounts / msdeploy / CI agents and change windows.
// ---------------------------------------------------------------------
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName matches regex @"(?i)\.(aspx|ashx|asmx|jsp|jspx|php|phtml)$"
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","tomcat9.exe","php-cgi.exe","httpd.exe",
                                       "mysqld.exe","mysqld","cmd.exe","powershell.exe","pwsh.exe",
                                       "java","php-fpm","httpd","apache2","nginx","sh","bash")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc

// ---------------------------------------------------------------------
// H2a | DCSync: directory replication requested by a non-DC
// ATT&CK: FLASH text "DCSync to steal domain krbtgt key" (no ID given) ->
//   T1003.006 [ANALYST MAPPING]
// Hypothesis: ARTEX reached domain privilege and replicated secrets from a
//   workstation/server that is not a domain controller.
// Licence: Defender for Identity sensors on DCs.
// Note: ActionType "Directory Services replication" taken from Microsoft
//   Tech Community example (2020); confirm the value in your tenant with
//   IdentityDirectoryEvents | distinct ActionType.
// Expected noise: LOW - Entra Connect / AD sync servers and new DCs. Allow-list them.
// ---------------------------------------------------------------------
let DCs = IdentityDirectoryEvents
    | where Timestamp > ago(30d)
    | where isnotempty(DestinationDeviceName)
    | distinct DC = tolower(DestinationDeviceName);
IdentityDirectoryEvents
| where Timestamp > ago(14d)
| where ActionType == "Directory Services replication"
| where tolower(DeviceName) !in (DCs)
| project Timestamp, DeviceName, IPAddress, AccountName, AccountDomain,
          DestinationDeviceName, AdditionalFields
| order by Timestamp desc

// ---------------------------------------------------------------------
// H2b | Kerberoasting / DCSync / AD enumeration tooling on endpoints
// ATT&CK: T1558.003 (FLASH, printed "T11558.003"), T1087.002 (FLASH),
//   T1059.001 (FLASH); T1003.006 [ANALYST MAPPING]
// Command-line strings below are ANALYST-SELECTED common tooling, not from the FLASH.
// Expected noise: LOW-MEDIUM - red team, AD admins running Get-ADDomainController.
// ---------------------------------------------------------------------
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("lsadump::dcsync","Invoke-Kerberoast","GetUserSPNs",
                                    "secretsdump","kerberoast","asktgs","Get-ADDomainController",
                                    "nltest /dclist","ms-Mcs-AdmPwd","Get-LapsADPassword")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// ---------------------------------------------------------------------
// H3a | Tunnels, webhook.site output and non-browser LLM API egress
// ATT&CK: T1572, T1090, T1071.001 (FLASH: "Tunneled traffic via Chisel and
//   SoftEther"; "Sent command output to rotating webhook.site endpoints";
//   LLM API endpoints as network indicators)
// Expected noise: MEDIUM - developers and sanctioned AI tools call LLM APIs.
//   Focus on servers, web hosts, DCs and service accounts.
// ---------------------------------------------------------------------
let LlmAndExfil = dynamic(["api.anthropic.com","api.deepseek.com","open.bigmodel.cn","api.x.ai",
                           "xcai.pro","webhook.site","api.db-ip.com"]);
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any (LlmAndExfil)
     or InitiatingProcessFileName has_any ("chisel","vpnclient","vpncmd","softether")
| where InitiatingProcessFileName !in~ (Browsers)
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Urls = make_set(RemoteUrl, 20), Cmds = make_set(InitiatingProcessCommandLine, 5)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Connections desc

// ---------------------------------------------------------------------
// H3b | IOC sweep - FBI FLASH-20261113-001 IOC table (IPs + domain)
// Infrastructure rotates: a miss is not a clean bill of health.
// Expected noise: LOW. Shared hosting/VPS ranges possible - verify before acting.
// ---------------------------------------------------------------------
let ArtexIPs = dynamic(["38.244.50.120","144.172.64.60","144.172.64.99","144.172.64.128",
    "187.15.88.186","187.15.90.217","187.15.89.186","101.53.80.20","205.214.59.31",
    "124.155.252.63","154.201.79.246","23.248.249.90","23.158.220.98","103.248.148.84",
    "203.160.133.172","209.209.85.38","199.19.95.66","199.19.95.67","199.19.95.68",
    "91.92.240.238","85.11.168.45","178.16.54.129","31.77.229.35","85.11.167.52"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (ArtexIPs) or RemoteUrl has "xcai.pro"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #14 | ARTEX agentic intrusions: web shell -> AD -> tunnel
// Builds on Intel Drop #40 (FBI FLASH-20261113-001, TLP:CLEAR, 13 Nov 2026)
// Platform: CrowdStrike Falcon NG-SIEM / Advanced Event Search (CQL)
// STATUS: UNTESTED in a live tenant. Test and tune before use.
// TIME WINDOW: set the time picker to Last 14 days for every query below.
// CQL double-check: cqlsearch.com not reachable from this run (blocked by
//   sandbox allowlist); cross-checked against CrowdStrike/logscale-community-content
//   (GitHub) + library.humio.com. See review notes.
// =====================================================================

// ---------------------------------------------------------------------
// H1a | Web server process spawns shell / recon (web shell execution)
// ATT&CK: T1505.003, T1059, T1059.001 (FLASH); T1190 (FLASH)
// Expected noise: MEDIUM - health checks, deploy scripts. Baseline per host.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| in(field="ParentBaseFileName", ignoreCase=true, values=["w3wp.exe","tomcat.exe","tomcat9.exe","java.exe","javaw.exe","php-cgi.exe","php.exe","httpd.exe","nginx.exe","java","php-fpm","httpd","apache2","nginx"])
| in(field="FileName", ignoreCase=true, values=["cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","nltest.exe","certutil.exe","curl.exe","bitsadmin.exe","systeminfo.exe","sh","bash","dash","whoami","id","uname","curl","wget","nc"])
| groupBy([aid, ComputerName, ParentBaseFileName, UserName], function=[count(as=executions), collect([FileName, CommandLine], limit=20)])
| sort(executions, order=asc, limit=500)

// ---------------------------------------------------------------------
// H1b | New ASPX/JSP/PHP script written (web shell drop)
// ATT&CK: T1505.003, T1105 (FLASH)
// Event names NewScriptWritten / WebScriptFileWritten as used in the CrowdStrike
//   community ToolShell query (logscale-community-content). Linux coverage of
//   these events: [UNVERIFIED] - confirm in your tenant.
// Expected noise: MEDIUM-HIGH during deployments. Allow-list CI/deploy accounts.
// ---------------------------------------------------------------------
#event_simpleName=/^(NewScriptWritten|WebScriptFileWritten)$/
| FileName=/\.(aspx|ashx|asmx|jsp|jspx|php|phtml)$/i
| table([@timestamp, aid, ComputerName, #event_simpleName, TargetFileName, FileName, ContextProcessId])
| sort(@timestamp, order=desc, limit=1000)

// ---------------------------------------------------------------------
// H2 | Kerberoasting / DCSync / DC + LAPS enumeration tooling
// ATT&CK: T1558.003 (FLASH, printed "T11558.003"), T1087.002, T1059.001 (FLASH);
//   T1003.006 [ANALYST MAPPING for "DCSync to steal domain krbtgt key"]
// Strings are ANALYST-SELECTED common tooling, not from the FLASH.
// Expected noise: LOW-MEDIUM - red team, AD admins. Identity-layer DCSync is
//   better hunted in Falcon Identity Protection / Defender for Identity.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(lsadump::dcsync|invoke-kerberoast|getuserspns|secretsdump|kerberoast|asktgs|get-addomaincontroller|nltest\s+\/dclist|ms-mcs-admpwd|get-lapsadpassword)/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)

// ---------------------------------------------------------------------
// H3a | Non-browser DNS to LLM APIs / webhook.site / reseller (C2, tunnelling)
// ATT&CK: T1071.001, T1090, T1572 (FLASH)
// ContextBaseFileName on DnsRequest as used in community query "Get DNS
//   Resolutions from Browser Processes".
// Expected noise: MEDIUM - sanctioned AI tooling, dev laptops. Focus on servers.
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest
| DomainName=/(^|\.)(api\.anthropic\.com|api\.deepseek\.com|open\.bigmodel\.cn|api\.x\.ai|xcai\.pro|webhook\.site|api\.db-ip\.com)$/i
| !in(field="ContextBaseFileName", ignoreCase=true, values=["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe"])
| groupBy([aid, ComputerName, ContextBaseFileName], function=[count(as=lookups), collect([DomainName], limit=20)])
| sort(lookups, order=desc, limit=500)

// ---------------------------------------------------------------------
// H3b | Chisel / SoftEther execution (tunnelling)
// ATT&CK: T1572, T1090 (FLASH: "Tunneled traffic via Chisel and SoftEther")
// Expected noise: LOW - admins using SoftEther VPN client. Renamed binaries evade this.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| (ImageFileName=/(chisel|vpnclient|vpncmd|softether)[^\\\/]*$/i OR CommandLine=/\b(client|server)\s+.*\bR:/i)
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])

// ---------------------------------------------------------------------
// H3c | IOC sweep - FBI FLASH-20261113-001 IP list
// Expected noise: LOW. Infrastructure rotates; a miss is not proof of absence.
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4
| in(field="RemoteAddressIP4", values=["38.244.50.120","144.172.64.60","144.172.64.99","144.172.64.128","187.15.88.186","187.15.90.217","187.15.89.186","101.53.80.20","205.214.59.31","124.155.252.63","154.201.79.246","23.248.249.90","23.158.220.98","103.248.148.84","203.160.133.172","209.209.85.38","199.19.95.66","199.19.95.67","199.19.95.68","91.92.240.238","85.11.168.45","178.16.54.129","31.77.229.35","85.11.167.52"])
| groupBy([aid, ComputerName, RemoteAddressIP4, RemotePort], function=[count(as=connections), collect([ContextBaseFileName])])  // ContextBaseFileName on NetworkConnectIP4: [UNVERIFIED]
```

Queries are untested: tune before use.

## Sources

1. FBI / IC3: Threat Overview of ARTEX Autonomous Penetration Testing Framework, FLASH-20261113-001 (13 Nov 2026) <https://www.ic3.gov/CSA/2026/261113.pdf>
2. OODA Loop: FBI FLASH on ARTEX: Agentic AI Hacking Frameworks Move From Pen Testing Tool to Mainstream Threat (14 Nov 2026) <https://oodaloop.com/analysis/ooda-original/fbi-flash-on-artex-agentic-ai-hacking-frameworks-move-from-pen-testing-tool-to-mainstream-threat/>
3. SafeBreach: ARTEX AI Attack Framework, coverage for FBI FLASH-20261113-001 (14 Nov 2026) <https://www.safebreach.com/blog/artex-ai-attack-framework-fbi-flash-alert-20261113-001-safebreach-coverage/>
4. GBHackers On Security: FBI Warns Hackers Are Weaponizing ARTEX AI Framework (14 Nov 2026) <https://gbhackers.com/fbi-warns-artex-ai-framework/>
