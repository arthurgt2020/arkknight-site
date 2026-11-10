---
title: "Hunt Drop 06 | Fake \"IT Support\" in Teams"
hypothesis: "An IT-desk chat becomes a remote session and a stager in under 30 minutes."
attack: [T1566.003, T1656, T1667, T1219, T1059.001, T1204.002, T1105, T1087.002, T1018]
dataSources: ["Teams chats", "Email events", "Endpoint process and network events"]
languages: [KQL, CQL]
drop: 6
risk: { likelihood: 4, impact: 4 }
status: published
date: 2026-10-28
---

Builds on [Intel Drop 15](/intel/intel-drop-15-teams-fake-it-support/).

## The hypothesis
If this campaign reached our users, we expect an external Teams chat from an "IT Support" style sender, often after an inbox flood, followed within ~30 minutes by Quick Assist or an RMM tool, a user-run PowerShell/MSI stager and pythonw.exe running from AppData.

## What to hunt
- External Teams chats from help-desk display names or default .onmicrosoft tenants, after email bombing (T1566.003, T1656, T1667)
- Quick Assist/RMM launch, then explorer → PowerShell download → msiexec (T1219, T1059.001, T1204.002, T1105)
- pythonw.exe from a user folder making LDAP connections to domain controllers (T1087.002, T1018)
- A second remote-access tool on the same host within 24 hours (T1219)

## Business risk
External federation is on by default. One convincing chat can put an operator on a ministry or utility endpoint. In some reported cases this led to data theft and ransomware.
Risk score: Likelihood 4 × Impact 4 = 16/25, CRITICAL (analyst judgement)

## Tune & triage
Allow-list partner tenants and your sanctioned RMM tools before you run these.
On a hit: confirm the chat with the user, isolate the host, scope LDAP activity and new RMM installs, and revoke the user's sessions.

**Risk: 16/25 CRITICAL** (likelihood 4 × impact 4, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================
// HUNT DROP #06 | Fake "IT Support" in Teams external chat -> Quick Assist/RMM -> PowerShell/MSI -> pythonw implant
// Builds on Intel Drop #15 | Microsoft Defender XDR Advanced Hunting (KQL)
// Author: Arthur T. (draft) | TLP:CLEAR | Drafted 2026-10-28
// STATUS: UNTESTED in a live tenant. These are HUNTS. Test and tune in a lab/tenant before any use;
//         tuned versions may later be promoted to custom detection rules (see notes in the .md).
// Default window: 14 days (Timestamp > ago(14d)).
// =====================================================================


// ---------------------------------------------------------------------
// H1 | External Teams chat from an IT/help-desk themed sender (optionally after an inbox flood)
// ATT&CK: T1566.003 Spearphishing via Service | T1656 Impersonation | T1667 Email Bombing | T1585.003 Cloud Accounts
// Hypothesis: if this campaign reached our users, we expect an external (federated) Teams chat whose sender display
//             name impersonates IT/help desk, or comes from a default *.onmicrosoft.com tenant, often within hours of
//             an inbound mail flood to the same user.
// Telemetry/licensing: Defender for Office 365 (MessageEvents: external conversations), Exchange Online (EmailEvents)
// Expected noise: MEDIUM - genuine vendor/partner support desks, MSP engineers using external chat; allow-list partner tenants.
// ---------------------------------------------------------------------
let lookback = 14d;
let ownDomains = dynamic(["contoso.com"]);            // <-- replace with your accepted domains
let partnerAllow = dynamic(["partner-msp.com"]);      // <-- replace with sanctioned external support tenants/domains
let itLure = @"(?i)(help\s*desk|\bit[\s\-/]*(support|service|desk|admin|representative|team)|service\s*desk|tech\s*support|\(internal\)|maintenance\s*service|supporte?\s+ti)";
let teamsLure = MessageEvents
    | where Timestamp > ago(lookback)
    | where IsExternalThread == true
    | extend SenderDomain = tolower(tostring(split(SenderEmailAddress, "@")[1]))
    | where not(SenderDomain in~ (ownDomains)) and not(SenderDomain in~ (partnerAllow))
    | where SenderDisplayName matches regex itLure or SenderDomain endswith ".onmicrosoft.com"
    | mv-expand Recipient = RecipientDetails
    | extend RecipientSmtp = tolower(tostring(Recipient.RecipientSmtpAddress))
    | where isnotempty(RecipientSmtp) and RecipientSmtp != tolower(SenderEmailAddress)
    | project ChatTime = Timestamp, RecipientSmtp, SenderDisplayName, SenderEmailAddress, SenderDomain, ThreadId, DeliveryAction;
let mailFlood = EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Inbound"
    | summarize FloodCount = count() by RecipientSmtp = tolower(RecipientEmailAddress), FloodHour = bin(Timestamp, 1h)
    | where FloodCount >= 50;                         // <-- tune to your per-user hourly baseline
teamsLure
| join kind=leftouter mailFlood on RecipientSmtp
| extend FloodBeforeChat = iff(isnotnull(FloodHour) and FloodHour between ((ChatTime - 6h) .. ChatTime), 1, 0)
| summarize Chats = dcount(ThreadId), FloodBeforeChat = max(FloodBeforeChat), MaxHourlyFlood = max(FloodCount),
            FirstChat = min(ChatTime), LastChat = max(ChatTime)
            by RecipientSmtp, SenderDisplayName, SenderEmailAddress, SenderDomain
| order by FloodBeforeChat desc, FirstChat desc

// Optional pivot - the same ChatCreated event Arctic Wolf alerts on, via the Office 365 audit feed.
// NOTE: ActionType value "ChatCreated" is taken from the Arctic Wolf report; confirm it in your tenant first:
// CloudAppEvents | where Timestamp > ago(14d) | where Application has "Teams" | distinct ActionType


// ---------------------------------------------------------------------
// H1-IOC | Sweep for published attacker tenants and domains (Arctic Wolf appendices). Low longevity - rotate often.
// ATT&CK: T1585.003 | T1583.001
// ---------------------------------------------------------------------
let badTenants = dynamic(["supportedge33.onmicrosoft.com","helpdeskteam365.onmicrosoft.com","itendpoint365.onmicrosoft.com",
    "itcoreportal.onmicrosoft.com","networkadmin797.onmicrosoft.com","networkadmin916.onmicrosoft.com","itadmin922.onmicrosoft.com",
    "supportagentonline.onmicrosoft.com","threatpro.onmicrosoft.com","ithelpplus42.onmicrosoft.com",
    "corporateitservicellc.onmicrosoft.com","techsupport2337.onmicrosoft.com"]);
let badDomains = dynamic(["update-software.top","expertassist.top","getsystembridge.top","techrelay.top","it-assistant.top",
    "get-help-systems.top","fix-it.top","helpdesk-support-us-ny.com","helpdesk-call.com","itdeskassist.com",
    "kilan.com.pl","saludcentro.gov.co","ggc.com.ph","scapini.com.br"]);
union
  (MessageEvents
    | where Timestamp > ago(14d)
    | extend SenderDomain = tolower(tostring(split(SenderEmailAddress, "@")[1]))
    | where SenderDomain in~ (badTenants) or SenderDomain in~ (badDomains)
    | project Timestamp, Source = "TeamsMessage", Entity = SenderEmailAddress, Detail = SenderDisplayName),
  (DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has_any (badDomains)
    | project Timestamp, Source = "DeviceNetwork", Entity = DeviceName, Detail = strcat(InitiatingProcessFileName, " -> ", RemoteUrl))
| order by Timestamp desc


// ---------------------------------------------------------------------
// H2 | Remote-assist session followed by a user-run PowerShell/MSI stager and a pythonw implant
// ATT&CK: T1219 Remote Access Software | T1059.001 PowerShell | T1204.002 Malicious File | T1105 Ingress Tool Transfer
// Hypothesis: if an operator got hands-on via Quick Assist/RMM, within ~30 min we expect explorer.exe -> powershell.exe
//             with a download (Azure Blob / MSI), msiexec pulling or running from user paths, a script under
//             AppData\Local\PowershellCleaner, and pythonw.exe running from a user-writable folder.
// Telemetry/licensing: Defender for Endpoint P2 (DeviceProcessEvents)
// Expected noise: MEDIUM - real help-desk sessions followed by admin scripts; allow-list your sanctioned RMM + signed installers.
// ---------------------------------------------------------------------
let lookback = 14d;
let remoteTools = dynamic(["quickassist.exe","msra.exe","anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe",
    "ateraagent.exe","client32.exe"]);              // <-- add your RMM inventory; remove sanctioned tools
let remoteStart = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ (remoteTools)
    | project DeviceId, DeviceName, RmmTime = Timestamp, RmmTool = FileName, RmmUser = AccountName;
let stager = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where (FileName in~ ("powershell.exe","pwsh.exe") and InitiatingProcessFileName =~ "explorer.exe"
             and ProcessCommandLine has_any ("http", "blob.core.windows.net", ".msi", "DownloadFile", "Invoke-WebRequest", "iwr ", "Start-BitsTransfer"))
         or (FileName =~ "msiexec.exe" and ProcessCommandLine has_any ("http", @"\AppData\", @"\Temp\"))
         or (ProcessCommandLine has "PowershellCleaner")
         or (FileName =~ "pythonw.exe" and FolderPath has_any (@"\AppData\", @"\Temp\", @"\ProgramData\"))
    | project DeviceId, StageTime = Timestamp, StageFile = FileName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, AccountName;
remoteStart
| join kind=inner stager on DeviceId
| where StageTime between (RmmTime .. (RmmTime + 30m))
| summarize Stages = make_set(StageFile, 10), Cmds = make_set(ProcessCommandLine, 10), FirstStage = min(StageTime)
            by DeviceName, RmmTool, RmmTime, RmmUser
| extend StageCount = array_length(Stages)
| order by StageCount desc, RmmTime desc


// ---------------------------------------------------------------------
// H2b | High-fidelity artefact: script dropped under AppData\Local\PowershellCleaner (as described by Arctic Wolf)
// ATT&CK: T1059.001 | T1036 Masquerading | T1105
// Telemetry/licensing: Defender for Endpoint P2 (DeviceFileEvents) | Expected noise: LOW
// ---------------------------------------------------------------------
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has @"\AppData\Local\PowershellCleaner\"
   or (FileName =~ "archive6.zip")
   or (FileName =~ "ss.py" and FolderPath has @"\AppData\")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc


// ---------------------------------------------------------------------
// H3 | pythonw/python from a user-writable path talking LDAP to domain controllers (implant AD recon)
// ATT&CK (analyst mapping of LDAP user/computer enumeration described in the source): T1087.002 Domain Account | T1018 Remote System Discovery
// Hypothesis: the ss.py implant queries AD over LDAP (adsisearcher) for users and computers right after execution.
// Telemetry/licensing: Defender for Endpoint P2 (DeviceNetworkEvents); optional Defender for Identity (IdentityQueryEvents)
// Expected noise: LOW-MEDIUM - admin/dev Python tooling (e.g. ldap3 scripts); allow-list by path and account.
// ---------------------------------------------------------------------
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort in (389, 636, 3268, 3269)
| where InitiatingProcessFileName in~ ("pythonw.exe", "python.exe")
| where InitiatingProcessFolderPath has_any (@"\AppData\", @"\Temp\", @"\ProgramData\", @"\Users\Public\")
| summarize Conns = count(), DCs = make_set(RemoteIP, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by FirstSeen desc

// H3b (optional, Defender for Identity) | burst of LDAP queries from one workstation/account in 10 minutes
// NOTE: Protocol values are not enumerated on the schema page; "has 'ldap'" is used so it is case-insensitive. Verify in tenant.
IdentityQueryEvents
| where Timestamp > ago(14d)
| where Protocol has "ldap"
| summarize Queries = count(), Targets = dcount(QueryTarget), QueryTypes = make_set(QueryType, 10)
            by DeviceName, AccountName, Window = bin(Timestamp, 10m)
| where Targets >= 50                                 // <-- tune; baseline admin servers first
| order by Targets desc


// ---------------------------------------------------------------------
// H3c | Second remote-access tool stacked on the same host within 24h (persistence via another RMM)
// ATT&CK: T1219 Remote Access Software
// Expected noise: MEDIUM - IT teams using two tools; exclude your sanctioned pair.
// ---------------------------------------------------------------------
let remoteTools3 = dynamic(["quickassist.exe","msra.exe","anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe",
    "ateraagent.exe","client32.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ (remoteTools3)
| summarize FirstSeen = min(Timestamp) by DeviceName, Tool = tolower(FileName)
| summarize Tools = make_set(Tool, 10), ToolCount = dcount(Tool), Span = max(FirstSeen) - min(FirstSeen) by DeviceName
| where ToolCount >= 2 and Span <= 24h
| order by ToolCount desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================
// HUNT DROP #06 | Fake "IT Support" in Teams external chat -> Quick Assist/RMM -> PowerShell/MSI -> pythonw implant
// Builds on Intel Drop #15 | CrowdStrike Falcon (CQL) - Next-Gen SIEM / Advanced Event Search
// Author: Arthur T. (draft) | TLP:CLEAR | Drafted 2026-10-28
// STATUS: UNTESTED in a live tenant. These are HUNTS. Test and tune before any use; tuned versions may later be
//         promoted to a custom IOA / correlation rule (see notes in the .md).
// TIME PICKER: set to Last 14 days for every query below.
// FIELD VERIFICATION: #event_simpleName, event_platform, aid, ImageFileName, CommandLine, UserSid, case{}, groupBy(),
//   collect(), count(distinct=true), regex named captures were checked against public LogScale/Falcon tutorial docs.
//   Lines marked  // UNVERIFIED FIELD  use field names that are standard in Falcon telemetry but could not be confirmed
//   on a public documentation page in this run - confirm them in your Event Search field list before use.
// H1 (Teams chat / email bombing) has NO Falcon endpoint equivalent: Teams chat events are not endpoint telemetry.
//   If you ingest Microsoft 365 audit logs into NG-SIEM, build H1 on that parser's field names.
// =====================================================================


// ---------------------------------------------------------------------
// H2 | Remote-assist tool + user-run PowerShell/MSI stager + pythonw from user path on the same host
// ATT&CK: T1219 | T1059.001 | T1204.002 | T1105
// Hypothesis: Quick Assist/RMM launch, then explorer -> powershell download, msiexec from user/URL paths,
//             PowershellCleaner script, pythonw.exe from AppData. Two or more stages on one host = hunt lead.
// Expected noise: MEDIUM - genuine help-desk sessions; exclude sanctioned RMM and signed software deployment paths.
// Note: this groups co-occurrence across the time window; check ordering/timing (target: <30 min) during triage.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
    ImageFileName=/\\(quickassist|msra|anydesk|teamviewer|ateraagent|client32|screenconnect\.clientservice)\.exe$/i
      | Stage := "1_remote_assist" ;
    ImageFileName=/\\(powershell|pwsh)\.exe$/i ParentBaseFileName=/^explorer\.exe$/i CommandLine=/(https?:|blob\.core\.windows\.net|\.msi|DownloadFile|Invoke-WebRequest|iwr\s|Start-BitsTransfer)/i
      | Stage := "2_ps_stager" ;   // UNVERIFIED FIELD: ParentBaseFileName
    ImageFileName=/\\msiexec\.exe$/i CommandLine=/(https?:|\\AppData\\|\\Temp\\)/i
      | Stage := "2_msiexec_user_path" ;
    CommandLine=/PowershellCleaner/i
      | Stage := "3_cleaner_script" ;
    ImageFileName=/\\(AppData|Temp|ProgramData)\\.*\\pythonw\.exe$/i
      | Stage := "4_pythonw_user_path" ;
  }
| groupBy([aid], function=[count(Stage, distinct=true, as=StageCount), collect([Stage, ImageFileName, CommandLine, UserSid])], limit=max)
| test(StageCount >= 2)
| sort(StageCount, order=desc)


// ---------------------------------------------------------------------
// H2b | High-fidelity artefacts named in the source: PowershellCleaner script path, archive6.zip, ss.py
// ATT&CK: T1059.001 | T1036 | T1105      Expected noise: LOW
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(\\AppData\\Local\\PowershellCleaner\\|archive6\.zip|\\ss\.py)/i
| table([@timestamp, aid, UserSid, ImageFileName, CommandLine], limit=1000)


// ---------------------------------------------------------------------
// H3 | pythonw/python making LDAP / Global Catalog connections (implant AD recon via adsisearcher)
// ATT&CK (analyst mapping): T1087.002 | T1018
// Expected noise: LOW-MEDIUM - admin/dev Python LDAP tooling; allow-list by host and path.
// ---------------------------------------------------------------------
#event_simpleName=NetworkConnectIP4 event_platform=Win
| in(field=RemotePort, values=["389", "636", "3268", "3269"])   // UNVERIFIED FIELD: RemotePort
| ContextBaseFileName=/^pythonw?\.exe$/i                          // UNVERIFIED FIELD: ContextBaseFileName
| groupBy([aid, ContextBaseFileName], function=[count(as=Conns), collect([RemoteAddressIP4, RemotePort])], limit=max)   // UNVERIFIED FIELD: RemoteAddressIP4
| sort(Conns, order=desc)


// ---------------------------------------------------------------------
// H3c | Two or more remote-access tool families on the same host (second RMM for persistence)
// ATT&CK: T1219      Expected noise: MEDIUM - exclude your sanctioned pair of tools.
// ---------------------------------------------------------------------
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(?<RmmTool>quickassist|msra|anydesk|teamviewer|ateraagent|client32|screenconnect\.clientservice)\.exe$/i
| groupBy([aid], function=[count(RmmTool, distinct=true, as=RmmFamilies), collect([RmmTool, UserSid])], limit=max)
| test(RmmFamilies >= 2)
| sort(RmmFamilies, order=desc)


// ---------------------------------------------------------------------
// IOC sweep | DNS lookups for published lure / payload / C2 domains (Arctic Wolf appendices). Low longevity.
// ATT&CK: T1583.001 | T1105
// ---------------------------------------------------------------------
#event_simpleName=DnsRequest event_platform=Win
| in(field=DomainName, ignoreCase=true, values=["update-software.top", "expertassist.top", "getsystembridge.top", "techrelay.top", "it-assistant.top", "get-help-systems.top", "fix-it.top", "helpdesk-support-us-ny.com", "helpdesk-call.com", "itdeskassist.com", "kilan.com.pl", "saludcentro.gov.co", "ggc.com.ph", "scapini.com.br"])   // UNVERIFIED FIELD: DomainName
| groupBy([aid, DomainName], function=[count(as=Lookups)], limit=max)
```

Queries are untested: tune before use.

## Sources

1. Arctic Wolf Labs (Shubham Dubey): Beyond the Inbox: How Threat Actors Abuse Microsoft Teams External Chat for Initial Access <https://arcticwolf.com/resources/blog/threat-actors-abuse-microsoft-teams-external-chat-for-initial-access/>
2. Techzine Global (Berry Zwets): Attackers are exploiting Teams chat as a fake IT help desk <https://www.techzine.eu/news/security/145269/attackers-are-exploiting-teams-chat-as-a-fake-it-help-desk/>
