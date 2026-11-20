---
title: "Hunt Drop 15 | Fake Microsoft 365 outage lures: hunt the click, not the domain"
hypothesis: "The M365 outage lure reached users: look-alike Service Health mail, then clicks through a tracking redirect to a non-Microsoft page."
attack: [T1566.002, T1036, T1204.001, T1078.004, T1114.003]
dataSources: ["Email events", "URL click events", "Endpoint DNS events"]
languages: [KQL, CQL]
drop: 15
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-18
---

Builds on [Intel Drop 41](/intel/intel-drop-41-fake-m365-outage-phishing/).

## The hypothesis
If the Microsoft 365 "outage" lure reached our users, we expect inbound mail with "Outage – <token>" subjects from look-alike "Service Health" senders, followed by clicks that pass a tracking redirect to a non-Microsoft page.

## What to hunt
- Outage / Strengthen / Restore subjects and Service Health display names (T1566.002, T1036)
- Recipients who clicked through the redirect chain (T1204.001)
- Endpoint DNS to the published lure infrastructure (T1204.001)
- Analyst view: sign-ins and inbox rules after a click (T1078.004, T1114.003)

## Business risk
A real outage made the lure believable. Microsoft assesses it as likely credential phishing, with no confirmed compromise. For a GCC SOC, one harvested mailbox can expose sensitive correspondence. Risk score: Likelihood 3 × Impact 4 = 12/25, HIGH (analyst judgement).

## Tune & triage
Allow-list your genuine service-health senders. Pivot on NetworkMessageId, confirm who clicked, then reset passwords and revoke sessions for anyone who entered credentials.

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// HUNT DROP #15 - Fake Microsoft 365 outage lures (builds on Intel Drop #41)
// Untested queries. Schema checked in this run against docs mirrors for EmailEvents, EmailUrlInfo, UrlClickEvents.
// Columns marked UNVERIFIED were not confirmed on a loaded page in this run.

// ===== Hunt 1A: outage-themed lure mail delivered (behavioural) =====
// Hunt Drop #15 | ATT&CK: T1566.002 (Microsoft), T1036 (Microsoft)
// Hypothesis: If the outage lure reached us, inbound mail has Outage/Strengthen/Restore subjects and Service Health display names from non-Microsoft senders.
// Expected noise: Genuine third-party status notifications, internal IT test mail; allow-list known senders.
// NOT TESTED in a live tenant. Test and tune before use. Default window 14 days.
// NOTE: Timestamp on EmailEvents is the Defender portal column name; the Azure Monitor mirror lists TimeGenerated (UNVERIFIED on an official page this run).
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where Subject matches regex @"(?i)^\s*(\[External\]|\*EXTERNAL\*)?\s*(Outage|Strengthen|Restore)\s*[-–—]\s*\S+"
    or SenderDisplayName matches regex @"(?i)^[A-Z0-9]{2,5}\s+(Outage Notification|Service Health)$"
| where SenderFromDomain !endswith "microsoft.com"
| summarize Msgs=count(), Recipients=dcount(RecipientEmailAddress), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Actions=make_set(DeliveryAction, 5), Locations=make_set(DeliveryLocation, 5)
    by SenderFromDomain, SenderMailFromDomain, SenderDisplayName
| order by Msgs desc

// ===== Hunt 1B: who clicked a lure mail (behavioural, survives domain rotation) =====
// Hunt Drop #15 | ATT&CK: T1204.001 (Microsoft)
// Hypothesis: Users who received a lure message and clicked a link in it are the priority for credential reset and sign-in review.
// Expected noise: Legitimate service-health mails clicked by admins; review Url/UrlChain.
// NOT TESTED in a live tenant. Test and tune before use. Default window 14 days.
let lure = EmailEvents
| where Timestamp > ago(14d) and EmailDirection == "Inbound"
| where Subject matches regex @"(?i)^\s*(\[External\]|\*EXTERNAL\*)?\s*(Outage|Strengthen|Restore)\s*[-–—]\s*\S+"
    or SenderDisplayName matches regex @"(?i)^[A-Z0-9]{2,5}\s+(Outage Notification|Service Health)$"
| where SenderFromDomain !endswith "microsoft.com"
| project NetworkMessageId, RecipientEmailAddress, SenderFromDomain, SenderDisplayName, Subject;
lure
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(14d)
    | project NetworkMessageId, ClickTime=Timestamp, ActionType, IsClickedThrough, Url, UrlChain, AccountUpn
  ) on NetworkMessageId
| project ClickTime, AccountUpn, RecipientEmailAddress, SenderFromDomain, ActionType, IsClickedThrough, Url, UrlChain
| order by ClickTime desc

// ===== Hunt 2: IOC sweep - published lure infrastructure (Microsoft, 16 Nov 2026) =====
// Hunt Drop #15 | ATT&CK: T1566.002, T1204.001 (Microsoft)
// Hypothesis: Mail or clicks touching the published sender, tracking and destination domains.
// Expected noise: sendgrid.net is shared email infrastructure: do NOT block or alert on the parent domain; the per-tenant ct.sendgrid.net hosts are listed by Microsoft but are shared.
// NOT TESTED in a live tenant. Test and tune before use. Default window 14 days.
let senderDomains = dynamic(["moments-notice.com","planetmaison.com","newbooker.com"]);
let lureUrlParts = dynamic(["reallifeaccounting.com","outagerestored.sbs","outagefixed.sbs","themelist0.html","/topics_pxyk/"]);
union
( EmailEvents
  | where Timestamp > ago(14d)
  | where SenderFromDomain in~ (senderDomains) or SenderMailFromDomain has_any (senderDomains)
  | project Timestamp, Source="EmailEvents", Who=RecipientEmailAddress, Detail=strcat(SenderFromDomain, " | ", Subject), NetworkMessageId ),
( UrlClickEvents
  | where Timestamp > ago(14d)
  | where Url has_any (lureUrlParts) or UrlChain has_any (lureUrlParts)
  | project Timestamp, Source="UrlClickEvents", Who=AccountUpn, Detail=Url, NetworkMessageId )
| order by Timestamp desc

// ===== Hunt 3: post-click account activity for clicked users (ANALYST mapping; Microsoft lists these as investigation targets, not observed behaviour) =====
// Hunt Drop #15 | ATT&CK: T1078.004 (analyst), T1114.003 (analyst)
// Hypothesis: If a clicker entered credentials, we may see new-location sign-ins and inbox/forwarding rule changes.
// Expected noise: Travel, VPN changes, legitimate rule creation; scope to clicked users only.
// NOT TESTED in a live tenant. Test and tune before use. Default window 14 days.
// UNVERIFIED SCHEMA: EntraIdSignInEvents (AccountUpn, ErrorCode, IPAddress, Country, Application) and
// CloudAppEvents (ActionType, RawEventData) were NOT confirmed on a loaded schema page in this run (learn.microsoft.com not reachable). Verify before use.
let clickedUsers = toscalar(
    EmailEvents
    | where Timestamp > ago(14d) and EmailDirection == "Inbound"
    | where Subject matches regex @"(?i)^\s*(\[External\]|\*EXTERNAL\*)?\s*(Outage|Strengthen|Restore)\s*[-–—]\s*\S+"
    | project NetworkMessageId
    | join kind=inner (UrlClickEvents | where Timestamp > ago(14d)) on NetworkMessageId
    | summarize make_set(AccountUpn));
EntraIdSignInEvents   // UNVERIFIED
| where Timestamp > ago(7d)
| where AccountUpn in~ (clickedUsers)
| where ErrorCode == 0
| summarize SignIns=count(), IPs=make_set(IPAddress, 10), Countries=make_set(Country, 10) by AccountUpn, Application
| order by SignIns desc
;
CloudAppEvents   // UNVERIFIED
| where Timestamp > ago(7d)
| where ActionType in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where tostring(RawEventData) has_any (clickedUsers)
| project Timestamp, ActionType, AccountObjectId, IPAddress, RawEventData
```

## CrowdStrike Falcon (CQL)

```
// HUNT DROP #15 - Fake Microsoft 365 outage lures (builds on Intel Drop #41)
// Untested queries. Falcon sees the endpoint side only (DNS / network), not mail. Set the time picker to the last 14 days.
// CQL double-check: cqlsearch.com NOT reachable in this run (allowlist); fallback = CrowdStrike community wiki mirror + Cool Query Friday mirror. See notes.
// Lines marked UNVERIFIED were not confirmed against any loaded page.

// ===== Hunt 1: browser / mail-client DNS to outage lookalikes and published lure hosts =====
// Hunt Drop #15 | ATT&CK: T1204.001 (Microsoft)
// Hypothesis: a user who clicked the lure resolves the redirect/destination domains from a browser or Outlook.
// Expected noise: low for the IOC domains; the outage[...].(sbs|top|...) regex is an ANALYST heuristic and may match legitimate status sites.
// Time picker: 14 days
#event_simpleName=DnsRequest event_platform=Win
| ContextBaseFileName=/^(chrome|msedge|firefox|brave|olk|outlook)\.exe$/i
| DomainName=/(outage[a-z0-9-]*\.(sbs|top|xyz|icu|click)|reallifeaccounting\.com|moments-notice\.com|planetmaison\.com|newbooker\.com)$/i
| groupBy([aid, ComputerName, ContextBaseFileName, DomainName], function=[count(aid, as=Lookups), max(@timestamp, as=LastSeen)])   // max(@timestamp, as=...) UNVERIFIED
| sort(Lookups, order=desc)

// ===== Hunt 2: egress to the published tracking-pixel host (IOC sweep) =====
// Hunt Drop #15 | ATT&CK: T1204.001 (Microsoft)
// Hypothesis: rendering/clicking the lure causes a connection to the host Microsoft lists for tracking resources (162.120.17.69:8080).
// Expected noise: very low; single published IP, may rotate.
// Time picker: 14 days
#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=162.120.17.69 RemotePort=8080   // NetworkConnectIP4 and RemotePort UNVERIFIED this run
| groupBy([aid, ComputerName], function=count(aid, as=Conns))

// Not written: Entra ID / Microsoft 365 sign-in and inbox-rule hunts in Falcon Next-Gen SIEM. The connector field names could not be verified in this run.
```

Queries are untested: tune before use.

## Sources

1. Microsoft Threat Intelligence (16 Nov 2026): <https://www.microsoft.com/en-us/security/blog/2026/11/16/high-volume-phishing-campaign-uses-microsoft-365-outage-lures-target-multiple-industry-sectors-2/>
2. SecurityWeek (16 Nov 2026): <https://www.securityweek.com/microsoft-rules-out-cyberattack-in-outage-warns-of-phishing-campaign/>
3. Microsoft (docs.azure.cn) (undated): <https://docs.azure.cn/en-us/azure-monitor/reference/tables/emailevents>
4. Microsoft (docs.azure.cn) (undated): <https://docs.azure.cn/en-us/azure-monitor/reference/tables/EmailUrlInfo>
5. Microsoft (docs.azure.cn) (undated): <https://docs.azure.cn/en-us/azure-monitor/reference/tables/urlclickevents>
6. CrowdStrike engineer post, via mirror (27 Sep 2024): <https://nyc1.lr.ggtyler.dev/r/crowdstrike/comments/1fqokic/20240927_cool_query_friday_hunting_newly_seen_dns>
