---
title: "Hunt Drop 03 | When your MSP's app becomes the attacker"
hypothesis: "A stolen app credential signs in app-only, then grants itself roles and credentials."
attack: [T1199, T1195, T1078.004, T1528, T1098.001, T1098.003, T1087.004, T1580, T1555.006]
dataSources: ["Service-principal and user sign-ins", "Graph API audit", "OAuth app inventory", "Azure audit"]
languages: [KQL, CQL]
drop: 3
risk: { likelihood: 3, impact: 5 }
status: published
date: 2026-10-23
---

Builds on [Intel Drop 10](/intel/intel-drop-10-storm-0940-artex/).

## The hypothesis
If a trusted multi-tenant app was turned against our tenants, we expect app-only sign-ins from new infrastructure, Graph calls that add credentials or privileged roles to the app, then discovery of accounts, Azure resources and Key Vault secrets.

## What to hunt
- Exposure: affected ConnectWise app IDs and any third-party app holding directory roles (T1199, T1195)
- Service-principal sign-ins from IPs never seen for that app, scripted tooling first (T1078.004, T1528)
- Apps adding secrets or certificates, or assigning roles including Global Administrator (T1098.001, T1098.003)
- Bulk Graph directory reads, Azure resource mapping and Key Vault secret alerts (T1087.004, T1580, T1555.006)

## Business risk
GCC government and critical-infrastructure tenants are often run through MSP and vendor apps. One stolen app credential can mean tenant-wide admin with no interactive user sign-in to catch.
Risk score (analyst judgement): Likelihood 3 × Impact 5 = 15/25, CRITICAL

## Tune & triage
Baseline each app's sign-in IPs and allow-list backup, governance and IaC apps by App ID, never by name. On a hit: disable the app's credentials, preserve Entra and Purview logs, and review consent, role and credential changes since 1 Oct.
Queries are untested in your environment: test and tune them before use.

**Risk: 15/25 CRITICAL** (likelihood 3 × impact 5, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// Microsoft Defender (KQL) | Hunt Drop #03 | UNTESTED: tune before use

// T1078.004/T1528: app-only sign-ins from IPs new for that app
let w=10d;
let Base=EntraIdSpnSignInEvents
| where Timestamp between (ago(30d)..ago(w)) and ErrorCode==0
| distinct ServicePrincipalId, IPAddress;
EntraIdSpnSignInEvents
| where Timestamp > ago(w) and ErrorCode==0 and IsManagedIdentity==false
| join kind=leftanti Base on ServicePrincipalId, IPAddress
| summarize SignIns=count(), IPs=make_set(IPAddress,20), UAs=make_set(UserAgent,10) by Application, ApplicationId, ServicePrincipalId

// T1098.003: apps assigning directory/app roles
GraphAPIAuditEvents
| where Timestamp > ago(14d)
| where RequestMethod in~ ("POST","PATCH","PUT") and ResponseStatusCode startswith "2"
| where RequestUri contains "roleManagement/directory/role" or RequestUri has_any ("directoryRoles","appRoleAssignedTo","appRoleAssignments")
| summarize Calls=count(), IPs=make_set(IpAddress,10), Uris=make_set(RequestUri,10) by ApplicationId, ServicePrincipalId

10 technique-mapped hunts (T1199, T1110.003, T1087.004, T1098.001, T1580, T1555.006...) in the Hunt Drop #03 files.
```

## CrowdStrike Falcon (CQL)

```
// CrowdStrike Falcon (CQL) | Hunt Drop #03 | UNTESTED: tune before use
Needs Entra ID logs in Falcon Next-Gen SIEM. Free-text filters, so they work whatever your parser's field names are.

// T1078.004/T1528: app-only sign-ins with scripted tooling. Time picker: last 14 days
/servicePrincipal/i
/python-requests|python-urllib|curl\/|azure-toolkit/i
| table([@timestamp, #repo, #type, @rawstring], limit=500)

// T1098.003: role assignments (Entra audit activity names)
/Add member to role|Add eligible member to role|Add app role assignment to service principal/i
| table([@timestamp, #repo, #type, @rawstring], limit=500)

// T1199/T1195 exposure: affected ConnectWise app IDs. Time picker: last 30 days
"506e08f9-6e9a-4da4-942b-a099a03644ae" OR "24205314-2b89-4e07-a2a4-579e898a5640" OR "0de14c77-b9b0-4137-9360-34878a929827"
| groupBy([#repo, #type], function=[count(), max(@timestamp, as=last_seen)])
```

Queries are untested: tune before use.

## Sources

1. Microsoft Threat Intelligence (21 Oct 2026): https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
2. Cybersecurity Dive (22 Oct 2026): https://www.cybersecuritydive.com/news/china-nexus-actor-attack-connectwise-cloud-backup/833727/
