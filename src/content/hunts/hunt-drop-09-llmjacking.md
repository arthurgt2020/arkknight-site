---
title: "Hunt Drop 09 | LLMJacking: find the hijacked AI before the bill does"
hypothesis: "A stolen cloud identity is reselling our AI quota."
attack: [T1078.004, T1580, T1562.008, T1496.004, T1136.003, T1098.001, T1098.003]
dataSources: ["AWS CloudTrail", "EDR"]
languages: [KQL, CQL]
drop: 9
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-04
---

Builds on [Intel Drop 26](/intel/intel-drop-26-llmjacking/).

## The hypothesis
If a stolen cloud identity is reselling our AI quota, CloudTrail will show Bedrock model access being enabled or invocation logging changed by an unfamiliar principal, followed by inference bursts and short-lived IAM users.

## What to hunt
- Bedrock model-access requests, model scoping and invocation-logging changes by new principals (T1078.004, T1580, T1562.008)
- Inference bursts and throttling spikes from a single identity (T1496.004)
- IAM users created and deleted within 24 hours, and admin policies attached to roles (T1136.003, T1098.001, T1098.003)
- Endpoints resolving known LLM-mixer domains or scripting max_tokens=1 key checks (T1496.004)

## Business risk
For GCC government and critical-infrastructure tenants piloting cloud AI, one leaked key can turn into a six-figure bill in a single day. Investigators also found admin backdoors and secret-manager theft in the same intrusions, so this is a control and data problem, not only a billing one.
Risk score (analyst judgement): Likelihood 3 × Impact 4 = 12/25, HIGH

## Tune & triage
Baseline your IaC and ML-platform principals first. Treat any model-access enablement or logging change outside change control as a priority. Revoke the keys first, then work out the spend.

**Risk: 12/25 HIGH** (likelihood 3 × impact 4, analyst judgement). Intel confidence: HIGH. Detection fidelity: MEDIUM.

## Microsoft Defender (KQL)

```kusto
// =====================================================================================
// HUNT DROP #09 | LLMJacking: find the hijacked AI before the bill does
// Builds on Intel Drop #26 (Mandiant / GTIG "The Rise of LLMJacking", 2 Nov 2026)
// Platform: Microsoft Defender XDR Advanced Hunting (KQL)
// STATUS: UNTESTED in a live tenant. Test and tune in a lab or tenant before relying on results,
//         and before promoting anything to a custom detection rule.
// Default window: 14 days (Timestamp > ago(14d)).
// Lines marked [VERIFY] use values that could not be confirmed against public docs in this run.
// =====================================================================================


// -------------------------------------------------------------------------------------
// H1 | Bedrock scoping, model-access enablement, invocation-logging tampering, inference bursts
// ATT&CK: T1078.004 Valid Accounts: Cloud Accounts | T1580 Cloud Infrastructure Discovery (analyst mapping)
//         T1562.008 Disable or Modify Cloud Logs | T1496.004 Resource Hijacking: Cloud Service Hijacking
// Hypothesis: If a stolen AWS identity is being used for LLMJacking, CloudTrail (via Defender for
//   Cloud Apps AWS connector) shows Bedrock model scoping / model-access enablement / invocation-logging
//   changes by one principal, often followed by InvokeModel/Converse bursts and throttling errors.
// Telemetry: CloudAppEvents, Application == "Amazon Web Services" (Defender for Cloud Apps + AWS connector).
//   Bedrock runtime calls (InvokeModel, Converse...) are CloudTrail management events per AWS docs.
// Expected noise: ML/platform teams, IaC pipelines (Terraform/CDK) setting logging config, model
//   evaluation jobs. Allow-list known automation principals and source IPs after baselining.
// -------------------------------------------------------------------------------------
let lookback = 14d;
let Scoping = dynamic(["ListFoundationModels","ListInferenceProfiles","GetFoundationModelAvailability"]);
let Enable  = dynamic(["PutUseCaseForModelAccess","CreateFoundationModelAgreement"]);
let Evasion = dynamic(["GetModelInvocationLoggingConfiguration","PutModelInvocationLoggingConfiguration","DeleteModelInvocationLoggingConfiguration"]);
let Invoke  = dynamic(["InvokeModel","InvokeModelWithResponseStream","Converse","ConverseStream"]);
let UAsOfInterest = dynamic(["claude-cli","aws-sdk-rust","aws-sdk-go-v2"]);   // UAs Mandiant says to analyse; not malicious by themselves
let KnownAutomation = dynamic(["<iac-principal>"]);                                            // TUNE: add IaC / ML-platform principals
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Amazon Web Services"
| where ActionType in (Scoping) or ActionType in (Enable) or ActionType in (Evasion) or ActionType in (Invoke)
| where AccountDisplayName !in (KnownAutomation)
| extend Stage = case(ActionType in (Enable), "Enable",
                      ActionType in (Evasion), "LogTamper",
                      ActionType in (Scoping), "Scoping",
                      "Invoke")
| extend ErrorCode = tostring(RawEventData.errorCode)            // [VERIFY] CloudTrail errorCode inside RawEventData
| extend UAFlag = iff(UserAgent has_any (UAsOfInterest), 1, 0)
| summarize Events = count(),
            Invokes = countif(Stage == "Invoke"),
            Errors = countif(ErrorCode in ("ThrottlingException","ValidationException","ResourceNotFoundException")),
            Stages = make_set(Stage),
            Actions = make_set(ActionType, 20),
            IPs = make_set(IPAddress, 10),
            UAs = make_set(UserAgent, 5),
            Countries = make_set(CountryCode, 5),
            UAHits = max(UAFlag),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by AccountId, AccountDisplayName
| extend Score = iff(set_has_element(Stages, "Enable"), 3, 0)
               + iff(set_has_element(Stages, "LogTamper"), 3, 0)
               + iff(set_has_element(Stages, "Scoping"), 1, 0)
               + iff(Invokes > 500, 2, 0)                      // TUNE threshold to your baseline
               + iff(Errors > 50, 1, 0)
               + UAHits
| where Score >= 3
| sort by Score desc, Invokes desc


// -------------------------------------------------------------------------------------
// H1b (optional) | Azure OpenAI / Cognitive Services deployment writes and diagnostic-setting tampering
// ATT&CK: T1496.004 | T1562.008
// Telemetry: CloudAppEvents with the Azure app connector.
// [VERIFY] Application name "Microsoft Azure" and whether the operation names below appear in
//          ActionType or only in RawEventData. Check your tenant with:
//          CloudAppEvents | where Application has "Azure" | summarize count() by Application, ActionType
// -------------------------------------------------------------------------------------
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "Azure"                                            // [VERIFY]
| extend Raw = tostring(RawEventData)
| where Raw has_any ("Microsoft.CognitiveServices/accounts/deployments/write",
                     "Microsoft.Insights/diagnosticSettings/write",
                     "Microsoft.Insights/diagnosticSettings/delete")
| extend Op = case(Raw has "deployments/write", "AI deployment write",
                   Raw has "diagnosticSettings/delete", "Diag setting delete",
                   "Diag setting write")
| summarize Events = count(), Ops = make_set(Op), IPs = make_set(IPAddress, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by AccountId, AccountDisplayName
| sort by Events desc


// -------------------------------------------------------------------------------------
// H2a | Burn-and-rotate: IAM users created and deleted within 24 hours
// ATT&CK: T1136.003 Create Account: Cloud Account | T1098.001 Additional Cloud Credentials
// Hypothesis: An LLMJacking actor rotating short-lived identities to dodge rate limits leaves
//   CreateUser -> (CreateAccessKey) -> DeleteUser for the same user name inside a day.
// Telemetry: CloudAppEvents, Amazon Web Services.
// Expected noise: CI/CD test fixtures, IAM automation, offboarding scripts. Allow-list by principal.
// -------------------------------------------------------------------------------------
let lookback2 = 14d;
let iam = CloudAppEvents
    | where Timestamp > ago(lookback2)
    | where Application == "Amazon Web Services"
    | where ActionType in ("CreateUser","DeleteUser","CreateAccessKey","DeleteAccessKey")
    | extend TargetUser = tostring(RawEventData.requestParameters.userName);   // [VERIFY] CloudTrail requestParameters path
let created = iam | where ActionType == "CreateUser"
    | project CreatedAt = Timestamp, TargetUser, Creator = AccountDisplayName, CreatorIP = IPAddress;
let deleted = iam | where ActionType == "DeleteUser"
    | project DeletedAt = Timestamp, TargetUser, Deleter = AccountDisplayName;
let keys = iam | where ActionType == "CreateAccessKey"
    | summarize KeysCreated = count() by TargetUser;
created
| join kind=inner deleted on TargetUser
| where DeletedAt between (CreatedAt .. (CreatedAt + 24h))
| join kind=leftouter keys on TargetUser
| extend LifetimeMin = datetime_diff('minute', DeletedAt, CreatedAt)
| summarize ShortLivedUsers = dcount(TargetUser), Users = make_set(TargetUser, 25),
            MinLifetimeMin = min(LifetimeMin), KeysCreated = sum(KeysCreated),
            FirstSeen = min(CreatedAt), LastSeen = max(DeletedAt)
            by Creator, CreatorIP
| where ShortLivedUsers >= 2                                                // TUNE
| sort by ShortLivedUsers desc


// -------------------------------------------------------------------------------------
// H2b | Administrative policies attached to users or service roles
// ATT&CK: T1098.003 Additional Cloud Roles
// Hypothesis: Mandiant saw actors attach administrative policies to service roles and create IAM
//   accounts with full admin rights. Attachment of AdministratorAccess outside change control is suspect.
// Expected noise: break-glass setup, landing-zone automation. Correlate with change tickets.
// -------------------------------------------------------------------------------------
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Amazon Web Services"
| where ActionType in ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy")
| extend PolicyArn = tostring(RawEventData.requestParameters.policyArn),     // [VERIFY]
         Target = coalesce(tostring(RawEventData.requestParameters.roleName),
                           tostring(RawEventData.requestParameters.userName)) // [VERIFY]
| where PolicyArn endswith "AdministratorAccess" or ActionType in ("PutUserPolicy","PutRolePolicy")
| project Timestamp, ActionType, AccountDisplayName, AccountId, IPAddress, CountryCode, UserAgent, Target, PolicyArn
| sort by Timestamp desc


// -------------------------------------------------------------------------------------
// H3a | IOC sweep: endpoints contacting LLM-mixer domains named by Mandiant/GTIG
// ATT&CK: T1496.004 (analyst mapping: buying or relaying hijacked LLM access)
// Hypothesis: A user or compromised host on our estate is consuming or relaying resold LLM quota.
// Telemetry: DeviceNetworkEvents (Defender for Endpoint).
// Expected noise: Very low. Any hit needs a conversation with the user and a host check.
// Real (non-defanged) strings below so the query works. Domains: jet-night[.]com, newapi[.]pro
// -------------------------------------------------------------------------------------
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("jet-night.com","newapi.pro")
| summarize Connections = count(), Urls = make_set(RemoteUrl, 10), RemoteIPs = make_set(RemoteIP, 10),
            Procs = make_set(InitiatingProcessFileName, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, InitiatingProcessAccountName
| sort by Connections desc


// -------------------------------------------------------------------------------------
// H3b | Scripted LLM API key validation sweeps (max_tokens=1) from our endpoints
// ATT&CK: T1078.004 (analyst mapping: validating harvested cloud/LLM keys)
// Hypothesis: Mandiant saw actors validate harvested keys with minimal single-token requests
//   (max_tokens=1). A host repeatedly running curl/python with max_tokens=1 against LLM APIs is
//   either a developer health-check or someone testing keys they should not have.
// Telemetry: DeviceProcessEvents. Only catches sweeps where the payload is on the command line
//   (curl -d / inline python -c). Script files and SDK calls will NOT show here.
// Expected noise: Developer health checks, monitoring probes. Allow-list by device group / account.
// -------------------------------------------------------------------------------------
let LlmApiHosts = dynamic(["api.openai.com","api.anthropic.com","bedrock-runtime","generativelanguage.googleapis.com","aiplatform.googleapis.com","openai.azure.com"]);  // example list, extend
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "max_tokens"
| where ProcessCommandLine matches regex @'(?i)max_tokens["'']?\s*[:=]\s*1\b'
| extend LlmHost = iff(ProcessCommandLine has_any (LlmApiHosts), "yes", "no")
| summarize Executions = count(), DistinctCmds = dcount(ProcessCommandLine),
            Samples = make_set(ProcessCommandLine, 5), Parents = make_set(InitiatingProcessFileName, 5),
            LlmHostSeen = max(LlmHost), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceName, AccountName, FileName
| where Executions >= 5 or DistinctCmds >= 3                                // TUNE
| sort by DistinctCmds desc
```

## CrowdStrike Falcon (CQL)

```
// =====================================================================================
// HUNT DROP #09 | LLMJacking: find the hijacked AI before the bill does
// Builds on Intel Drop #26 (Mandiant / GTIG "The Rise of LLMJacking", 2 Nov 2026)
// Platform: CrowdStrike Falcon Next-Gen SIEM / Advanced Event Search (CQL)
// STATUS: UNTESTED in a live tenant. Test and tune before relying on results, and before
//         promoting anything to a correlation rule or custom IOA.
// TIME WINDOW: set the time picker to Last 14 days for every query below.
// Lines marked [UNVERIFIED] use field paths that could not be confirmed against public docs in this run.
// Cloud queries (H1, H2) need AWS CloudTrail ingested into NG-SIEM with the aws-cloudtrail parser
//   (#Vendor="aws", #event.module="cloudtrail"; fields event.action, event.provider, user.name,
//   source.address, user_agent.original, cloud.region, error.code per library.humio.com parser page).
// Endpoint queries (H3) use native Falcon sensor events.
// =====================================================================================


// -------------------------------------------------------------------------------------
// H1 | Bedrock scoping, model-access enablement, invocation-logging tampering, inference bursts
// ATT&CK: T1078.004 | T1580 (analyst mapping) | T1562.008 | T1496.004
// Hypothesis: A stolen AWS identity used for LLMJacking shows Bedrock scoping / enablement /
//   logging changes, then InvokeModel/Converse bursts and throttling errors.
// Expected noise: ML/platform teams, IaC pipelines. Exclude known automation principals.
// -------------------------------------------------------------------------------------
#Vendor="aws" #event.module="cloudtrail"
| event.provider="bedrock.amazonaws.com"
| in(field="event.action", values=["ListFoundationModels","ListInferenceProfiles","GetFoundationModelAvailability","PutUseCaseForModelAccess","CreateFoundationModelAgreement","GetModelInvocationLoggingConfiguration","PutModelInvocationLoggingConfiguration","DeleteModelInvocationLoggingConfiguration","InvokeModel","InvokeModelWithResponseStream","Converse","ConverseStream"])
// TUNE: exclude IaC / ML-platform principals
| !in(field="user.name", values=["<iac-principal>"])
| case {
    in(field="event.action", values=["PutUseCaseForModelAccess","CreateFoundationModelAgreement"]) | Stage := "Enable" | w := 3 ;
    in(field="event.action", values=["GetModelInvocationLoggingConfiguration","PutModelInvocationLoggingConfiguration","DeleteModelInvocationLoggingConfiguration"]) | Stage := "LogTamper" | w := 3 ;
    in(field="event.action", values=["ListFoundationModels","ListInferenceProfiles","GetFoundationModelAvailability"]) | Stage := "Scoping" | w := 1 ;
    * | Stage := "Invoke" | w := 0 ;
  }
| case {
    in(field="error.code", values=["ThrottlingException","ValidationException","ResourceNotFoundException"]) | err := 1 ;
    * | err := 0 ;
  }
| groupBy([user.name, source.address], function=[count(as=Events), sum(w, as=StageWeight), sum(err, as=Errors), collect([Stage, event.action, user_agent.original, cloud.region], limit=20), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| Score := StageWeight + if(Events > 500, then=2, else=0) + if(Errors > 50, then=1, else=0)
| Score >= 3
| sort(Score, order=desc, limit=200)
// Note: StageWeight sums every matching event, so repeated scoping calls also raise the score. Tune.


// -------------------------------------------------------------------------------------
// H2a | Burn-and-rotate: IAM users created and deleted within 24 hours
// ATT&CK: T1136.003 | T1098.001
// Expected noise: CI/CD fixtures, IAM automation, offboarding scripts.
// -------------------------------------------------------------------------------------
#Vendor="aws" #event.module="cloudtrail"
| event.provider="iam.amazonaws.com"
| in(field="event.action", values=["CreateUser","DeleteUser","CreateAccessKey"])
| rename(field="Vendor.requestParameters.userName", as=TargetUser)     // [UNVERIFIED] field path not listed on parser page
| case {
    event.action="CreateUser" | c := 1 | d := 0 | k := 0 ;
    event.action="DeleteUser" | c := 0 | d := 1 | k := 0 ;
    * | c := 0 | d := 0 | k := 1 ;
  }
| groupBy([TargetUser], function=[sum(c, as=Creates), sum(d, as=Deletes), sum(k, as=KeysCreated), collect([user.name, source.address], limit=10), min(@timestamp, as=First), max(@timestamp, as=Last)])
| Creates >= 1
| Deletes >= 1
| LifetimeMin := (Last - First) / 60000
| LifetimeMin < 1440
| sort(LifetimeMin, order=asc, limit=200)


// -------------------------------------------------------------------------------------
// H2b | Administrative policies attached to users or service roles
// ATT&CK: T1098.003
// Expected noise: break-glass setup, landing-zone automation. Correlate with change tickets.
// -------------------------------------------------------------------------------------
#Vendor="aws" #event.module="cloudtrail"
| event.provider="iam.amazonaws.com"
| in(field="event.action", values=["AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy"])
| case {
    Vendor.requestParameters.policyArn=/AdministratorAccess$/ ;          // [UNVERIFIED] field path
    in(field="event.action", values=["PutUserPolicy","PutRolePolicy"]) ;
  }
| table([@timestamp, event.action, user.name, source.address, user_agent.original, cloud.region, Vendor.requestParameters.roleName, Vendor.requestParameters.userName, Vendor.requestParameters.policyArn])


// -------------------------------------------------------------------------------------
// H3a | IOC sweep: endpoints resolving LLM-mixer domains (jet-night[.]com, newapi[.]pro)
// ATT&CK: T1496.004 (analyst mapping)
// Expected noise: Very low.
// Real (non-defanged) strings below so the query works.
// -------------------------------------------------------------------------------------
#event_simpleName=DnsRequest
| DomainName=/(^|\.)(jet-night\.com|newapi\.pro)$/i
| groupBy([aid, ContextBaseFileName, DomainName], function=[count(as=Lookups), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| sort(Lookups, order=desc, limit=200)
// Add hostnames with your aid_master lookup if needed.


// -------------------------------------------------------------------------------------
// H3b | Scripted LLM API key validation sweeps (max_tokens=1) from our endpoints
// ATT&CK: T1078.004 (analyst mapping)
// Only catches payloads on the command line (curl -d, python -c). Script files / SDK calls will not show.
// Expected noise: developer health checks, monitoring probes.
// -------------------------------------------------------------------------------------
#event_simpleName=ProcessRollup2
| CommandLine=/max_tokens["']?\s*[:=]\s*1\b/i
| case {
    CommandLine=/(api\.openai\.com|api\.anthropic\.com|bedrock-runtime|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|openai\.azure\.com)/i | LlmHost := "yes" ;
    * | LlmHost := "no" ;
  }
| groupBy([aid, ComputerName, UserName, ImageFileName], function=[count(as=Executions), collect([CommandLine, ParentBaseFileName, LlmHost], limit=5)])
| Executions >= 5
| sort(Executions, order=desc, limit=200)
```

Queries are untested: tune before use.

## Sources

1. The Rise of LLMJacking: How Threat Actors Monetize Compromised Cloud and Model Resources <https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models/>
2. Monitor Amazon Bedrock API calls using CloudTrail <https://docs.aws.eu/bedrock/latest/userguide/logging-using-cloudtrail.html>
3. Resource Hijacking: Cloud Service Hijacking (T1496.004) <https://attack.mitre.org/techniques/T1496/004/>
4. CVE-2026-40217 <https://nvd.nist.gov/vuln/detail/CVE-2026-40217>
5. LiteLLM vulnerability chain enables full AI gateway takeover <https://dev.to/etairos/litellm-vulnerability-chain-enables-full-ai-gateway-takeover-from-default-account-kh2>
6. cs-shadowbq/CQL-Queries <https://gh.r-mj.com/cs-shadowbq/CQL-Queries>
7. Cool Query Friday: hunting newly seen DNS <https://nyc1.lr.ggtyler.dev/r/crowdstrike/comments/1fqokic/20240927_cool_query_friday_hunting_newly_seen_dns>
