---
title: "Hunt Drop 09 | LLMJacking: find the hijacked AI before the bill does"
hypothesis: A stolen cloud identity is reselling our AI quota.
attack: [T1078.004, T1580, T1562.008, T1496.004, T1136.003, T1098.001, T1098.003]
dataSources: [AWS CloudTrail (Defender / NG-SIEM), EDR]
languages: [KQL]
drop: 9
risk: { likelihood: 3, impact: 4 }
status: draft
date: 2026-11-04
---

Builds on [Intel Drop 26](/intel/intel-drop-26-llmjacking/).

## Hypothesis

A stolen cloud identity is reselling our AI quota.

## Telemetry

AWS CloudTrail (through Defender or NG-SIEM) and EDR.

## Hunt logic

Model access or logging changes, bursts of model invocations, short-lived IAM users, and an admin policy being attached.

## Triage

Revoke the keys, check spend, and hunt for backdoors.

## KQL (simplified)

```kusto
CloudAppEvents
| where Application == "Amazon Web Services"
| where ActionType in (Enable, LogCfg, Scoping, Invoke)
| summarize Events=count() by AccountId, ActionType
```

**Untested: tune before use.** The queries were shared in the comments of the LinkedIn post.

## Risk and confidence

**12/25 HIGH** (likelihood 3 x impact 4). Intel confidence: high. Detection fidelity: medium.
