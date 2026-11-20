---
title: "Intel Drop 47 | Operation ShadowCloud: GitDoor and GraphDoor backdoors"
type: intel-drop
drop: 47
motivation: unknown
sectors: [Government]
regions: [Asia, Africa]
attack: [T1219, T1574.002, T1102]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Kaspersky tracks GitDoor and GraphDoor backdoors against government networks in Asia and Africa; they start from a MeshCentral agent, side-load DLLs and hide C2 in GitHub, Ably and Microsoft Graph traffic."
date: 2026-11-19
---

Kaspersky tracks GitDoor and GraphDoor backdoors against government networks in Asia and Africa. They start from a MeshCentral agent, side-load DLLs and hide C2 in GitHub, Ably and Microsoft Graph traffic. No firm attribution.

Posted together with [Intel Drop 46](/intel/intel-drop-46-auditteam-opsagent/), [Intel Drop 48](/intel/intel-drop-48-cold-relic-workspace-mfa/).

## Attack chain

1. **Start**. MeshCentral agent on the host (T1219).
2. **Load**. Legitimate EXE side-loads a rogue DLL (T1574.002).
3. **C2**. GitHub, Ably and Microsoft Graph traffic carries commands (T1102).

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (Kaspersky) | MODERATE |
| Attribution | NONE (no firm attribution) |

## Business risk

Attackers are hiding inside things you already trust: MSI processes, cloud APIs and your own identity provider. Detection gaps mean longer dwell time and data theft before anyone sees damage.

## What to do now

- Baseline GitHub, Ably and Graph/SharePoint traffic from servers and non-browser processes.
- Inventory MeshCentral and other RMM agents and remove any you did not deploy.

## Sources

1. Securelist, GitDoor (17 Nov 2026): <https://securelist.com/operation-shadowcloud-gitdoor/122004/>
2. Securelist, GraphDoor (17 Nov 2026): <https://securelist.com/operation-shadowcloud-graphdoor/122005/>
3. The Hacker News (17 Nov 2026): <https://thehackernews.com/2026/11/new-gitdoor-and-graphdoor-backdoors.html>
