---
title: "Intel Drop 07 | BRONZE SANDCASTLE: spying via trusted binaries"
type: intel-drop
drop: 7
actor: BRONZE SANDCASTLE
attack: [T1574.001, T1027, T1102, T1087, T1003.003]
risk: { likelihood: 2, impact: 4 }
tlp: CLEAR
summary: "A new China-based cluster side-loads a rogue DLL through a renamed Sandboxie binary. Victims are in Asia and Africa."
date: 2026-10-21
---

Sophos has documented BRONZE SANDCASTLE, a previously undocumented cluster it assesses as China-based. Victims were observed between August 2025 and August 2026 in the Philippines, Taiwan, Afghanistan and Namibia, and likely South Korea.

Its signature is DLL side-loading through renamed Sandboxie binaries, such as SandboxieWUAU.exe loading a malicious sbiedll.dll. It also abuses Java, Krita, NVDA, LINE and Sysinternals executables. The DLL decrypts a config.ini payload and runs it in memory. Sophos describes the payload as a novel Meterpreter-based backdoor. Once inside, operators enumerate accounts with net commands, create shadow copies with vssadmin, and copy ntds.dit, the domain's credential store.

My GCC read, as an analyst observation: one C2 domain, net.dpworldto[.]com, reads like a play on a major Dubai logistics brand. No GCC victims are reported, and nothing suggests that brand was compromised.

## Intrusion chain

1. Renamed Sandboxie loads rogue sbiedll.dll (T1574.001)
2. Encrypted config.ini run in memory (T1027)
3. Backdoor pulls tasks via web services (T1102)
4. Account discovery with net commands (T1087)
5. vssadmin shadow copy, ntds.dit copied (T1003.003)

## Risk

**8/25 MEDIUM** (likelihood 2 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Intrusion activity | HIGH |
| China-based attribution | MODERATE |

## Business risk

A stolen AD database gives an attacker long-term, quiet access to email, files and systems. Brand-themed infrastructure also creates reputational noise for the brand being imitated.

## What to do now

- Hunt for sbiedll.dll, jli.dll or version.dll loaded by signed apps from user or temp folders.
- Alert when vssadmin creates a shadow copy and ntds.dit is then accessed.
- Block or monitor the published C2 domains.
- Logistics and aviation brands: watch for lookalike domains.

## Sources

1. Sophos CTU (20 Oct 2026): <https://www.sophos.com/en-us/blog/bronze-sandcastle-deploys-modified-meterpreter-shells>
2. The Hacker News (21 Oct 2026): <https://thehackernews.com/2026/10/china-aligned-bronze-sandcastle-abuses.html>
