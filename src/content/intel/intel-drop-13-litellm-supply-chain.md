---
title: "Intel Drop 13 | LiteLLM 1.107.0: an AI gateway turned credential thief"
type: intel-drop
drop: 13
attack: [T1195.001, T1546.018, T1552.001, T1552.005, T1102.001]
risk: { likelihood: 2, impact: 5 }
tlp: CLEAR
summary: "A poisoned LiteLLM release ran on every Python start, with no import needed."
date: 2026-10-25
---

AI gateways now sit next to some of the most valuable keys in the enterprise, and attackers have noticed.

On 21 Oct, an attacker used maintainer GitHub tokens, obtained through a master key that had been leaked publicly in May, to push a poisoned LiteLLM 1.107.0 to PyPI, Docker Hub and GHCR. It was live for about two hours. Analysis published on 23 Oct shows the payload hid in Python startup files (cook.pth, sitecustomize.py) outside the package folder, so it ran whenever Python started, with no import needed. It collected cloud, AI-provider, CI/CD, SSH and browser secrets, plus rows of LiteLLM's own stored credentials, and set up a loader that checks a GitHub-hosted pointer for new code. No actor has been named.

Companion hunt: [Hunt Drop 5](/hunting/hunt-drop-05-litellm-startup-hook/).

## Attack chain

1. Leaked key leads to maintainer GitHub tokens (10-12 Oct)
2. Hijacked release: litellm 1.107.0 (T1195.001)
3. Startup hook: cook.pth / sitecustomize.py (T1546.018)
4. Harvest cloud, AI and CI/CD secrets (T1552.001, T1552.005)
5. Encrypted POST and GitHub dead-drop loader (T1102.001)

## Risk

**10/25 HIGH** (likelihood 2 × impact 5).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Actor attribution | NONE (unnamed) |

## Business risk

If 1.107.0 ran anywhere in your estate, assume the AI provider keys, cloud credentials and pipeline secrets on that host are exposed. Uninstalling the package does not remove the hooks.

## What to do now

- Search lock files, mirrors and container images (by digest) for litellm 1.107.0.
- Rebuild affected hosts from clean artifacts; don't just uninstall.
- Rotate every reachable secret from a clean machine.
- Restrict outbound traffic from AI gateways and build runners.

## Sources

1. Microsoft Security (23 Oct 2026): <https://www.microsoft.com/en-us/security/blog/2026/10/23/inside-the-litellm-1-107-0-supply-chain-compromise-credential-theft-through-python-startup-hooks/>
2. LiteLLM (23 Oct 2026): <https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain>
3. Socket (23 Oct 2026): <https://socket.dev/blog/litellm-attack-timeline>
4. The Hacker News (24 Oct 2026): <https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html>
5. BleepingComputer (22 Oct 2026): <https://www.bleepingcomputer.com/news/security/litellm-release-pipeline-hacked-to-distribute-info-stealer-malware/>
