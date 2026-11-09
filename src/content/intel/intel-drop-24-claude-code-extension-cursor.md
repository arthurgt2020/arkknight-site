---
title: "Intel Drop 24 | Trojanised Claude Code extension plants SSH backdoors via Cursor"
type: intel-drop
drop: 24
attack: [T1195.002, T1082, T1098.004, T1572, T1053.005, T1543.001]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Tampered builds were live for about 11 hours on 29 Oct, on Windows and macOS."
date: 2026-11-01
---

For about 11 hours on 29 Oct, tampered builds 2.1.312 and 2.1.313 ran on load, added an attacker SSH key ("svc-telemetry"), opened reverse SSH tunnels and persisted via a "SysMon" task or an Apple-named LaunchAgent. The actor is unknown.

Companion hunt: [Hunt Drop 8](/hunting/hunt-drop-08-claude-code-extension/).

## Attack chain

1. Tampered v2.1.312 / 2.1.313 served by the marketplace (T1195.002)
2. Runs on load and profiles the host, Git email and env-var names (T1082)
3. Adds the "svc-telemetry" key to authorized_keys (T1098.004)
4. Reverse SSH tunnel to the attacker host, retrying about every 60 s (T1572)
5. Persists as a "SysMon" task or a fake Apple LaunchAgent (T1053.005, T1543.001)

## Risk

**12/25 HIGH** (likelihood 3 × impact 4), organisations with developers using Cursor.

## Confidence

| Assessment | Confidence |
|---|---|
| Malicious activity | HIGH |
| Actor attribution | NONE (unknown) |
| Delivery path | LOW (unexplained) |

## Business risk

The attack went after engineers: their laptops and their tools sit one step away from money, code and cloud.

## What to do now

- Check authorized_keys for "svc-telemetry" and rotate exposed credentials.
- Allow-list and pin IDE extensions.

## Sources

1. Cursor security notice (29 Oct 2026, upd. 30 Oct): <https://cursor.com/blog/claude-code-extension-security-notice>
2. Help Net Security (30 Oct 2026): <https://www.helpnetsecurity.com/2026/10/30/claude-code-extension-ssh-backdoor/>
3. The Register (30 Oct 2026): <https://www.theregister.com/cyber-crime/2026/10/30/anthropic-that-claude-code-extension-compromise-couldnt-be-us/5306682>
4. Cyber Security News (31 Oct 2026): <https://cybersecuritynews.com/malicious-claude-code-extension-with-cursor/>
