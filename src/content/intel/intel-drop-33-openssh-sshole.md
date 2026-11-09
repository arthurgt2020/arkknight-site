---
title: "Intel Drop 33 | SSHole: an OpenSSH login bypass exploited within hours"
type: intel-drop
drop: 33
motivation: unknown
sectors: []
regions: [GCC]
attack: [T1021.004, T1078, T1082, T1033]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: An OpenSSH login bypass (CVE-2026-123158, CVSS 8.1) affecting musl libc builds with PAM disabled, such as Alpine, was exploited on a honeypot about eight hours after disclosure.
date: 2026-11-08
---

**CVE-2026-123158** · CVSS 8.1 · affects OpenSSH on musl libc with PAM disabled (for example Alpine).

## Attack chain

1. **Password authentication exposed** (T1021.004). An account that has a `*` hash alongside one real hash.
2. **Oversized password sent.** Any password of 257 to 1,024 bytes is accepted.
3. **Root login on a honeypot** (T1078). The first attempt arrived about 8 hours after disclosure.
4. **Host reconnaissance** (T1082, T1033). `id`, `uname` and `hostname`.

## Risk

**12/25 HIGH** (likelihood 3 × impact 4), with a wider GCC estate in scope.

## Confidence

| Assessment | Confidence |
|---|---|
| Flaw and fix details | High |
| Exploitation attempts | Moderate |
| Threat actor | Not identified |

## Do now

- Patch to OpenSSH 10.6p2 and restart `sshd`.
- Or set `PasswordAuthentication no`.
- Hunt for `Accepted password for` in SSH logs.
