---
title: "Hunt Drop 11 | SSHole: Hunting Root Logins That Skipped the Password"
hypothesis: A password-less SSH login on a musl build without PAM was used to get root.
attack: [T1021.004, T1033, T1082, T1190, T1133, T1548, T1136.001, T1098.004]
dataSources: [Linux EDR process events, Network events, File events]
languages: [KQL]
drop: 11
risk: { likelihood: 3, impact: 4 }
status: published
date: 2026-11-09
---

Builds on [Intel Drop 33](/intel/intel-drop-33-openssh-sshole/).

OpenSSH CVE-2026-123158 lets password logins succeed on accounts that have no password, on musl builds without PAM (think Alpine). Exploitation attempts were reported within nine hours of disclosure, including root on a honeypot.

## The hypothesis

If SSHole was used against us, we expect `sshd` to spawn a short, non-interactive session running `id`, `uname` and `hostname`, followed by `doas`, a new user or an `authorized_keys` change.

## What to hunt

Analyst ATT&CK mapping.

- `sshd` → `id` / `uname` / `hostname` burst in one session (T1021.004, T1033, T1082)
- Inbound SSH to Linux from public IPs, plus the published source IP (T1190, T1133)
- `doas`, `adduser`/`useradd` or `authorized_keys` edits after an SSH login (T1548, T1136.001, T1098.004)

## Business risk

Alpine sits under many containers, appliances and cloud images. Root on one means data access, a pivot point and tampered services. The catch: musl hosts are often outside EDR support, so no hits does not mean no compromise.

**Risk score:** likelihood 3 × impact 4 = **12/25, HIGH** (analyst judgement).

## Tune and triage

Allow-list Ansible, monitoring and jump-host accounts. On a hit, check `/var/log/messages` for "Accepted password for" on password-less accounts, then review `doas` use, new users and `authorized_keys`. Patch to OpenSSH 10.6p2.

## Confidence

| Assessment | Confidence |
|---|---|
| Intel confidence | MODERATE |
| Detection fidelity | LOW |

## Microsoft Defender (KQL)

Simplified query from the Hunt Drop graphic. Untested: tune before use. The full KQL and Falcon CQL queries are in the LinkedIn post comments.

```kql
// sshd → id / uname / hostname burst (T1021.004, T1033, T1082)
DeviceProcessEvents
| where InitiatingProcessFileName =~ "sshd"
| where FileName in~ ("id", "uname", "hostname")
| summarize make_set(FileName) by DeviceName, bin(Timestamp, 5m)
```
