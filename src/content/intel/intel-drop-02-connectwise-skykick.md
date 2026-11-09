---
title: "Intel Drop 02 | Backup app turned backdoor"
type: intel-drop
drop: 2
attack: [T1078.004, T1098.003, T1098.001]
risk: { likelihood: 5, impact: 5 }
tlp: CLEAR
summary: "A stolen ConnectWise Cloud Backup app credential was used to sign in to Microsoft 365 tenants on 15 Oct 2026."
date: 2026-10-19
---

The access path wasn't a phishing email or a zero-day. It was a trusted backup app that already had permission to read the mail.

Unknown actors used a stolen credential belonging to the ConnectWise Cloud Backup (formerly SkyKick) Microsoft 365 app to request Graph tokens in customer tenants on 15 October. Responders tracked confirmed unauthorised sign-ins in more than 160 tenants. In some tenants, ConnectWise Cloud Management apps gave themselves admin roles, and client secrets were added to other trusted apps for persistence (T1078.004, T1098.003, T1098.001).

A second, apparently manual sweep targeted policy, national security, trade and critical minerals organisations. That points to selection, not just spray-and-pray. No actor has been attributed.

## How it worked

1. Stolen app credential used for Graph tokens (T1078.004)
2. Vendor apps gave themselves admin roles (T1098.003)
3. Secrets added to other trusted apps (T1098.001)
4. Backups paused, restores unavailable

## Risk

**25/25 CRITICAL** (likelihood 5 × impact 5), affected-app tenants.

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Actor | LOW |

## Business risk

If the affected apps are enabled in a tenant, the attacker potentially has tenant-wide mail, files and Teams data, and admin control. Backups are paused while the vendor contains the incident, so restore options are reduced exactly when they may be needed.

## What to do now

- • Disable (don't delete) the affected ConnectWise/SkyKick apps until the vendor confirms the credential is rotated
- • Hunt for new app secrets, role assignments and consent grants since 13 October
- • Revoking user sessions won't end app-only access, so review service principal sign-ins
- • Enable Microsoft Graph activity logs
- Your SaaS vendors' app identities are part of your attack surface. Inventory them like privileged accounts.

## Sources

1. Huntress (16 Oct 2026 (updated 17 Oct)): <https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access>
2. Todyl (16 Oct 2026): <https://www.todyl.com/blog/investigation-unauthorized-access-through-the-connectwise-cloud-backup-microsoft-365-app>
3. BleepingComputer (17 Oct 2026 (updated 18 Oct)): <https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/>
4. The Hacker News (18 Oct 2026): <https://thehackernews.com/2026/10/connectwise-suspends-cloud-backup-after.html>
