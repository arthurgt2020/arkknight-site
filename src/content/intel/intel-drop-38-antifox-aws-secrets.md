---
title: "Intel Drop 38 | AntiFox AI agents loot AWS secrets"
type: intel-drop
drop: 38
motivation: unknown
sectors: [Cloud]
regions: []
attack: [T1190, T1505.003, T1552.001, T1078.004, T1555.006]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "Arctic Wolf saw self-hosted AntiFox, an ARTEX-derived agentic framework, drive IIS web-shell intrusions and hundreds of AWS API calls in about 30 minutes, retrieving a production secret."
date: 2026-11-12
---

Arctic Wolf saw self-hosted AntiFox, an ARTEX-derived agentic framework, drive IIS web-shell intrusions and hundreds of AWS API calls in about 30 minutes, retrieving a production secret.

Posted together with [Intel Drop 36](/intel/intel-drop-36-screenconnect-msp-rogue-agents/), [Intel Drop 37](/intel/intel-drop-37-qlik-sense-scheduler-shells/).

## Attack chain

1. **Entry**. Vulnerable IIS web application (T1190).
2. **Foothold**. Web shell dropped (T1505.003).
3. **Harvest**. Credentials read from web.config (T1552.001).
4. **Cloud**. Stolen keys used for AWS API calls (T1078.004), then a secret retrieved from Secrets Manager (T1555.006).

## Risk

**12/25 HIGH** (likelihood 3 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| Activity (vendor observation) | HIGH |
| ARTEX derivation | MODERATE |

## Business risk

Your MSP, analytics server and cloud keys each sit one hop from your data and backups. One compromise can mean silent remote control, stolen secrets and a ransomware foothold.

## What to do now

- Enable CloudTrail S3 data events; alert on GetSecretValue from new sources.
- Rotate credentials stored in web.config.

## Sources

1. Arctic Wolf Labs (10 Nov 2026): <https://raw.githubusercontent.com/rtkwlf/wolf-tools/main/pack_alerts/202611-antifox-alibaba-hosted-platforms-facilitate-web-cloud-intrusions/README.md>
2. BleepingComputer (11 Nov 2026): <https://www.bleepingcomputer.com/news/security/hackers-use-antifox-ai-agents-in-aws-credential-theft-attacks/>
3. Security Affairs (11 Nov 2026): <https://securityaffairs.com/202880/hacking/ai-pentest-tool-antifox-abused-to-steal-aws-credentials.html>
