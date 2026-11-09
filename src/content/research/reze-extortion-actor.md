---
title: "REZE: new extortion actor targeting the Middle East"
actor: REZE
summary: "An actor calling itself REZE Ransomware has claimed two breaches in Dubai, in the financial and government real-estate sectors. None of the claims is confirmed."
date: 2026-10-27
tlp: CLEAR
claimsUnverified: true
linkedinUrl: "https://lnkd.in/p/diTG3V9G"
---

In the past week, an actor calling itself REZE Ransomware has claimed two breaches in Dubai: one in the financial sector (USD 5M demand) and one in the government real-estate sector (USD 100K). It says it has started leaking files from the financial-sector victim. **None of this is confirmed.** Every item below is a claim unless stated otherwise.

## Claims

| Sector | Ask | Claimed data |
|---|---|---|
| Financial | USD 5M demand | Leak of files has begun |
| Government, real estate | USD 100K ask | Property and ID data |

## What we know

- A single forum account, created in September 2026.
- The claimed way in is cracked credentials for a Salesforce integration user.
- 200+ infostealer credentials exist for the financial-sector target's domain, the latest from mid-October.
- No encryption, no leak site and no published indicators of compromise.
- An earlier claim, on 10 October, against an Indian public transport operator.

## Risk for UAE financial-sector firms

Likelihood **Medium**, impact **High**, overall **HIGH** (data exposure, regulatory and reputational).

## What to do now

- Reset any account that appears in stealer logs.
- Rotate Salesforce and SAP integration credentials and API keys.
- Review data export logs back to 1 September.

The full TLP:CLEAR profile, with seven Sigma rules and Splunk and KQL hunts, is linked from the LinkedIn post.
