---
title: "Intel Drop 03 | One vendor, 38 maritime victims?"
type: intel-drop
drop: 3
actor: n0n
attack: [T1078, T1199, T1657]
risk: { likelihood: 3, impact: 4 }
tlp: CLEAR
summary: "n0n data-theft extortion hits ports and shipping: 38 listings across 18 countries, GCC included."
date: 2026-10-20
linkedinUrl: "https://lnkd.in/p/d2JdkfA5"
---

On 12 Oct, the data-theft extortion group n0n (first seen Sept 2026) listed 38 shipping lines, port terminals and logistics firms across 18 countries in a single batch, including entries in Saudi Arabia and Kuwait. Its payment deadline passed on 19 Oct.

What's new: maritime security researchers now assess the data most likely came from one maritime software provider's support and project archive, split into per-customer listings, not from 38 separate intrusions. At least 21 of the named organisations are publicly documented customers of that provider. No incident has been confirmed and the data remains unverified.

Our read: this is likely a third-party exposure, not a port-by-port campaign. Samples reportedly include credentials, EDI messages and deployment documents, which can fuel follow-on intrusion and fraud long after the headlines fade.

## Timeline

1. 18 Sep: n0n extortion group emerges
2. 12 Oct: 38 maritime organisations listed across 18 countries
3. 19 Oct: leak deadline passes
4. 20 Oct: analysis suggests the data came from one vendor's support archive

ATT&CK (analyst mapping): T1078 Valid Accounts, T1199 Trusted Relationship (suspected), T1657 Financial Theft.

## Risk

**12/25 HIGH** (likelihood 3 × impact 4), GCC maritime and logistics.

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Vendor link | LOW to MODERATE |
| Attribution | LOW |

## Business risk

Vendor-held credentials and system configs could give attackers a path into terminal and logistics systems, enable cargo-data tampering or invoice fraud, and trigger customer and regulator scrutiny.

## What to do now

- Map which maritime/logistics vendors hold your credentials, configs or support files.
- Rotate any credentials ever shared through vendor support channels.
- Review vendor remote access; hunt for vendor-account logins outside change windows.
- Prepare customer and regulator comms in case your name appears.

## Sources

1. SOCRadar (13 Oct 2026): <https://socradar.io/blog/n0n-group-global-ports-shipping-leak/>
2. The Maritime Executive (14 Oct 2026): <https://maritime-executive.com/article/massive-cyber-attack-threatens-release-of-data-from-38-maritime-companies>
3. The Loadstar (14 Oct 2026): <https://theloadstar.com/cyber-crime-group-hits-38-shipping-and-port-groups-with-date-leak-threat/>
4. Boan News, Korean (13 Oct 2026): <https://www.boannews.com/news/articleView.html?idxno=146345>
