---
title: "Intel Drop 32 | One crafted SMS can knock Android off the network"
type: intel-drop
drop: 32
motivation: unknown
sectors: []
regions: []
attack: []
risk: { likelihood: 3, impact: 3 }
tlp: CLEAR
summary: "CVE-2026-58882, the \"SMS of Death\": a crafted WAP Push message crashes Android's phone process and drops calls. Critical DoS, public PoC, no exploitation reported."
date: 2026-11-05
---

**CVE-2026-58882** · Critical DoS · public PoC · no exploitation reported.

One crafted WAP Push SMS crashes Android's phone process and drops calls, even emergency ones. Google's November bulletin rates it Critical and fixes Android 14 to 17. Android 12 and 13 are not listed.

## Attack chain

1. **Crafted WAP Push SMS, no user interaction.** It needs only the victim's phone number.
2. **Header length decodes to a negative array size.** The result is a `NegativeArraySizeException` in `WapPushOverSms`.
3. **The phone process crashes and active calls drop,** including emergency calls, with a brief loss of service.
4. **Around 20 messages can leave a device unusable.** Reboot loops are reported.

## Risk

**9/25 MEDIUM** (likelihood 3 × impact 3), unpatched Android fleets.

## Confidence

| Assessment | Confidence |
|---|---|
| Flaw and impact | HIGH |
| In-the-wild use | NONE REPORTED |

## Business risk

Unpatched phones lower the cost of attack, and a text message is enough.

## What to do now

- Apply the November Android patch.
- Retire Android 12 and 13 for critical roles.

## Sources

1. Android Security Bulletin (2 Nov 2026): <https://source.android.com/docs/security/bulletin/2026/2026-11-01>
2. Researcher write-up (29 Oct 2026): <https://smsofdeath.com/>
3. ThaiCERT (2 Nov 2026): <https://www.thaicert.or.th/en/2026/11/02/android-sms-of-death-vulnerability-could-crash-phone-services-through-crafted-messages/>
