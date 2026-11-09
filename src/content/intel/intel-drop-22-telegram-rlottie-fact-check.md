---
title: "Intel Drop 22 | Telegram sticker claims: confirmed vs unverified"
type: intel-drop
drop: 22
attack: []
risk: { likelihood: 2, impact: 4 }
tlp: CLEAR
summary: "A conference talk claims a zero-click iOS chain through the rlottie sticker renderer."
date: 2026-10-29
---

At OffensiveCon in Tokyo this week, researcher Saifeldeen Aziz presented claims of new memory-corruption bugs in rlottie, the library Telegram uses to render animated (TGS/Lottie) stickers. He says he bypassed Telegram's server-side sticker checks and chained the bugs into code execution on iOS without user interaction.

Confirmed: rlottie is a recurring bug source. ZDI published CVE-2026-111105, an unfixed rlottie flaw (CVSS 7.0, user interaction assumed), on 15 October; Telegram's position since March is that server-side validation stops malformed stickers.

Not confirmed: the iOS chain. Only the talk abstract is public, no fix or affected versions have been announced, Telegram disputes the risk, and no in-the-wild exploitation is reported.

Don't conflate it with September's 269-byte sticker that crashed Telegram clients. That was a denial-of-service bug, not code execution. Telegram Desktop 7.2.7 (7 Sep) lists a fix for "crashes with invalid lottie files".

## Fact check

1. CONFIRMED: rlottie flaw CVE-2026-111105, published 15 Oct, CVSS 7.0, no fix listed
2. CLAIMED: zero-click iOS chain, from the talk abstract only with no code or versions
3. DISPUTED: server-side checks. Telegram says validation blocks bad stickers
4. SEPARATE: 269-byte crash sticker, a September denial of service and not code execution

## Risk

**8/25 MEDIUM** (likelihood 2 × impact 4).

## Confidence

| Assessment | Confidence |
|---|---|
| rlottie bug class | HIGH |
| Claimed iOS zero-click chain | LOW |
| In-the-wild exploitation | NOT REPORTED |

## Business risk

For executives, officials and journalists who use Telegram, a working zero-click chain would mean silent device compromise. Today it is a credible but unverified claim.

## What to do now

- Keep Telegram and iOS updated on every managed device.
- Restrict who can message high-risk users; leave unneeded groups.
- Keep sensitive work off Telegram on the same device as email and MFA.
- Watch Telegram release notes and ZDI for a fix.

## Sources

1. Sandbanks Digital, claimed vs confirmed (28 Oct 2026): <https://sandbanksdigital.com/guides/telegram-sticker-zero-click-claims>
2. TokenPost (28 Oct 2026): <https://www.tokenpost.com/news/technology/42995>
3. OpenCVE, CVE-2026-111105: <https://app.opencve.io/cve/CVE-2026-111105>
4. SQ Magazine, Telegram response (30 Mar 2026): <https://sqmagazine.co.uk/telegram-zero-click-sticker-vulnerability/>
5. Telegram Desktop changelog: <https://telegramdesktop.github.io/tdesktop/changelog/>
6. VGTimes, 269-byte sticker (9 Sep 2026): <https://vgtimes.com/tech-and-hardware/166982-a-269-byte-telegram-sticker-is-crashing-mobile-clients.html>
