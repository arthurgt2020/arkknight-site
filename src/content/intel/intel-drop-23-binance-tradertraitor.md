---
title: "Intel Drop 23 | North Korea's TraderTraitor drains $6.3B from Binance"
type: intel-drop
drop: 23
actor: TraderTraitor
attack: []
risk: { likelihood: 4, impact: 5 }
tlp: CLEAR
summary: "No key theft was found: Binance's own signer was made to sign."
date: 2026-11-01
---

On 29 Oct, Binance hot wallets across about ten blockchains were emptied, most of it in roughly 20 minutes. The FBI attributed it to North Korea on 31 Oct. No private-key theft has been found: analysts assess the attacker made Binance's own signing system sign, including 50 pre-signed EIP-7702 authorisations. Binance's preliminary view points to a compromised DevOps engineer's laptop.

## How it unfolded (UTC)

1. 28 Oct: operator wallet funded via Tornado Cash withdrawals
2. 29 Oct: attack code deployed, tested and rehearsed on 3 wallets
3. 29 Oct 20:05: hot-wallet drains begin, and most moved in about 20 minutes
4. 29 Oct 20:20: 50 pre-signed EIP-7702 authorisations seize the ETH wallet
5. 31 Oct: the FBI attributes the theft to North Korea (TraderTraitor)

## Risk

**20/25 CRITICAL** (likelihood 4 × impact 5), GCC crypto exchanges and VASPs.

## Confidence

| Assessment | Confidence |
|---|---|
| Theft activity | HIGH |
| North Korea link | HIGH |
| Root cause | LOW (no post-mortem) |

## Business risk

Both this attack and Intel Drop 24 went after engineers: their laptops and their tools sit one step away from money, code and cloud.

## What to do now

- Treat DevOps and developer endpoints as tier-0.
- Gate signing services with independent approval.

## Sources

1. Binance (30 Oct 2026): <https://www.binance.com/en/support/announcement/detail/c5a8729a97ac486d963784d96c5642d7>
2. TRM Labs (29–30 Oct 2026): <https://www.trmlabs.com/resources/blog/north-korea-steals-usd-6-36-billion-from-binance-in-the-largest-hack-in-history>
3. Chainalysis (30 Oct 2026): <https://www.chainalysis.com/blog/binance-exploit-latest-findings-and-response/>
4. Elliptic (30 Oct 2026, upd. 31 Oct): <https://www.elliptic.co/insights/binance-largest-hack-in-history/>
5. CoinDesk (31 Oct 2026): <https://www.coindesk.com/policy/2026/10/31/fbi-confirms-north-korea-s-role-in-usd6-billion-binance-hack-asks-defi-community-to-block-btc-eth-sol-addresses>
6. RTÉ News (1 Nov 2026): <https://www.rte.ie/news/2026/1101/1597504-fbi-crypyo/>
