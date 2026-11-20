---
title: "Weaponised ARTEX: who uses it, how, and how to hunt it"
actor: ARTEX
summary: "An open-source AI penetration-testing framework is now run by at least six named actors, from China-nexus espionage teams to small criminal crews, to compress intrusions into hours. Hunt the behaviour it automates, not its name."
date: 2026-11-17
tlp: CLEAR
claimsUnverified: false
attack: [T1595, T1526, T1580, T1583.003, T1588.007, T1090.003, T1190, T1110.003, T1078.004, T1199, T1505.003, T1098.001, T1558.003, T1003.006, T1552.001, T1606.002, T1087.002, T1550.002, T1021.006, T1572, T1114.002, T1530, T1567.002, T1657]
---

ARTEX is an open-source AI penetration-testing framework, released on GitHub on 26 July 2026, that attackers now use to run intrusions at machine speed. An operator gives it a goal. AI agents, backed by any large language model and most often DeepSeek, turn that goal into scanning, exploitation and lateral movement. On 13 November the FBI warned (FLASH-20261113-001) that it has been abused since at least August against government and ten critical sectors, sometimes reaching privileged access in under three hours.

Reporting period: July to 17 November 2026. Collection cut-off: 17 November 2026.

Related drops: [Intel Drop 16](/intel/intel-drop-16-artex-arrests/), [Intel Drop 31](/intel/intel-drop-31-artex-infrastructure/), [Intel Drop 38](/intel/intel-drop-38-antifox-aws-secrets/), [Intel Drop 40](/intel/intel-drop-40-artex-fbi-flash/) and [Hunt Drop 14](/hunting/hunt-drop-14-artex-ai-run-intrusion/).

## Key judgements

**Overall threat level: HIGH, rising.** Abuse by at least six named actors and four unnamed clusters in three months, a low barrier to entry, cheap models without guardrails and an FBI FLASH. The framework adds speed and scale rather than new techniques, so organisations with good identity hygiene and detection coverage are far better placed than the headlines suggest.

1. **Six actors are publicly tied to ARTEX by name.** We found no source naming more. The top ten below are those six plus four unattributed clusters, and each is labelled. Lists of ten named ARTEX groups elsewhere are padding.
2. **China-nexus actors are the heaviest users.** Storm-0940 used ARTEX in the ConnectWise Cloud Backup compromise, and VAPOR PANDA used it against government, defence, semiconductor and telecom targets in at least 14 countries. It is likely (55 to 70%) that more China-nexus clusters use ARTEX or its forks now.
3. **Criminals use it for fast money.** A Cambodia-based cluster hits Southeast Asian finance, an unnamed group targets Indian fintech and crypto, and a Korean crew stole about 8.2 million records from more than 90 organisations before arrest.
4. **The techniques are familiar.** Web shells, password spraying, OAuth and service-principal abuse, Kerberoasting, DCSync and staging to webhook.site. ARTEX chains them faster and tries more doors at once. Every one of them has existing detections.
5. **IOCs expire fast.** Published IP addresses belong to campaigns, not the framework, and the FBI says to treat them as historical. Two User-Agent strings and the console's default port are the only framework fingerprints, and operators can change all of them.
6. **Exposed edges and third-party identities are the way in.** Partner portals, staging systems, legacy web apps and highly privileged SaaS integrations led the way in across almost every case.

## Timeline

| Date (2026) | Event |
|---|---|
| 13 Nov | FBI FLASH-20261113-001 warns ARTEX has been abused since at least August. Cisco Talos and Elastic publish detection content. |
| 12 Nov | Unit 42 attributes CAIRN-driven intrusions to the China-nexus cluster CL-STA-1238. |
| 11 Nov | Unit 42 describes ARTEX behaviour in retail and consulting cloud environments. SOCRadar counts 916 live ARTEX-family consoles in the US. |
| 6 Nov | Microsoft reports Storm-3358, a Cambodia-based criminal cluster, using ARTEX against financial organisations. |
| 5 Nov | Check Point details ARTEX cybercrime campaigns. Censys counts 1,465 exposed hosts. |
| 4 Nov | India's CERT-In warns of the Crafty Falcon cluster using ARTEX and PentAGI against fintech and crypto firms. |
| 2 to 4 Nov | Up to 62 consoles reportedly serve a backdoored ARTEX build (single source). |
| 29 to 31 Oct | CrowdStrike reports VAPOR PANDA. Google Threat Intelligence and Mandiant report ARTEX, PentAGI, CAIRN and HexStrike in incident response cases. |
| 26 Oct | Seoul police arrest seven suspects who used ARTEX against more than 90 Korean organisations. |
| 21 Oct | Microsoft attributes the ConnectWise Cloud Backup compromise to Storm-0940 using ARTEX. |
| 17 Oct | VAPOR PANDA campaign starts and runs about 11 days. |
| 14 to 16 Oct | ConnectWise discovers and contains abuse of Cloud Backup application identities. |
| 8 Oct | The developer, Autumn-27, removes the GitHub repository. More than 12,000 forks exist. |
| 7 Oct | CrowdStrike reports an unknown actor using ARTEX against South Korean finance. |
| Aug | First observed malicious use. |
| 26 Jul | ARTEX published on GitHub under AGPL-3.0. |

## Business risk

Scores are analyst judgement (likelihood 1 to 5 × impact 1 to 5). Three of the eight scenarios score Critical, and all three start at the edge or in a trusted third-party identity.

| # | Scenario | L | I | Score |
|---|---|---|---|---|
| 1 | A forgotten portal, staging system or legacy web app is found and exploited within hours | 4 | 5 | 20 Critical |
| 2 | A privileged SaaS or backup integration is abused to reach Microsoft 365 or Entra ID | 3 | 5 | 15 Critical |
| 3 | Password spraying at thousands of attempts per minute against cloud identities | 4 | 4 | 16 Critical |
| 4 | Leaked cloud keys or secrets in front-end code are validated and used | 3 | 4 | 12 High |
| 5 | Kerberoasting and DCSync after a foothold | 3 | 5 | 15 Critical |
| 6 | Business data stolen and used for extortion | 3 | 4 | 12 High |
| 7 | A partner or supplier is breached through ARTEX and used as a bridge | 3 | 4 | 12 High |
| 8 | An internal team runs a backdoored ARTEX fork for testing | 2 | 4 | 8 Medium |

Scenario 2 deserves the board's attention: one compromised integration gave Storm-0940 a route into thousands of tenants that had done nothing wrong themselves.

## How ARTEX works

ARTEX is written in Go with a Next.js web console. An operator types a goal, a planner breaks it into tasks, and specialised agents run tools such as nuclei, httpx, katana, ffuf and sqlmap, store what they find in a shared asset graph, and report back. It ships no model of its own: it connects to Claude, GPT, DeepSeek, GLM, Grok, Kimi or any OpenAI-compatible endpoint. Attackers mostly pick DeepSeek Flash-family models for cost and for the lack of guardrails when a task is framed as penetration testing.

The orchestration, prompts, model and tooling all sit on the attacker's infrastructure. What reaches the victim is ordinary attack traffic: scans, exploit attempts, web shells and stolen credentials in use. Swap the model or the tools and the same goal produces different traffic, which is why "ARTEX IOC lists" mislead.

### Stage by stage

| Stage | What the operator and agents do | ATT&CK |
|---|---|---|
| 1. Tasking | A goal and a scope in plain language. VAPOR PANDA wrote instructions in Chinese and told agents to skip hosts running CrowdStrike Falcon. | T1588.007 |
| 2. Infrastructure | A model, most often DeepSeek Flash, on rented servers such as Hong Kong VPS behind residential proxies or Tor. One intrusion used about 1.4 billion input tokens. | T1583.003, T1588.007, T1090.003 |
| 3. Reconnaissance | httpx, katana and nuclei across the target range, plus cloud permission checks in sub-second bursts. | T1595, T1526, T1580 |
| 4. Initial access | The weakest entry found: SQL injection, SAML or XXE flaws, SSRF, anonymous upload, exposed staging systems, or password spray at up to 2,900 attempts a minute. | T1190, T1110.003, T1078.004, T1199 |
| 5. Foothold | JSP or PHP web shells, sometimes written through the MySQL general log, or credentials added to an OAuth application so access survives a password reset. | T1505.003, T1098.001 |
| 6. Credential access | Kerberoasting, DCSync of krbtgt, secrets read from web bundles and LAPS, and SAML tokens forged from old mail-server keys. | T1558.003, T1003.006, T1552.001, T1606.002 |
| 7. Discovery and lateral movement | More than 110,000 Active Directory objects enumerated in one case, then pass-the-hash, pass-the-ticket and WinRM, with Chisel or SoftEther tunnels. | T1087.002, T1550.002, T1021.006, T1572 |
| 8. Collection and exfiltration | Mailbox and blob reads, staging volumes of about 100 GB, then curl to rotating webhook.site URLs or uploads to Backblaze B2. | T1114.002, T1530, T1567.002 |
| 9. Objective | Espionage through mailbox access and the BLOODALCHEMY backdoor; extortion (38 demands from one ring); fraudulent transfers timed for weekends after small test payments. | T1657 |

### How threat actors abuse a legitimate testing tool

Nothing in ARTEX's code is malicious. The abuse lies in who points it at whom.

- **Pentest framing.** Tasks are framed as authorised testing, so many models carry them out. In one case only Anthropic's Opus 5.5 refused, and the operator switched to Chinese models.
- **Model shopping.** Operators pick cheap models with weak guardrails and buy API access through resellers.
- **Steering around defences.** Operators tell agents which security products to avoid and which hosts to leave alone.
- **Low skill, high output.** A former penetration tester and six associates hit more than 90 organisations.
- **Rebranded forks.** Forks such as ScopeWeaver and the commercial ARTEX PRO can rename files, accounts and console titles, so artefact-based detection breaks.
- **Careless exposure.** More than 1,600 consoles were left open on the internet.
- **Attackers attacking attackers.** Some public copies were trojanised with a root shell in the login handler (single source).

### What it looks like from the defender's side

| Item | Detail |
|---|---|
| Speed | Bursts of 1 to 14 requests about a second apart, then a 25 to 31 second pause; more than 200 application secrets validated in about three minutes; polling every 48 seconds. |
| Retry pattern | HTTP 422 errors retried after small changes, and a GET to the same path after almost every write. |
| Canary values | Test strings such as `evil[.]com`, `test@example[.]com` and `deadbeefdeadbeefdeadbeef12` in submitted data. |
| Artefacts | `artex-probe-*` files with numbered suffixes, `ArtexProbe` in created accounts and email subjects, numbered JSP web shells, and hundreds of rotating webhook.site URLs. Forks can rename all of them. |
| Framework fingerprints | User-Agent `artex-enrich/1.0` (enrichment probes) and `norma/0.4` (web fetch tool); console on TCP 8787 with a title starting "ARTEX"; HTTP Basic realm "ARTEX". |
| Models seen | DeepSeek v4.1 Flash dominates; Kimi K3.1 Pro, GLM-5.3, Grok 4.6 and Claude Code also appear. |

### Forks and related frameworks

| Framework | What it is |
|---|---|
| ScopeWeaver | Localised or rebranded ARTEX fork |
| ARTEX PRO | Commercial edition named by the FBI; seller and price not established |
| CAIRN | Agentic platform producing noisy multi-protocol traffic from one origin; linked to CL-STA-1238 |
| PentAGI | Agent framework running Kali sandboxes; checks in to update.pentagi.com |
| HexStrike | Python MCP server on port 8888 with its own User-Agent strings |
| CyberStrikeAI | Go framework, often co-hosted with ARTEX |

## Threat actor landscape

Ranked by strength of evidence. No source ties ARTEX to Iranian, North Korean, Russian or named ransomware brands so far.

| # | Actor | Attribution | Status | Activity |
|---|---|---|---|---|
| 1 | Storm-0940 (overlaps UNC7228) | China-state aligned (Microsoft, Google) | ACTIVE | ARTEX for spraying and OAuth abuse in the ConnectWise Cloud Backup compromise; 2,250+ tenants attempted, 162 confirmed |
| 2 | VAPOR PANDA | China-nexus espionage (CrowdStrike) | ACTIVE | 200+ organisations in 14+ countries over 11 days from 17 October; 9 compromised; BLOODALCHEMY backdoor |
| 3 | TAG-217 | Chinese-speaking, financially motivated, likely one person (moderate confidence) | ACTIVE | South Korean banks via a loan portal and a staff mobile system; about 67,000 people's data taken |
| 4 | Storm-3358 | Cambodia-based criminal cluster (Microsoft) | ACTIVE | Financial organisations, mainly Southeast Asia; WISP, vshell and AdaptixC2 RATs |
| 5 | Crafty Falcon | Criminal, nexus not stated (CERT-In) | ACTIVE | Indian NBFCs, fintechs and crypto exchanges through exposed staging systems; ARTEX and PentAGI |
| 6 | Korean extortion ring | Domestic criminals; leader a former pentester | DISRUPTED | 90+ Korean organisations, about 8.2 million records, 38 ransom demands; seven arrested |
| 7 | Unattributed cloud campaign (Unit 42) | Unknown | ACTIVE | Retail and consulting cloud environments from 24 September |
| 8 | Unattributed cybercriminals (Check Point) | Unknown, Chinese-language tooling | ACTIVE | iOS signing shops, crypto payment domains and gaming credential servers |
| 9 | Unnamed extortion and PRC-nexus clusters (Mandiant) | Mixed | ACTIVE | Incident response cases in US government, technology, chemicals and manufacturing |
| 10 | Vitas / GodNet (suspected) | Chinese DDoS-for-hire community | UNCONFIRMED | Linked by Logpresso to the Korean bank attacks; Logpresso says the link is not proof |

### Actor risk scoring

Each actor is scored 1 to 5 on capability, intent toward Western and Asian enterprises, activity in the last 30 days, and evidence of ARTEX use (maximum 20). Bands: 17 to 20 Critical, 13 to 16 High, 9 to 12 Medium, 4 to 8 Low. This is analyst judgement, not a measured value.

| Actor | Capability | Intent | Recent activity | ARTEX evidence | Total | Rating |
|---|---|---|---|---|---|---|
| Storm-0940 | 5 | 5 | 4 | 5 | 19 | Critical |
| VAPOR PANDA | 5 | 5 | 4 | 5 | 19 | Critical |
| TAG-217 | 3 | 4 | 3 | 5 | 15 | High |
| Storm-3358 | 3 | 4 | 5 | 4 | 16 | High |
| Crafty Falcon | 3 | 4 | 5 | 3 | 15 | High |
| Korean extortion ring | 2 | 3 | 1 | 4 | 10 | Medium |
| Unit 42 cluster | 3 | 3 | 4 | 4 | 14 | High |
| Check Point criminals | 2 | 3 | 4 | 4 | 13 | High |

## Targeted countries and sectors

No source publishes a complete country list for ARTEX victims. VAPOR PANDA's 14 countries are only partly named, and Zscaler's 19 jurisdictions are scanning targets, not confirmed victims. Countries below are ranked by the number of independent reports, which is not the same as the number of victims.

1. South Korea (banks, 90+ organisations)
2. United States
3. India
4. Japan (about 20 companies)
5. Belgium
6. Greece
7. Philippines
8. Netherlands (single source)
9. Canada
10. United Kingdom and Taiwan (scanning only, low confidence)

Regions mentioned without named countries: Southeast Asia, Latin America, the Middle East and an unnamed European country. Exposed ARTEX consoles sit mostly in the United States, Hong Kong and China, which shows where operators rent servers, not where victims are.

| Sector | Risk | Reason |
|---|---|---|
| Financial services, fintech and crypto | Critical | Hit by TAG-217, Storm-3358, Crafty Falcon and the FBI's sector list |
| Government and foreign ministries | Critical | VAPOR PANDA and Mandiant cases |
| IT, SaaS and managed service providers | High | Storm-0940 through ConnectWise; Wiz reports targeting of software vendors |
| Semiconductor and defence | High | VAPOR PANDA; CL-STA-1238 with CAIRN |
| Telecommunications | High | VAPOR PANDA victims in the US and Belgium |
| Healthcare and education | Medium | Korean extortion ring |
| Gaming, retail and consulting | Medium | Check Point and Unit 42 campaigns |

## Underground footprint

Assessed through clear-web monitoring reporting only; no Tor site was visited and no file or tool was downloaded. ARTEX spreads mostly as free code, not as a product for sale.

- No clear-web source shows ARTEX for sale on XSS, Exploit, BreachForums or RAMP, and no price or as-a-service offer has been published.
- Brandefense counted 52 Telegram, Discord and forum posts mentioning ARTEX between 17 and 30 October; most reshared news (single source).
- More than 12,000 forks existed before the repository came down. Copies, an English translation and a "global edition" remain on GitHub.
- Exposed consoles: Unit 42 609 (October); Censys 1,465 (4 November, about 815 distinct deployments); Check Point 1,608 live; FBI more than 1,600; SOCRadar 916 live in the US alone. 155 hosts also run Cobalt Strike, AdaptixC2, Vshell or other tooling.

## Indicators

The network indicators are historically observed campaign infrastructure, may already be reassigned, and should be corroborated before blocking. Only the framework fingerprints above travel from one operator to the next, and operators can change those too. Full IOC lists are in the FBI FLASH and the Microsoft, CrowdStrike, Unit 42, Check Point and Cisco Talos publications listed below. Microsoft's table and its own hunting query disagree on one IP address, so check before using either.

## Threat hunting

The hunts look for the behaviour ARTEX automates, plus the few framework fingerprints that exist. Each would also catch the same attack driven by a different framework. Queries were written against the published Falcon Next-Gen SIEM (CQL) and Defender XDR advanced hunting (KQL) schemas but have not been run in a live environment, so test and tune thresholds first.

| # | Hunt | ATT&CK |
|---|---|---|
| 1 | Framework fingerprints in web and proxy logs | T1595, T1190 |
| 2 | Web server spawning a shell (web shell) | T1505.003 |
| 3 | Web shell files written by web or database processes | T1505.003 |
| 4 | curl or PowerShell to webhook.site | T1567, T1071.001 |
| 5 | ARTEX intrusion markers in command lines | T1059 |
| 6 | Machine-speed discovery bursts | T1087, T1069, T1082 |
| 7 | Tunnelling and RAT tooling (Chisel, vshell, AdaptixC2, SoftEther, frp) | T1572, T1090 |
| 8 | Kerberoasting and DCSync | T1558.003, T1003.006 |
| 9 | Credentials added to applications and service principals | T1098.001 |
| 10 | Password spray at machine speed | T1110.003 |
| 11 | ARTEX or other agent consoles inside your network | T1219 |
| 12 | Connections to published campaign infrastructure | T1071 |

Working queries for the web-shell and process-lineage hunts are in [Hunt Drop 14](/hunting/hunt-drop-14-artex-ai-run-intrusion/).

## Outlook: next 30 to 90 days

| Judgement | Likelihood |
|---|---|
| More China-nexus clusters are publicly linked to ARTEX or its forks | Likely (55 to 70%) |
| A ransomware brand is publicly tied to ARTEX use | Realistic possibility (35 to 50%) |
| Another SaaS or MSP integration is abused at scale through an agentic framework | Likely (55 to 70%) |
| Takedowns reduce ARTEX use | Unlikely (10 to 25%) |
| Attackers move to a renamed or new framework | Almost certain (90 to 95%) |

## What to do now

1. Inventory and shrink the external attack surface: staging, UAT, partner portals and legacy apps first.
2. Review every third-party application with high Graph or directory permissions, search sign-ins by app ID, and remove unused credentials.
3. Remove secrets from front-end bundles and rotate any cloud keys that have ever been exposed.
4. Enforce phishing-resistant MFA, block legacy authentication and rate-limit sign-ins.
5. Deploy hunts 2 to 10 as scheduled detections; run 1, 11 and 12 as periodic hunts.
6. Ban unofficial ARTEX builds internally; if red teams use agentic tools, keep them off production networks.

## Sources and evaluation

Twenty-seven public sources, led by the FBI FLASH and the original vendor research. News coverage was used only where a primary source could not be read or added facts. Ratings use the Admiralty Code (reliability A to F, credibility 1 to 6). Limits: Microsoft's 21 October Storm-0940 post and the full Check Point report were read through secondary summaries, and exposure counts differ by vendor because each uses a different scanning method and date.

1. FBI, FLASH-20261113-001: ARTEX agentic AI framework (13 Nov 2026), A1
2. Cisco Talos, ARTEX and beyond (13 Nov 2026), A2
3. Elastic Security Labs, Agentic offensive frameworks: detecting ARTEX (13 Nov 2026), A2
4. Palo Alto Networks Unit 42, CAIRN framework and AI autonomous attacks (12 Nov 2026), A2
5. Palo Alto Networks Unit 42, ARTEX and AI-powered red-teaming tools (11 Nov 2026), A2
6. SOCRadar, ARTEX AI pentest consoles in the US (11 Nov 2026), B3
7. Microsoft Threat Intelligence, ARTEX abuse expands as cybercriminals target financial sector (6 Nov 2026), A2
8. Check Point Research, Hacking on autopilot: inside ARTEX cybercrime campaigns (5 Nov 2026), A2
9. Censys, ARTEX: agentic asbestos (5 Nov 2026), A2
10. Infosecurity Magazine, India warns of AI cyberattacks on fintech, citing CERT-In CIAD-2026-0058 (4 Nov 2026), B2
11. Let's Data Science, Censys finds 1,465 exposed hosts running ARTEX (Nov 2026), C3, single source
12. CrowdStrike, VAPOR PANDA uses ARTEX to scale global campaign (29 Oct 2026), A2
13. Google Threat Intelligence and Mandiant, ARTEX and friends enter: agentic offensive frameworks (31 Oct 2026), A2
14. BleepingComputer, Former pentester used ARTEX AI to steal 8.2 million data records (26 Oct 2026), B2
15. CyberScoop, Microsoft attributes ConnectWise supply-chain attack to China's Storm-0940 (21 Oct 2026), B2
16. The Record, ConnectWise suspends Cloud Backup after supply-chain attack (19 Oct 2026), B2
17. BleepingComputer, FBI warns ARTEX AI hacking tool is powering global cyberattacks (13 Nov 2026), B2
18. Help Net Security, ARTEX goes from pentesting tool to attacker staple in three months (9 Nov 2026), B2
19. CrowdStrike, Unknown threat actor uses ARTEX to target South Korean finance (7 Oct 2026), A2
20. Zscaler ThreatLabz, Threat actor abuses agentic AI pentesting framework to target South Korean finance (14 Oct 2026), B2
21. Wiz, ARTEX in the wild: Storm-0940 expands targeting (22 Oct 2026), B2
22. Recorded Future Insikt Group, TAG-217: ARTEX attacks on South Korean banks (16 Oct 2026), A2
23. Palo Alto Networks Unit 42, Activity using ARTEX agentic AI, IOC file on GitHub (30 Oct 2026), A2
24. BleepingComputer, Chinese hackers use ARTEX AI in automated attacks against 200 orgs (2 Nov 2026), B2
25. Asia News Network, Logpresso links DDoS community to Korean bank attacks (Oct 2026), C3
26. Cloud Security Alliance, Multi-agent offensive frameworks in the wild: CyberStrikeAI and ARTEX (28 Oct 2026), B2
27. Brandefense, ARTEX knowledge hub (31 Oct 2026), C3
