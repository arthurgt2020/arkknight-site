---
title: "Intel Drop 04 | ClickFix goes as-a-service"
type: intel-drop
drop: 4
attack: [T1204.004, T1059.001, T1218.007, T1574.002, T1555.003]
risk: { likelihood: 4, impact: 3 }
tlp: CLEAR
summary: "ROMULUS: one panel, multiple payload routes, including LegionLoader and a browser-data stealer."
date: 2026-10-20
linkedinUrl: "https://lnkd.in/p/d2JdkfA5"
---

ClickFix, the fake "fix this error" prompt that tricks users into pasting a command, is no longer a one-off trick. Researchers have exposed ROMULUS, a reusable ClickFix delivery panel found on six servers. It serves different payloads from one backend and tracks installs on a stats page.

Two routes were observed. One drops a trojanised MSI that sideloads a malicious DLL through a legitimate signed app. The other delivers LegionLoader inside an executable padded to about 842 MB, likely to slip past scanner size limits, and goes on to collect browser data. The same chain overlaps with a recent campaign that used malicious ChatGPT Custom GPTs to push ClickFix pages.

Our read: the operator is unknown, and ROMULUS may be a private panel or a commercial crimeware service. Either way, ClickFix is maturing into shared infrastructure, so expect more lures and faster payload rotation.

Companion hunt: [Hunt Drop 1](/hunting/hunt-drop-01-romulus-clickfix/).

## Attack chain

1. Fake 'fix' lure: the user pastes a command (T1204.004)
2. PowerShell stager picks the next payload (T1059.001)
3. Trojanised MSI run silently via msiexec (T1218.007)
4. DLL sideloading via a legitimate signed app (T1574.002)
5. Browser credential and data theft (T1555.003)

Hunt for: hidden PowerShell with a URL, silent MSI installs from %TEMP%, huge EXEs in user folders, and non-browser reads of Chrome data.

## Risk

**12/25 HIGH** (likelihood 4 × impact 3), GCC enterprise endpoints.

## Confidence

| Assessment | Confidence |
|---|---|
| Activity | HIGH |
| Operator | UNKNOWN |
| Custom GPT campaign link | MODERATE |

## Business risk

One user pasting one command can hand attackers browser-stored passwords and session data, opening a path to email, SaaS and VPN account takeover and follow-on intrusion.

## What to do now

- Alert on hidden PowerShell or -ep bypass launched with a URL.
- Flag silent MSI installs and very large EXEs in user-writable folders.
- Restrict the Run dialog and PowerShell for standard users where feasible.
- Tell staff plainly: no legitimate site asks you to paste commands.

## Sources

1. Forescout Vedere Labs, ROMULUS analysis (Oct 2026): <https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/>
2. The Hacker News (20 Oct 2026): <https://thehackernews.com/2026/10/romulus-clickfix-platform-tricks-users.html>
3. Infosecurity Magazine (14 Oct 2026): <https://www.infosecurity-magazine.com/news/romulus-malware-clickfix-deliver/>
4. SecurityWeek on Huntress Custom GPT ClickFix research (29 Sep 2026): <https://www.securityweek.com/hackers-use-chatgpt-custom-gpts-in-clickfix-attacks/amp/>
