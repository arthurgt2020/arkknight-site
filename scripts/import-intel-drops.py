#!/usr/bin/env python3
"""Rebuild Intel Drop pages from a folder of source drafts.

Usage:  python scripts/import-intel-drops.py <source-folder> [drop numbers...]

Each drop in META names the draft file that holds its LinkedIn post and sources
(a section starting "INTEL DROP #NN |" or "-"). Facts that only appear on the
published graphic (attack chain, risk, confidence) are kept in META. Working
notes, review checklists and caveats are not copied. Existing dates and
linkedinUrl values are kept. Add new drops to META and re-run.
"""
import glob
import os
import re
import sys

SITE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTEL = os.path.join(SITE, 'src', 'content', 'intel')
SRC = ''
FENCE = '`' * 3

PHRASES = {}  # reviewed rewordings, same idea as the hunt importer

F22 = 'intel-drop-2026-10-22_1.md'
F25 = 'intel-drop-2026-10-25.md'
F29 = 'intel-drop-2026-10-29-b.md'
F19 = 'intel-drop-02-2026-10-19.md'
F20 = 'intel-drop-2026-10-20.md'

# chain: (text, attack ids)
META = {
    2: dict(file=F19, title='Backup app turned backdoor',
            sub='A stolen ConnectWise Cloud Backup app credential was used to sign in to Microsoft 365 tenants on 15 Oct 2026.',
            chain_title='How it worked', risk=(5, 5), area='affected-app tenants',
            conf=[('Activity', 'HIGH'), ('Actor', 'LOW')],
            chain=[('Stolen app credential used for Graph tokens', 'T1078.004'),
                   ('Vendor apps gave themselves admin roles', 'T1098.003'),
                   ('Secrets added to other trusted apps', 'T1098.001'),
                   ('Backups paused, restores unavailable', '')]),
    3: dict(file=F20, title='One vendor, 38 maritime victims?', actor='n0n', drop_sources=[1],
            sub='n0n data-theft extortion hits ports and shipping: 38 listings across 18 countries, GCC included.',
            chain_title='Timeline', risk=(3, 4), area='GCC maritime and logistics',
            conf=[('Activity', 'HIGH'), ('Vendor link', 'LOW to MODERATE'), ('Attribution', 'LOW')],
            chain=[('18 Sep: n0n extortion group emerges', ''),
                   ('12 Oct: 38 maritime organisations listed across 18 countries', ''),
                   ('19 Oct: leak deadline passes', ''),
                   ("20 Oct: analysis suggests the data came from one vendor's support archive", '')],
            extra='ATT&CK (analyst mapping): T1078 Valid Accounts, T1199 Trusted Relationship (suspected), T1657 Financial Theft.',
            attack_ids=['T1078', 'T1199', 'T1657']),
    4: dict(file=F20, title='ClickFix goes as-a-service', hunt=(1, 'hunt-drop-01-romulus-clickfix'),
            sub='ROMULUS: one panel, multiple payload routes, including LegionLoader and a browser-data stealer.',
            chain_title='Attack chain', risk=(4, 3), area='GCC enterprise endpoints',
            conf=[('Activity', 'HIGH'), ('Operator', 'UNKNOWN'), ('Custom GPT campaign link', 'MODERATE')],
            chain=[("Fake 'fix' lure: the user pastes a command", 'T1204.004'),
                   ('PowerShell stager picks the next payload', 'T1059.001'),
                   ('Trojanised MSI run silently via msiexec', 'T1218.007'),
                   ('DLL sideloading via a legitimate signed app', 'T1574.002'),
                   ('Browser credential and data theft', 'T1555.003')],
            extra='Hunt for: hidden PowerShell with a URL, silent MSI installs from %TEMP%, huge EXEs in user folders, and non-browser reads of Chrome data.'),
    5: dict(file=F22, title='PHP2Shell: critical PHP runtime RCE flaws', hunt=(2, 'hunt-drop-02-php2shell'),
            sub='CVSS 9.2, unauthenticated, PHP 5.4 onward affected: two chained memory flaws give remote code execution.',
            chain_title='Attack path', risk=(4, 5), area=None,
            conf=[('In-the-wild attempts', 'HIGH')],
            chain=[('Unauthenticated request to any PHP app', 'T1190'),
                   ('Out-of-memory corruption at setup', 'CVE-2026-109618'),
                   ('Stale state reused by next request', 'CVE-2026-109619'),
                   ('RCE: web worker spawns a shell', 'T1059.004')]),
    6: dict(file=F22, title='Qilin & INC: GlobalProtect bypass to the hypervisor',
            sub='PAN-OS CVE-2026-0257 is now used by ransomware crews to get past MFA and reach vCenter.',
            chain_title='Attack chain', risk=(4, 5), area=None, actor='Qilin, INC',
            conf=[('Exploitation activity', 'HIGH'), ('Qilin / INC naming', 'MODERATE')],
            chain=[('GlobalProtect auth bypass, MFA evaded', 'T1190, T1133'),
                   ('Recon with dual-use RMM tools', 'T1219'),
                   ('Lateral movement over RDP and SMB', 'T1021'),
                   ('vCenter pivot, ESXi controls disabled', 'T1562'),
                   ('Offline creds from DC virtual disk', 'T1003.003')]),
    7: dict(file=F22, title='BRONZE SANDCASTLE: spying via trusted binaries',
            sub='A new China-based cluster side-loads a rogue DLL through a renamed Sandboxie binary. Victims are in Asia and Africa.',
            chain_title='Intrusion chain', risk=(2, 4), area=None, actor='BRONZE SANDCASTLE',
            conf=[('Intrusion activity', 'HIGH'), ('China-based attribution', 'MODERATE')],
            chain=[('Renamed Sandboxie loads rogue sbiedll.dll', 'T1574.001'),
                   ('Encrypted config.ini run in memory', 'T1027'),
                   ('Backdoor pulls tasks via web services', 'T1102'),
                   ('Account discovery with net commands', 'T1087'),
                   ('vssadmin shadow copy, ntds.dit copied', 'T1003.003')]),
    8: dict(file=F22, title='SafePay ransomware: 600+ victims, backups first',
            sub='Joint US-German-UK advisory AA26-293A (20 Oct 2026): SafePay wipes backups before it encrypts.',
            chain_title='Attack chain', risk=(3, 5), area=None, actor='SafePay',
            conf=[('SafePay activity', 'HIGH'), ('GCC targeting', 'LOW')],
            chain=[('Edge/Veeam CVEs, brute force, phishing', 'T1190, T1110'),
                   ('Lateral movement: PsExec, WinRM, RDP', 'T1021'),
                   ('Remote access via AnyDesk / TeamViewer', 'T1219'),
                   ('Exfiltration with Rclone / WinSCP', 'T1567'),
                   ('Stop VSS, reset backup NAS, encrypt', 'T1490, T1486')]),
    9: dict(file=F22, title='GitLab CVE-2026-110264: CVSS 10.0, 12 years deep',
            sub='Unauthenticated RCE on self-managed GitLab CE/EE, in every release since 7.0.',
            chain_title='Attack path', risk=(3, 5), area=None,
            conf=[('Exploitation within 30 days', 'MODERATE')],
            chain=[('Crafted regex reaches the GitLab server', 'T1190'),
                   ("Integer overflow in Ruby's Onigmo engine", 'CVE-2026-110264'),
                   ('Code runs as the git user', 'T1059.004'),
                   ('Source code and CI secrets exposed', 'T1213.003')]),
    13: dict(file=F25, title='LiteLLM 1.107.0: an AI gateway turned credential thief', hunt=(5, 'hunt-drop-05-litellm-startup-hook'),
             sub='A poisoned LiteLLM release ran on every Python start, with no import needed.',
             chain_title='Attack chain', risk=(2, 5), area=None,
             conf=[('Activity', 'HIGH'), ('Actor attribution', 'NONE (unnamed)')],
             chain=[('Leaked key leads to maintainer GitHub tokens', '10-12 Oct'),
                    ('Hijacked release: litellm 1.107.0', 'T1195.001'),
                    ('Startup hook: cook.pth / sitecustomize.py', 'T1546.018'),
                    ('Harvest cloud, AI and CI/CD secrets', 'T1552.001, T1552.005'),
                    ('Encrypted POST and GitHub dead-drop loader', 'T1102.001')]),
    14: dict(file=F25, title='PHP2Shell, week one: a Mirai botnet joins the rush',
             sub='Follow-up to Intel Drop 05: millions of attempts, no confirmed compromise yet.',
             chain_title='Attempted chain (as reported)', risk=(3, 4), area=None,
             conf=[('Mass exploit attempts', 'HIGH'), ('Botnet infections via PHP', 'LOW')],
             chain=[('Upload-progress request, CVE-2026-109618/9', 'T1190'),
                    ('Dropper: wget .../s | sh', 'T1059.004'),
                    ('Bot fetched to /tmp/nfs (Potassium)', 'T1105'),
                    ('24 DDoS flood vectors (Mirai fork)', 'T1498'),
                    ('New PHP session flaw CVE-2026-115560', 'Mitigate')]),
    15: dict(file=None, title="Fake 'IT Support' on Microsoft Teams", hunt=(6, 'hunt-drop-06-teams-fake-it-support'),
             sub='400+ incidents analysed: Teams chat, then vishing, then remote-management tools, with a payload in under 15 minutes.',
             chain_title='Attack chain', risk=(4, 4), area=None,
             conf=[('Activity', 'HIGH'), ('Named group', 'LOW')],
             chain=[('400+ incidents analysed', ''), ('Teams chat, then vishing, then RMM', ''),
                    ('Payload in under 15 minutes', '')],
             sources=['Arctic Wolf: <https://arcticwolf.com/resources/blog/threat-actors-abuse-microsoft-teams-external-chat-for-initial-access/>']),
    16: dict(file=None, title='AI pentest tool turned extortion engine',
             sub='ARTEX AI hit about 60 firms in 44 days and about 90 Korean organisations lost 8.2M records.',
             chain_title='Case facts', risk=(3, 4), area=None, actor='ARTEX',
             conf=[('Case facts', 'HIGH'), ('Bank-hack link', 'LOW')],
             chain=[('About 90 Korean organisations, 8.2M records', ''), ('ARTEX AI: about 60 firms in 44 days', ''),
                    ('38 extortion demands', '')]),
    20: dict(file=F29, title='HTTP2Shell: one Brotli bug, many stacks, now exploited',
             sub='CVE-2026-111497 was added to the CISA Known Exploited Vulnerabilities catalogue on 27 Oct 2026.',
             chain_title='Where the bug hides', risk=(4, 4), area=None,
             conf=[('Vulnerability impact', 'HIGH'), ('In-the-wild exploitation', 'MODERATE'),
                   ('Exploitation of named vendors', 'NOT CONFIRMED')],
             chain=[('Web runtimes and libraries: Node.js, Python brotli, Bun, Express 5', 'T1190'),
                    ('Proxies and service mesh: Envoy, Istio with Brotli decompression', ''),
                    ('Vendor products: .NET (opt-in), PAN-OS 12.2/12.1/11.2, SDDC Manager', ''),
                    ('Crash, restart, retry: failed attempts crash the service and restarts allow retries', '')]),
    21: dict(file=F29, title='Oracle EBS CVE-2026-101767: probed a week after patch', hunt=(7, 'hunt-drop-07-oracle-ebs-tcf-rce'),
             sub='Unauthenticated SQL injection to RCE in EBS 12.2.3 to 12.2.15 (CVSS 9.8). Patched 20 Oct.',
             chain_title='Timeline and attack path', risk=(3, 5), area=None,
             conf=[('Vulnerability and impact', 'HIGH'), ('Probing in the wild', 'MODERATE'),
                   ('Successful exploitation', 'NOT REPORTED')],
             chain=[('20 Oct: Oracle CPU patch, and Horizon3 publishes its advisory the same day', ''),
                    ('27 Oct: decoys probed with exploratory attempts and no confirmed breach', ''),
                    ('Unauthenticated SQL injection: POST to the TCF servlet, SQL as the APPS user', 'T1190'),
                    ('OS commands on the app server: the oracle account spawns a shell', 'T1059.004')]),
    22: dict(file=F29, title='Telegram sticker claims: confirmed vs unverified',
             sub='A conference talk claims a zero-click iOS chain through the rlottie sticker renderer.',
             chain_title='Fact check', risk=(2, 4), area=None,
             conf=[('rlottie bug class', 'HIGH'), ('Claimed iOS zero-click chain', 'LOW'),
                   ('In-the-wild exploitation', 'NOT REPORTED')],
             chain=[('CONFIRMED: rlottie flaw CVE-2026-111105, published 15 Oct, CVSS 7.0, no fix listed', ''),
                    ('CLAIMED: zero-click iOS chain, from the talk abstract only with no code or versions', ''),
                    ('DISPUTED: server-side checks. Telegram says validation blocks bad stickers', ''),
                    ('SEPARATE: 269-byte crash sticker, a September denial of service and not code execution', '')]),
    23: dict(file=None, title="North Korea's TraderTraitor drains $6.3B from Binance", actor='TraderTraitor',
             sub="No key theft was found: Binance's own signer was made to sign.",
             intro=("On 29 Oct, Binance hot wallets across about ten blockchains were emptied, most of it in roughly 20 minutes. "
                    "The FBI attributed it to North Korea on 31 Oct. No private-key theft has been found: analysts assess the "
                    "attacker made Binance's own signing system sign, including 50 pre-signed EIP-7702 authorisations. "
                    "Binance's preliminary view points to a compromised DevOps engineer's laptop."),
             business="Both this attack and Intel Drop 24 went after engineers: their laptops and their tools sit one step away from money, code and cloud.",
             todo=['Treat DevOps and developer endpoints as tier-0.', 'Gate signing services with independent approval.'],
             chain_title='How it unfolded (UTC)', risk=(4, 5), area='GCC crypto exchanges and VASPs',
             conf=[('Theft activity', 'HIGH'), ('North Korea link', 'HIGH'), ('Root cause', 'LOW (no post-mortem)')],
             chain=[('28 Oct: operator wallet funded via Tornado Cash withdrawals', ''),
                    ('29 Oct: attack code deployed, tested and rehearsed on 3 wallets', ''),
                    ('29 Oct 20:05: hot-wallet drains begin, and most moved in about 20 minutes', ''),
                    ('29 Oct 20:20: 50 pre-signed EIP-7702 authorisations seize the ETH wallet', ''),
                    ('31 Oct: the FBI attributes the theft to North Korea (TraderTraitor)', '')],
             src_lines=(1, 6)),
    24: dict(file=None, title='Trojanised Claude Code extension plants SSH backdoors via Cursor', hunt=(8, 'hunt-drop-08-claude-code-extension'),
             sub='Tampered builds were live for about 11 hours on 29 Oct, on Windows and macOS.',
             intro=("For about 11 hours on 29 Oct, tampered builds 2.1.312 and 2.1.313 ran on load, added an attacker SSH key "
                    "(\"svc-telemetry\"), opened reverse SSH tunnels and persisted via a \"SysMon\" task or an Apple-named LaunchAgent. "
                    "The actor is unknown."),
             business="The attack went after engineers: their laptops and their tools sit one step away from money, code and cloud.",
             todo=['Check authorized_keys for "svc-telemetry" and rotate exposed credentials.', 'Allow-list and pin IDE extensions.'],
             chain_title='Attack chain', risk=(3, 4), area='organisations with developers using Cursor',
             conf=[('Malicious activity', 'HIGH'), ('Actor attribution', 'NONE (unknown)'), ('Delivery path', 'LOW (unexplained)')],
             chain=[('Tampered v2.1.312 / 2.1.313 served by the marketplace', 'T1195.002'),
                    ('Runs on load and profiles the host, Git email and env-var names', 'T1082'),
                    ('Adds the "svc-telemetry" key to authorized_keys', 'T1098.004'),
                    ('Reverse SSH tunnel to the attacker host, retrying about every 60 s', 'T1572'),
                    ('Persists as a "SysMon" task or a fake Apple LaunchAgent', 'T1053.005, T1543.001')],
             src_lines=(7, 10)),
}


def rating(score):
    return 'LOW' if score <= 4 else 'MEDIUM' if score <= 9 else 'HIGH' if score <= 14 else 'CRITICAL'


def read(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read().replace('\r\n', '\n')


def sanitise(text):
    for old, new in PHRASES.items():
        text = text.replace(old, new)
    for m in re.finditer(r'.{0,50}(?<![A-Za-z])clients?(?![A-Za-z]).{0,50}', text, flags=re.I):
        print('  REVIEW client ->', m.group(0))
    return text


def section(md, drop):
    start = re.search(r'^#{1,2} .*INTEL DROP #%02d\s*[|—:-]' % drop, md, re.M | re.I)
    if not start:
        return None
    rest = md[start.end():]
    end = re.search(r'^#{1,2} (?:.*INTEL DROP #\d+\s*[|—:-]|COMBINED|OPTIONAL COMBINED|Source-validation|Near-misses)',
                    rest, re.M | re.I)
    return rest[:end.start()] if end else rest


def first_fence_after(text, heading_re, allow_quote=False):
    m = re.search(heading_re, text, re.I | re.M)
    if not m:
        return None
    after = text[m.end():]
    b = re.search(FENCE + r'[^\n]*\n(.*?)' + FENCE, after, re.S)
    q = re.search(r'^>[^\n]*(?:\n>[^\n]*)*', after, re.M) if allow_quote else None  # post as a block quote
    if q and (not b or q.start() < b.start()):
        return '\n'.join(re.sub(r'^>\s?', '', l) for l in q.group(0).split('\n')).strip()
    return b.group(1).rstrip() if b else None


def split_post(post):
    """Return (intro, business, todo_lines) from a LinkedIn post body."""
    lines = [l.rstrip() for l in post.split('\n')]
    lines = [l for l in lines[1:] if not re.match(r'^(#\w+\s*)+$', l.strip())]
    text = '\n'.join(lines).strip()
    m_b = re.search(r'^BUSINESS RISK\s*$', text, re.M)
    m_t = re.search(r'^WHAT TO DO NOW\s*$', text, re.M)
    intro = text[:m_b.start()].strip() if m_b else text
    business = text[m_b.end():m_t.start()].strip() if m_b and m_t else ''
    todo = text[m_t.end():].strip() if m_t else ''
    business = '\n'.join(l for l in business.split('\n') if not l.startswith('Risk score'))
    return intro, business.strip(), todo


def sources_from(block):
    out = []
    for line in block.split('\n'):
        m = re.match(r'^\s*\d+\.\s+(.*?):\s+(https?://\S+)\s*$', line)
        if m:
            out.append('%s: <%s>' % (m.group(1), m.group(2)))
    return out


def build(drop):
    meta = META[drop]
    intro = business = ''
    todo_lines = []
    sources = list(meta.get('sources', []))
    if meta.get('file'):
        sec = section(read(os.path.join(SRC, meta['file'])), drop)
        if not sec:
            raise SystemExit('Drop %d: section not found' % drop)
        post = first_fence_after(sec, r'^#+ .*Draft LinkedIn post', allow_quote=True)
        if not post:
            raise SystemExit('Drop %d: no post block' % drop)
        intro, business, todo = split_post(post)
        todo_lines = [re.sub(r'^\d+\.\s*', '', l).strip() for l in todo.split('\n') if l.strip()]
        block = first_fence_after(sec, r'^#+ .*Comment-ready sources')
        if block:
            sources = sources_from(block)
        else:  # numbered "[title](url) - Publisher - date" lines in a Sources section
            sm = re.search(r'^#+ Sources[^\n]*\n(.*?)(?=^#+ |\Z)', sec, re.S | re.M)
            for line in (sm.group(1) if sm else '').split('\n'):
                m = re.match(r'^\d+\.\s+\[[^\]]*\]\(([^)]+)\)\s+—\s+([^—]+?)\s+—\s+([^—]+?)\s+—', line)
                if m:
                    sources.append('%s (%s): <%s>' % (m.group(2), m.group(3), m.group(1)))
        for i in sorted(meta.get('drop_sources', []), reverse=True):
            if 0 < i <= len(sources):
                del sources[i - 1]
    else:
        intro = meta.get('intro', '')
        business = meta.get('business', '')
        todo_lines = meta.get('todo', [])
        if meta.get('src_lines'):
            comb = read(os.path.join(SRC, 'intel-drop-23-24-combined-post-2026-11-01.txt'))
            lo, hi = meta['src_lines']
            for line in comb.split('\n'):
                m = re.match(r'^(\d+)\.\s+(.*?):\s+(https?://\S+)\s*$', line.strip())
                if m and lo <= int(m.group(1)) <= hi:
                    sources.append('%s: <%s>' % (m.group(2), m.group(3)))

    existing = (glob.glob(os.path.join(INTEL, 'intel-drop-%02d-*.md' % drop)) or [None])[0]
    if not existing:
        raise SystemExit('Drop %d: no existing page to update' % drop)
    old = read(existing)
    date = re.search(r'^date:\s*(.+)$', old, re.M).group(1).strip()
    linked = re.search(r'^linkedinUrl:.*$', old, re.M)

    likelihood, impact = meta['risk']
    score = likelihood * impact
    attack = []
    for _, ids in meta['chain']:
        for t in re.findall(r'\bT\d{4}(?:\.\d{3})?\b', ids):
            if t not in attack:
                attack.append(t)

    for t in meta.get('attack_ids', []):
        if t not in attack:
            attack.append(t)

    body = []
    if intro:
        body.append(intro)
    if meta.get('hunt'):
        body.append('Companion hunt: [Hunt Drop %d](/hunting/%s/).' % meta['hunt'])
    body.append('## %s\n\n' % meta['chain_title'] + '\n'.join(
        '%d. %s%s' % (i, text, (' (%s)' % ids) if ids else '') for i, (text, ids) in enumerate(meta['chain'], 1)))
    if meta.get('extra'):
        body.append(meta['extra'])
    where = (', ' + meta['area']) if meta.get('area') else ''
    body.append('## Risk\n\n**%d/25 %s** (likelihood %d × impact %d)%s.' % (score, rating(score), likelihood, impact, where))
    body.append('## Confidence\n\n| Assessment | Confidence |\n|---|---|\n' + '\n'.join('| %s | %s |' % c for c in meta['conf']))
    if business:
        body.append('## Business risk\n\n' + business)
    if todo_lines:
        body.append('## What to do now\n\n' + '\n'.join('- ' + t for t in todo_lines))
    if sources:
        body.append('## Sources\n\n' + '\n'.join('%d. %s' % (i, s) for i, s in enumerate(sources, 1)))

    title = 'Intel Drop %02d | %s' % (drop, meta['title'])
    fm = ['---', 'title: "%s"' % title.replace('"', '\\"'), 'type: intel-drop', 'drop: %d' % drop]
    if meta.get('actor'):
        fm.append('actor: %s' % meta['actor'].replace(', ', ' and '))
    fm += ['attack: [%s]' % ', '.join(attack),
           'risk: { likelihood: %d, impact: %d }' % (likelihood, impact), 'tlp: CLEAR',
           'summary: "%s"' % meta['sub'].replace('"', '\\"'), 'date: %s' % date]
    if linked:
        fm.append(linked.group(0))
    fm += ['---', '']
    out = sanitise('\n'.join(fm) + '\n' + '\n\n'.join(body) + '\n')
    with open(existing, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out)
    print('Drop %02d: %s attack=%d sources=%d' % (drop, os.path.basename(existing), len(attack), len(sources)))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    SRC = sys.argv[1]
    for d in ([int(a) for a in sys.argv[2:]] or sorted(META)):
        build(d)
