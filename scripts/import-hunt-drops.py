#!/usr/bin/env python3
"""Rebuild Hunt Drop pages from a folder of source drafts.

Usage:  python scripts/import-hunt-drops.py <source-folder> [drop numbers...]

Reads, per drop NN, from the source folder:
  hunt-drop-NN-*.md            the LinkedIn post (first fenced block after the "LinkedIn post" heading),
                               the sources table, and (09) the appendix queries
  hunt-drop-NN-defender.kql    full Defender KQL        (optional)
  hunt-drop-NN-falcon-cql.txt  full CrowdStrike CQL     (optional)
Only publishable parts are copied. Working notes, review checklists and caveat
sections stay in the source folder. Add new drops to META below and re-run.
"""
import glob
import os
import re
import sys

SITE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HUNTS = os.path.join(SITE, 'src', 'content', 'hunts')
INTEL = os.path.join(SITE, 'src', 'content', 'intel')
SRC = ''

# Facts read from the published graphics (title, hypothesis, risk, confidence).
META = {
    1:  dict(date='2026-10-21', title='ROMULUS ClickFix: hunt the paste-to-loader chain', intel=None,
             hyp='Run-box PowerShell leads to a silent MSI or passworded 7-Zip, then a loader on the host.',
             risk=(3, 4), conf=('HIGH', 'MEDIUM'),
             ds=['Process events', 'Image-load events', 'File events', 'Registry events']),
    2:  dict(date=None, title='PHP2Shell: hunt PHP workers gone rogue', intel=5,
             hyp='A PHP web worker has been turned into a shell on the host.',
             risk=(4, 5), conf=('', ''), conf_text='Hunt logic sourced: HIGH.',
             kql_file='hunt-drop-02-php2shell.kql', cql_file='hunt-drop-02-php2shell.cql',
             sources_from_comment=True, post_heading='## The nine hunts\n\n',
             attack=['T1059.004', 'T1059', 'T1033', 'T1505.003', 'T1071', 'T1053.003'],
             ds=['Web server and PHP worker process events', 'File events', 'Network events']),
    3:  dict(date='2026-10-23', title="When your MSP's app becomes the attacker", intel=10,
             hyp='A stolen app credential signs in app-only, then grants itself roles and credentials.',
             risk=(3, 5), conf=('HIGH', 'MEDIUM'),
             ds=['Service-principal and user sign-ins', 'Graph API audit', 'OAuth app inventory', 'Azure audit']),
    4:  dict(date='2026-10-23', title='Hiding in plain System32', intel=11,
             hyp='Trusted software spawns a LOLBin host, then a renamed Windows binary side-loads a DLL.',
             risk=(1, 4), conf=('HIGH', 'MEDIUM-HIGH'),
             ds=['Process events', 'Image-load events', 'File events', 'Network and DNS events']),
    5:  dict(date='2026-10-26', title='Hunting the LiteLLM 1.107.0 startup-hook stealer', intel=13,
             hyp='Python itself runs the stealer on every start.',
             risk=(2, 5), conf=('HIGH', 'MEDIUM-HIGH'),
             ds=['Process events', 'File events', 'Network events']),
    6:  dict(date='2026-10-28', title='Fake "IT Support" in Teams', intel=15,
             hyp='An IT-desk chat becomes a remote session and a stager in under 30 minutes.',
             risk=(4, 4), conf=('HIGH', 'MEDIUM'),
             ds=['Teams chats', 'Email events', 'Endpoint process and network events']),
    7:  dict(date='2026-10-30', title='Oracle EBS: hunting the TCF servlet RCE', intel=21,
             hyp='An EBS Java process or app account starts a shell.',
             risk=(3, 5), conf=('MODERATE (flaw); LOW (exploitation: decoys only)', 'MEDIUM'),
             ds=['Linux EDR process, file and network events']),
    8:  dict(date='2026-11-02', title='Trojanised Claude Code extension: hunt the reverse SSH backdoor', intel=24,
             hyp='An editor loader plants an SSH key and a reverse tunnel.',
             risk=(3, 4), conf=('HIGH', 'MEDIUM'),
             ds=['Endpoint process and file events']),
    9:  dict(date='2026-11-04', title='LLMJacking: find the hijacked AI before the bill does', intel=26,
             hyp='A stolen cloud identity is reselling our AI quota.',
             risk=(3, 4), conf=('HIGH', 'MEDIUM'),
             ds=['AWS CloudTrail', 'EDR']),
}
# Drops 03/04 share one combined sources file; keep only the entries each one cites.
SOURCES_FROM_COMBINED = {3: [1, 2, 6, 7], 4: [3, 4, 5, 7]}
# Drops whose queries are LinkedIn comment blocks in the .md instead of separate files.
QUERIES_FROM_COMMENTS = {3, 4}

# Schema and syntax references used only to validate queries are not sources of the intel.
REFERENCE_DOC = re.compile(
    r'advanced-hunting|library\.humio\.com|pysigma|LogScale|CrowdStrike Query Language|/schema', re.I)
FENCE = '`' * 3
# Reviewed rewordings: keeps customer-of-an-MSP wording off the public site.
PHRASES = {
    'scripted clients': 'scripted tooling',
    'across client estates': 'across your estates',
    'MSP client access': 'downstream MSP access',
}


def rating(score):
    return 'LOW' if score <= 4 else 'MEDIUM' if score <= 9 else 'HIGH' if score <= 14 else 'CRITICAL'


def sanitise(text):
    """No automatic rewriting ('clients' can be a technical term, e.g. HTTP clients).
    Only the reviewed phrases below are reworded; any other hit is reported."""
    for old, new in PHRASES.items():
        text = text.replace(old, new)
    for m in re.finditer(r'.{0,50}(?<![A-Za-z])clients?(?![A-Za-z]).{0,50}', text, flags=re.I):
        print("  REVIEW client ->", m.group(0))
    return text


def read(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read().replace('\r\n', '\n')


def fenced_after(md, heading_re, nth=0):
    m = re.search(heading_re, md, re.I | re.M)
    if not m:
        return None
    blocks = re.findall(FENCE + r'[^\n]*\n(.*?)' + FENCE, md[m.end():], re.S)
    return blocks[nth].rstrip() if len(blocks) > nth else None


def comment_blocks(md):
    pat = r'^###\s*Comment \d[^\n]*\n(?:(?!' + FENCE + r')[^\n]*\n)*' + FENCE + r'[^\n]*\n(.*?)' + FENCE
    return re.findall(pat, md, re.S | re.M)


def post_to_markdown(post):
    out = []
    for i, line in enumerate(l.rstrip() for l in post.split('\n')):
        if i < 3 and (re.match(r'HUNT DROP', line, re.I) or re.match(r'Builds on', line, re.I)):
            continue
        if re.match(r'^(#\w+\s*)+$', line.strip()):
            continue
        if re.search(r'queries are in the comments|queries in the comments', line, re.I):
            continue
        line = re.sub(r'^[•▪]\s*', '- ', line)
        m = re.match(r'^(THE HYPOTHESIS):\s*(.*)$', line)
        if m:
            out.append('## The hypothesis')
            out.append(m.group(2))
            continue
        if (line == line.upper() and re.match(r'^[A-Z][A-Z &/\'’-]{3,39}$', line)
                and not line.startswith('- ')):
            out.append('## ' + line.strip().capitalize())
            continue
        out.append(line)
    text = re.sub(r'\n{3,}', '\n\n', '\n'.join(out)).strip()
    return sanitise(text)


def parse_sources(md, drop):
    out = []
    if drop in SOURCES_FROM_COMBINED:
        comb = read(os.path.join(SRC, 'hunt-drop-03-04-combined-sources.txt'))
        keep = SOURCES_FROM_COMBINED[drop]
        for line in comb.split('\n'):
            m = re.match(r'^(\d+)\.\s+(.*)$', line.strip())
            if m and int(m.group(1)) in keep:
                out.append(m.group(2))
        return [o for o in out if not REFERENCE_DOC.search(o)]
    sec = re.search(r'^##\s*\d*\.?\s*Sources[^\n]*\n(.*?)(?=^##\s|\Z)', md, re.S | re.M | re.I)
    if not sec:
        return out
    for line in sec.group(1).split('\n'):
        m = re.match(r'^\|\s*\d+\s*\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*([^|]*)\|\s*([^|]*)\|', line)
        if m:
            title, url, pub, date = (x.strip() for x in m.groups())
            out.append(f'{pub} ({date}): <{url}>')
            continue
        m = re.match(r'^\s*(?:\d+\.|-)\s+(.*https?://\S+.*)$', line)
        if m:
            txt = m.group(1).strip()
            ml = re.match(r'\[([^\]]+)\]\(([^)]+)\)\s*(?:·\s*([^·]+))?', txt)
            if ml:
                title, url, pub = ml.group(1), ml.group(2), (ml.group(3) or '').strip()
                out.append((pub + ': ' if pub else '') + title + ' <' + url + '>')
            else:
                out.append(txt)
    return [o for o in out if not REFERENCE_DOC.search(o)]


def tidy_query(q):
    if not q:
        return q
    lines = q.split('\n')
    if not lines[0].lstrip().startswith(('//', '#')) and 'UNTESTED' in lines[0].upper():
        lines[0] = '// ' + lines[0]
    return '\n'.join(lines)


def build(drop):
    meta = META[drop]
    md_path = (glob.glob(os.path.join(SRC, 'hunt-drop-%02d-20*.md' % drop)) or [None])[0]
    kit = os.path.join(SRC, 'hunt-drop-%02d-linkedin-posting-kit.md' % drop)
    md = read(md_path) if md_path else read(kit)
    post = fenced_after(md, r'^##\s*\d*\.?\s*(?:Draft )?LinkedIn post')
    if not post:
        raise SystemExit('Drop %d: no LinkedIn post block found' % drop)

    kql = cql = None
    kf = os.path.join(SRC, meta.get('kql_file', 'hunt-drop-%02d-defender.kql' % drop))
    cf = os.path.join(SRC, meta.get('cql_file', 'hunt-drop-%02d-falcon-cql.txt' % drop))
    if os.path.exists(kf):
        kql = read(kf).strip()
    if os.path.exists(cf):
        cql = read(cf).strip()
    if drop in QUERIES_FROM_COMMENTS:
        cb = comment_blocks(md)
        kql = kql or (cb[0].strip() if len(cb) > 0 else None)
        cql = cql or (cb[1].strip() if len(cb) > 1 else None)
    if drop == 9:
        kql = kql or fenced_after(md, r'^##\s*Appendix A')
        cql = cql or fenced_after(md, r'^##\s*Appendix B')
    if drop == 1:
        cb = comment_blocks(read(kit))
        if len(cb) >= 4 and not cql:
            cql = cb[2].strip() + '\n\n' + cb[3].strip()
    kql, cql = tidy_query(kql), tidy_query(cql)

    attack = []
    for t in re.findall(r'\bT\d{4}(?:\.\d{3})?\b', post):
        if t not in attack:
            attack.append(t)
    attack = meta.get('attack') or attack
    likelihood, impact = meta['risk']
    score = likelihood * impact

    body = []
    if meta['intel']:
        found = (glob.glob(os.path.join(INTEL, 'intel-drop-%02d-*.md' % meta['intel'])) or [None])[0]
        if found:
            sid = os.path.splitext(os.path.basename(found))[0]
            body.append('Builds on [Intel Drop %d](/intel/%s/).' % (meta['intel'], sid))
        else:
            body.append('Builds on Intel Drop %d.' % meta['intel'])
    body.append(meta.get('post_heading', '') + post_to_markdown(post))
    conf_text = meta.get('conf_text') or ('Intel confidence: %s. Detection fidelity: %s.'
                                          % (meta['conf'][0], meta['conf'][1]))
    body.append('**Risk: %d/25 %s** (likelihood %d × impact %d, analyst judgement). %s'
                % (score, rating(score), likelihood, impact, conf_text))
    langs = []
    if kql:
        langs.append('KQL')
        body.append('## Microsoft Defender (KQL)\n\n' + FENCE + 'kusto\n' + kql + '\n' + FENCE)
    if cql:
        langs.append('CQL')
        body.append('## CrowdStrike Falcon (CQL)\n\n' + FENCE + '\n' + cql + '\n' + FENCE)
    body.append('Queries are untested: tune before use.')

    srcs = parse_sources(md, drop)
    if meta.get('sources_from_comment'):
        block = fenced_after(md, r'^#+\s*Comment-ready sources')
        srcs = []
        for line in (block or '').split('\n'):
            m = re.match(r'^\s*\d+\.\s+(.*?):\s+(https?://\S+)\s*$', line)
            if m:
                srcs.append('%s: <%s>' % (m.group(1), m.group(2)))
    if not srcs and drop == 1:
        last = comment_blocks(read(kit))[-1]
        for line in last.split('\n'):
            m = re.match(r'^\d+\.\s+(.*)$', line.strip())
            if m:
                srcs.append(m.group(1))
        srcs = [x for x in srcs if not REFERENCE_DOC.search(x)]
    if srcs:
        body.append('## Sources\n\n' + '\n'.join('%d. %s' % (i, sanitise(s)) for i, s in enumerate(srcs, 1)))

    safe_title = meta['title'].replace('"', '\\"')
    fm = ['---',
          'title: "Hunt Drop %02d | %s"' % (drop, safe_title),
          'hypothesis: "%s"' % meta['hyp'],
          'attack: [%s]' % ', '.join(attack),
          'dataSources: [%s]' % ', '.join('"%s"' % d for d in meta['ds']),
          'languages: [%s]' % ', '.join(langs),
          'drop: %d' % drop,
          'risk: { likelihood: %d, impact: %d }' % (likelihood, impact)]
    existing = (glob.glob(os.path.join(HUNTS, 'hunt-drop-%02d-*.md' % drop)) or [None])[0]
    if existing:
        m = re.search(r'^linkedinUrl:.*$', read(existing), re.M)
        if m:
            fm.append(m.group(0))
    date = meta['date']
    if not date and existing:
        date = re.search(r'^date:\s*(.+)$', read(existing), re.M).group(1).strip()
    fm += ['status: published', 'date: %s' % date, '---', '']
    out = '\n'.join(fm) + '\n' + '\n\n'.join(body) + '\n'
    for old, new in PHRASES.items():
        out = out.replace(old, new)
    if not existing:
        slug =re.sub(r'[^a-z0-9]+', '-', meta['title'].lower()).strip('-')[:40]
        existing = os.path.join(HUNTS, 'hunt-drop-%02d-%s.md' % (drop, slug))
    with open(existing, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out)
    print('Drop %02d: %s attack=%d kql=%s cql=%s sources=%d'
          % (drop, os.path.basename(existing), len(attack), bool(kql), bool(cql), len(srcs)))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    SRC = sys.argv[1]
    for d in ([int(a) for a in sys.argv[2:]] or sorted(META)):
        build(d)
