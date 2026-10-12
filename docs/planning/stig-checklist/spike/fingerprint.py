"""Which DISA release does a pinned datastream's STIG profile match?

    fingerprint.py <results.xml> '<DISA manual xccdf glob>' [--allow-unmapped rule[,rule...]]

Takes a results.xml from a scan of one accepted STIG profile, not the
datastream: OpenSCAP's own selection (every rule-result other than
notselected) already resolves profile extends, Rule/Group selected defaults
and requires/conflicts (4 of the RHEL 8/9 stig profile's explicit selects are
deselected by conflicts). Selection doesn't depend on the target, so a scan of
any image with the datastream and profile will do. Run it once per accepted
profile; every run must name the same release.

Exits 0 only when exactly one release contains every selected SV id, every
selected rule without a DISA reference is in --allow-unmapped (the known
helper rules, e.g. enable_authselect on RHEL 8/9), and no selected rule has an
unpaired V-ID/SV reference (the generator drops those, plan D3, so they would
vanish from a checklist labeled verified). Anything else is not a verified
match.
"""
import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

X = '{http://checklists.nist.gov/xccdf/1.2}'
X11 = '{http://checklists.nist.gov/xccdf/1.1}'
HREF = 'https://www.cyber.mil/stigs/srg-stig-tools/'
HREF_VULN = HREF.rstrip('/') + '#vulnerability_id'
RULE = 'xccdf_org.ssgproject.content_rule_'

ap = argparse.ArgumentParser()
ap.add_argument('results')
ap.add_argument('pattern')
ap.add_argument('--allow-unmapped', default='', help='comma-separated short rule ids known to have no DISA reference')
a = ap.parse_args()

root = ET.parse(a.results).getroot()
tr = next(root.iter(X + 'TestResult'), None)
if tr is None:
    sys.exit(f'{a.results}: no TestResult; pass a results.xml from a scan of the STIG profile')
bench = next(root.iter(X + 'Benchmark'))
pid = tr.find(X + 'profile').get('idref')
prof = next(p for p in bench.iter(X + 'Profile') if p.get('id') == pid)
sel = {rr.get('idref') for rr in tr.findall(X + 'rule-result') if (rr.findtext(X + 'result') or '').strip() != 'notselected'}
rules = {r.get('id'): r for r in bench.iter(X + 'Rule')}
svs_of = {rid: {x.text.strip() for x in rules[rid].findall(X + 'reference') if x.get('href') == HREF} for rid in sel if rid in rules}
svs = set().union(*svs_of.values())
unmapped = sorted(rid.replace(RULE, '') for rid, s in svs_of.items() if not s)
# The generator's pairing (D3): with any V-ID reference on a rule, only V-n/SV-n
# pairs of the same number become rows.
unpaired = []
for rid in svs_of:
    refs = {x.text.strip() for x in rules[rid].findall(X + 'reference') if x.get('href') == HREF_VULN}
    vids = {v[2:] for v in refs if re.fullmatch(r'V-\d+', v)}
    malformed = sorted(v for v in refs if not re.fullmatch(r'V-\d+', v))
    nums = {re.match(r'SV-(\d+)', sv).group(1) for sv in svs_of[rid] if re.match(r'SV-\d+', sv)}
    if refs and (malformed or vids != nums):
        unpaired.append(f"{rid.replace(RULE, '')}: V-{sorted(vids - nums)} SV-{sorted(nums - vids)} malformed {malformed}")
allowed = {r.strip() for r in a.allow_unmapped.split(',') if r.strip()}
label = re.search(r'V\d+R\d+', ''.join(prof.find(X + 'title').itertext()) + ' ' + ''.join(prof.find(X + 'description').itertext()))
print(os.path.basename(a.results), pid.split('_profile_')[-1], 'profile label', label.group(0) if label else '?',
      'selected rules', len(sel), 'SV ids', len(svs), 'unmapped', unmapped)
full = []
for f in sorted(glob.glob(a.pattern)):
    ids = {r.get('id') for r in ET.parse(f).getroot().iter(X11 + 'Rule')}
    print(f'  {os.path.basename(f):50s} DISA rules {len(ids):4d}  SSG SV ids found {len(svs & ids):4d}  revision/unknown {len(svs - ids):4d}  DISA rules with no SSG {len(ids - svs):3d}')
    if svs and svs <= ids:
        full.append(os.path.basename(f))
problems = [f'unpaired V-ID/SV references: {unpaired}'] if unpaired else []
if set(unmapped) - allowed:
    problems.append(f'selected rules without a DISA reference: {sorted(set(unmapped) - allowed)}')
if len(full) != 1:
    problems.append(f'{len(full)} releases contain every selected SV id: {full}' if full else 'no release contains every selected SV id')
if problems:
    print('NOT VERIFIED: ' + '; '.join(problems))
    sys.exit(1)
print(f'MATCH: {full[0]}')
