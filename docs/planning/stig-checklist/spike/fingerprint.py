"""Which DISA release does a pinned datastream's STIG profile match?

    fingerprint.py <results.xml> '<DISA manual xccdf glob>'

Takes a results.xml from a scan of the STIG profile, not the datastream:
OpenSCAP's own selection (every rule-result other than notselected) already
resolves profile extends, Rule/Group selected defaults and requires/conflicts
(4 of the RHEL 8/9 stig profile's explicit selects are deselected by
conflicts). Selection doesn't depend on the target, so a scan of any image
with the datastream and profile will do.
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

X = '{http://checklists.nist.gov/xccdf/1.2}'
X11 = '{http://checklists.nist.gov/xccdf/1.1}'
HREF = 'https://www.cyber.mil/stigs/srg-stig-tools/'

results, pattern = sys.argv[1], sys.argv[2]
root = ET.parse(results).getroot()
tr = next(root.iter(X + 'TestResult'), None)
if tr is None:
    sys.exit(f'{results}: no TestResult; pass a results.xml from a scan of the STIG profile')
bench = next(root.iter(X + 'Benchmark'))
pid = tr.find(X + 'profile').get('idref')
prof = next(p for p in bench.iter(X + 'Profile') if p.get('id') == pid)
sel = {rr.get('idref') for rr in tr.findall(X + 'rule-result') if (rr.findtext(X + 'result') or '').strip() != 'notselected'}
svs = {x.text.strip() for r in bench.iter(X + 'Rule') if r.get('id') in sel for x in r.findall(X + 'reference') if x.get('href') == HREF}
label = re.search(r'V\d+R\d+', ''.join(prof.find(X + 'title').itertext()) + ' ' + ''.join(prof.find(X + 'description').itertext()))
print(os.path.basename(results), pid.split('_profile_')[-1], 'profile label', label.group(0) if label else '?', 'selected rules', len(sel), 'SV ids', len(svs))
for f in sorted(glob.glob(pattern)):
    ids = {r.get('id') for r in ET.parse(f).getroot().iter(X11 + 'Rule')}
    print(f'  {os.path.basename(f):50s} DISA rules {len(ids):4d}  SSG SV ids found {len(svs & ids):4d}  revision/unknown {len(svs - ids):4d}  DISA rules with no SSG {len(ids - svs):3d}')
