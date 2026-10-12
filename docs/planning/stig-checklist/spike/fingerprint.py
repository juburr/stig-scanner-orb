"""Spike helpers for D4.

    fingerprint.py <datastream> '<DISA manual xccdf glob>'
        Which DISA release does a datastream's stig profile match (SV ids)?
    fingerprint.py --content <datastream or results.xml>...
        The D4 content fingerprint, from the (embedded) benchmark.
"""
import glob
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET

X = '{http://checklists.nist.gov/xccdf/1.2}'
X11 = '{http://checklists.nist.gov/xccdf/1.1}'
HREF = 'https://www.cyber.mil/stigs/srg-stig-tools/'
STIG_PROFILE = re.compile(r'_profile_stig(_gui)?$')


def benchmark(path):
    root = ET.parse(path).getroot()
    return root if root.tag == X + 'Benchmark' else next(root.iter(X + 'Benchmark'))


def selected(prof):
    sel = set()
    for s in prof.findall(X + 'select'):
        (sel.add if s.get('selected') == 'true' else sel.discard)(s.get('idref'))
    return sel


def content_fingerprint(path):
    """sha256 over every rule -> SV reference pair plus the selection
    semantics (selects, refine-value, set-value, refine-rule) of *every*
    built-in profile the checklist accepts (D11: ..._stig and ..._stig_gui),
    so editing any accepted profile's selection changes it. External
    tailoring is not in the benchmark and is handled separately (PR 4)."""
    bench = benchmark(path)
    pairs = sorted({f"{r.get('id')} {x.text.strip()}" for r in bench.iter(X + 'Rule')
                    for x in r.findall(X + 'reference') if x.get('href') == HREF})
    lines = ['rule-sv ' + p for p in pairs]
    counts = {}
    for prof in sorted((p for p in bench.iter(X + 'Profile') if STIG_PROFILE.search(p.get('id'))), key=lambda p: p.get('id')):
        pid = prof.get('id')
        sel = selected(prof)
        lines += [f'select {pid} {r}' for r in sorted(sel)]
        lines += sorted(f"refine-value {pid} {e.get('idref')} {e.get('selector')}" for e in prof.findall(X + 'refine-value'))
        lines += sorted(f"set-value {pid} {e.get('idref')} {(e.text or '').strip()}" for e in prof.findall(X + 'set-value'))
        lines += sorted(f"refine-rule {pid} {e.get('idref')} " + ' '.join(f'{k}={v}' for k, v in sorted(e.attrib.items()) if k != 'idref')
                        for e in prof.findall(X + 'refine-rule'))
        counts[pid.split('_profile_')[1]] = len(sel)
    return len(pairs), counts, hashlib.sha256('\n'.join(lines).encode()).hexdigest()


def release_match(ds, pattern):
    bench = benchmark(ds)
    prof = [p for p in bench.iter(X + 'Profile') if p.get('id').endswith('_profile_stig')][0]
    sel = selected(prof)
    svs = {x.text.strip() for r in bench.iter(X + 'Rule') if r.get('id') in sel for x in r.findall(X + 'reference') if x.get('href') == HREF}
    label = re.search(r'V\d+R\d+', ''.join(prof.find(X + 'title').itertext()) + ' ' + ''.join(prof.find(X + 'description').itertext())).group(0)
    print(os.path.basename(ds), 'profile label', label, 'SV ids', len(svs))
    for f in sorted(glob.glob(pattern)):
        d = ET.parse(f).getroot()
        ids = {r.get('id') for r in d.iter(X11 + 'Rule')}
        print(f'  {os.path.basename(f):50s} DISA rules {len(ids):4d}  SSG SV ids found {len(svs & ids):4d}  revision/unknown {len(svs - ids):4d}  DISA rules with no SSG {len(ids - svs):3d}')


if __name__ == '__main__':
    if sys.argv[1] == '--content':
        for path in sys.argv[2:]:
            n, counts, digest = content_fingerprint(path)
            print(f'{path}: pairs {n}, selected {counts}, fingerprint {digest}')
    else:
        release_match(sys.argv[1], sys.argv[2])
