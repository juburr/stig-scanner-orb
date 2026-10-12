"""Which DISA release does an SSG datastream's stig profile match?"""
import sys, re, glob, os, xml.etree.ElementTree as ET
X='{http://checklists.nist.gov/xccdf/1.2}'; X11='{http://checklists.nist.gov/xccdf/1.1}'
ds, pattern = sys.argv[1], sys.argv[2]
root = ET.parse(ds).getroot()
bench = next(root.iter(X+'Benchmark'))
prof = [p for p in bench.iter(X+'Profile') if p.get('id').endswith('_profile_stig')][0]
sel = set()
for s in prof.findall(X+'select'):
    (sel.add if s.get('selected') == 'true' else sel.discard)(s.get('idref'))
svs = {x.text.strip() for r in bench.iter(X+'Rule') if r.get('id') in sel for x in r.findall(X+'reference') if x.get('href') == 'https://www.cyber.mil/stigs/srg-stig-tools/'}
label = re.search(r'V\d+R\d+', ''.join(prof.find(X+'title').itertext()) + ' ' + ''.join(prof.find(X+'description').itertext())).group(0)
print(os.path.basename(ds), 'profile label', label, 'SV ids', len(svs))
for f in sorted(glob.glob(pattern)):
    d = ET.parse(f).getroot()
    ids = {r.get('id') for r in d.iter(X11+'Rule')}
    print(f'  {os.path.basename(f):50s} DISA rules {len(ids):4d}  SSG SV ids found {len(svs & ids):4d}  revision/unknown {len(svs - ids):4d}  DISA rules with no SSG {len(ids - svs):3d}')
