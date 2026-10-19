"""Verify answer precedence/evidence in real CI artifacts and unchanged scan gates."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

out, path = map(Path, sys.argv[1:])
meta = json.loads((out / 'checklist-meta.json').read_text())
answers = meta['answers']
digest = hashlib.sha256(path.read_bytes()).hexdigest()
assert answers['file']['sha256'] == digest
assert answers['file_rows'] == answers['default_rows'] == 1
assert answers['category_rows'] > 0
assert answers['default_set']['name'] == 'container-host'
assert sum(answers['automatic_status'].values()) == meta['vulns'] == 445
rows = json.loads((out / 'checklist.cklb').read_text())['stigs'][0]['rules']
row = next(r for r in rows if r['group_id'] == 'V-257782')
assert row['status'] == 'open'
assert 'CI fixture:' in row['comments']
assert 'No scanner rule' in row['finding_details']
assert 'curated container-host sha256:' in row['finding_details']
assert 'result before answer: Not_Reviewed; final result: Not_Applicable' in row['finding_details']
assert 'result before answer: Not_Applicable; final result: Open' in row['finding_details']
assert digest in row['finding_details']
xml = ET.parse(out / 'checklist.ckl')
for r in xml.findall('.//VULN'):
    vid = next(d.findtext('ATTRIBUTE_DATA') for d in r.findall('STIG_DATA')
               if d.findtext('VULN_ATTRIBUTE') == 'Vuln_Num')
    match = next(x for x in rows if x['group_id'] == vid)
    assert r.findtext('COMMENTS', '') == match['comments']
    assert r.findtext('FINDING_DETAILS', '') == match['finding_details']
    assert digest in match['finding_details']
# Answers cannot waive scan findings. Test summarize with its real input,
# including fail_on, instead of inferring this from checklist counts.
before = {name: hashlib.sha256((out / name).read_bytes()).hexdigest()
          for name in ('results.xml', 'scan-plan.env', 'checklist.ckl', 'checklist.cklb')}
proc = subprocess.run(['bash', 'src/scripts/summarize.sh'], env={**os.environ,
    'PARAM_OUTPUT_DIR': str(out), 'PARAM_CHECKLIST': 'require', 'PARAM_FAIL_ON': 'info',
    'PARAM_DEFER_GATE': 'false', 'PARAM_IGNORE_FINDINGS': ''}, capture_output=True, text=True)
assert proc.returncode == 1, proc.stdout + proc.stderr
assert all(hashlib.sha256((out / name).read_bytes()).hexdigest() == value for name, value in before.items())
assert json.loads((out / 'provenance.json').read_text())['checklist']['answers'] == answers
print('Answer file/default precedence, both formats, provenance and independent finding gate verified')
