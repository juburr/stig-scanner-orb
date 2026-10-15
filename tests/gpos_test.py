"""Native vendor SRG identity, applicability, evidence and gate regressions."""

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import checklist_test as common
from checklist_test import MOD, H, X
from skeleton_test import skeleton

B = MOD['GPOS_BENCHMARK']
P = MOD['GPOS_PROFILE']
PREFIX = MOD['GPOS_RULE_PREFIX']


def vendor_fixture(results=('pass', 'notapplicable', 'fail', 'error')):
    root = common.fixture([(PREFIX + f'SV-{i}r1_rule', i, result,
                            ('cpe:/o:notapplicable',) if result == 'notapplicable' else (), [])
                           for i, result in enumerate(results, 1)], benchmark=B, profile=P)
    root.find(X + 'version').text = '3.2.17'
    for i, rule in enumerate(root.iter(X + 'Rule'), 1):
        ET.SubElement(rule, X + 'ident', system='http://cyber.mil/cci').text = f'CCI-{i:06}'
        # Repeated CCI is deduplicated; unrelated idents cannot become CCIs.
        ET.SubElement(rule, X + 'ident', system='http://cyber.mil/cci').text = f'CCI-{i:06}'
        ET.SubElement(rule, X + 'ident', system='https://example.test').text = 'CCI-999999'
    return root


class GposTests(unittest.TestCase):
    setUp = common.ChecklistTests.setUp
    prepare = common.ChecklistTests.prepare
    save_plan = common.ChecklistTests.save_plan
    generate = common.ChecklistTests.generate
    rows = common.ChecklistTests.rows
    summary = common.ChecklistTests.summary
    guard = common.ChecklistTests.guard

    def vendor(self, root=None):
        root = vendor_fixture() if root is None else root
        self.plan['profile'] = P
        self.plan['datastream'] = 'ssg-chainguard-gpos-ds.xml'
        self.prepare(root, register=False)
        res = MOD['parse_results'](io.BytesIO(ET.tostring(root)))
        self.entry = (B, '3.2.17', {P: MOD['selection_fingerprint'](res)},
                      ('3', 'Release: 2 Benchmark Date: 30 Jan 2025'),
                      {'kind': 'vendor-srg', 'evidence_sha256': MOD['vendor_evidence_fingerprint'](res),
                       'profiles': {P: {'vids': len(res['rules']), 'unmapped': []}}})
        return root

    def rewrite(self, root):
        self.prepare(root, register=False)

    def test_both_formats_identity_status_ccis_and_vendor_text(self):
        root = self.vendor()
        rc, meta = self.generate()
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['content_kind'], 'vendor-srg')
        self.assertEqual(meta['release_source'], 'table')
        self.assertIsNone(meta['bundle'])
        self.assertEqual(meta['stig']['benchmark_id'], 'General_Purpose_Operating_System')
        self.assertEqual(meta['status'], {'NotAFinding': 1, 'Not_Applicable': 1, 'Open': 1, 'Not_Reviewed': 1})
        self.assertEqual(meta['na_by_reason'], {'vendor': 1})
        for i, row in enumerate(self.rows(), 1):
            self.assertEqual(row['ccis'], [f'CCI-{i:06}'])
            self.assertEqual(row['rule_id_src'], f'SV-{i}r1_rule')
            self.assertIn('not a DISA OS STIG', row['finding_details'])
            self.assertEqual(row['discussion'], list(root.iter(X + 'Rule'))[i-1].findtext(X + 'description'))
        row = self.rows()[1]
        rationale = list(root.iter(X + 'Rule'))[1].findtext(X + 'rationale')
        self.assertIn(rationale, row['comments'])
        self.assertIn(rationale, row['finding_details'])
        self.assertIn('Chainguard vendor N/A rationale', row['comments'])
        self.assertIn('does not establish control inheritance', row['comments'])
        ckl = ET.parse(self.out / 'checklist.ckl')
        self.assertEqual(ckl.findall('.//VULN')[1].findtext('COMMENTS'), row['comments'])
        ccis = [e.findtext('ATTRIBUTE_DATA') for e in ckl.findall('.//VULN')[1].findall('STIG_DATA')
                if e.findtext('VULN_ATTRIBUTE') == 'CCI_REF']
        self.assertEqual(ccis, row['ccis'])
        self.assertEqual(self.guard(), 0)
        self.assertEqual(self.summary('require').returncode, 0)
        self.assertEqual(json.loads((self.out / 'provenance.json').read_text())['checklist']['content_kind'], 'vendor-srg')

    def test_unknown_hash_skips_even_with_a_skeleton_and_require_fails(self):
        self.vendor()
        self.assertEqual(self.generate()[0], 0)
        self.plan['datastream_sha256'] = '9' * 64
        self.save_plan()
        rc, meta = self.generate('--stig-xccdf-path=/unused')
        self.assertEqual(rc, 0)
        self.assertEqual(meta['outcome'], 'skipped')
        self.assertIn('exact verified pinned datastream', meta['reason'])
        self.assertFalse((self.out / 'checklist.ckl').exists())
        self.assertEqual(self.summary('auto').returncode, 0)
        self.assertNotEqual(self.summary('require').returncode, 0)

    def test_alternate_profile_is_not_admitted_by_rule_ids(self):
        root = self.vendor()
        other = 'xccdf_basic_profile_other'
        root.find(X + 'Profile').set('id', other)
        root.find(X + 'TestResult/' + X + 'profile').set('idref', other)
        self.plan['profile'] = other
        self.rewrite(root)
        self.assertEqual(self.generate()[1]['outcome'], 'skipped')

    def test_known_hash_different_benchmark_or_version_fails(self):
        for tag in ('benchmark', 'version'):
            with self.subTest(tag=tag):
                root = self.vendor()
                if tag == 'benchmark':
                    root.set('id', common.B)
                    root.find(X + 'Profile').set('id', common.P)
                    root.find(X + 'TestResult/' + X + 'profile').set('idref', common.P)
                    self.plan['profile'] = common.P
                else:
                    root.find(X + 'version').text = '3.2.18'
                self.rewrite(root)
                self.assertEqual(self.generate()[1]['outcome'], 'failed')

    def test_changed_rationale_cci_platform_text_and_severity_fail_closed(self):
        for field in ('rationale', 'ident', 'platform', 'description', 'title', 'severity'):
            with self.subTest(field=field):
                root = self.vendor()
                rule = list(root.iter(X + 'Rule'))[1]
                if field == 'severity':
                    rule.set('severity', 'low')
                elif field == 'platform':
                    rule.find(X + field).set('idref', 'cpe:/o:other')
                else:
                    rule.find(X + field).text = 'changed'
                self.rewrite(root)
                rc, meta = self.generate()
                self.assertEqual(rc, 1, meta)
                self.assertIn('metadata differs', meta['reason'])
                self.assertFalse((self.out / 'checklist.cklb').exists())

    def test_selection_change_fails_and_unevaluated_verdicts_remain_visible(self):
        root = self.vendor()
        root.find(X + 'TestResult/' + X + 'rule-result/' + X + 'result').text = 'notselected'
        self.rewrite(root)
        self.assertIn('selects', self.generate()[1]['reason'])
        self.vendor(vendor_fixture(('notchecked', 'unknown', 'informational', 'fixed')))
        rc, meta = self.generate()
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['status'], {'Not_Reviewed': 3, 'NotAFinding': 1})

    def test_native_id_must_be_complete_and_prefixed(self):
        for invalid in ('SV-1r1_rule', PREFIX + 'SV-1garbage', PREFIX + 'SV-1', PREFIX + 'SV-1r1_rule_extra'):
            with self.subTest(invalid=invalid):
                root = self.vendor()
                root.find('.//' + X + 'Rule').set('id', invalid)
                self.rewrite(root)
                self.assertIn('invalid Chainguard GPOS Rule id', self.generate()[1]['reason'])

    def test_missing_results_duplicate_rules_and_extra_references_fail(self):
        for fault in ('missing', 'duplicate', 'reference'):
            with self.subTest(fault=fault):
                root = self.vendor()
                rule = root.find('.//' + X + 'Rule')
                if fault == 'missing':
                    tr = root.find(X + 'TestResult')
                    tr.remove(tr.find(X + 'rule-result'))
                elif fault == 'duplicate':
                    root.append(copy.deepcopy(rule))
                else:
                    ET.SubElement(rule, X + 'reference', href=MOD['HREF_RULE']).text = 'SV-999r1_rule'
                self.rewrite(root)
                self.assertEqual(self.generate()[1]['outcome'], 'failed')

    def test_missing_rationale_and_invalid_ccis_cannot_generate(self):
        for fault in ('rationale', 'cci', 'no-cci'):
            with self.subTest(fault=fault):
                root = vendor_fixture()
                rule = list(root.iter(X + 'Rule'))[1]
                if fault == 'rationale':
                    rule.remove(rule.find(X + 'rationale'))
                elif fault == 'cci':
                    rule.find(X + 'ident').text = 'CCI-invalid'
                else:
                    for el in rule.findall(X + 'ident'):
                        rule.remove(el)
                self.vendor(root)  # Register even this invalid metadata: structural guards still apply.
                self.assertEqual(self.generate()[1]['outcome'], 'failed')

    def test_rootfs_requires_name_and_does_not_claim_verified_deployment(self):
        self.vendor()
        for k in ('image', 'image_id', 'image_platform'):
            self.plan.pop(k)
        self.plan['rootfs_path'] = '/mnt/disk'
        self.save_plan()
        self.assertEqual(self.generate()[1]['outcome'], 'skipped')
        rc, meta = self.generate('--host-name=mounted-disk')
        self.assertEqual(rc, 0, meta)
        self.assertIn('not verified deployment conditions', self.rows()[1]['finding_details'])
        self.assertIn('intended deployment', self.rows()[1]['comments'])

    def test_supplied_reference_revisions_do_not_borrow_vendor_verdict(self):
        self.vendor(vendor_fixture(('notapplicable', 'pass')))
        for revision in (1, 2):
            sk = skeleton(revision=revision)
            sk.set('id', MOD['GPOS_STIG'][0])
            path = self.out / 'reference.xml'
            path.write_bytes(ET.tostring(sk))
            rc, meta = self.generate('--stig-xccdf-path=' + str(path))
            self.assertEqual(rc, 0, meta)
            self.assertEqual(meta['release_source'], 'skeleton')
            if revision == 1:
                self.assertEqual(self.rows()[0]['status'], 'not_applicable')
            else:
                self.assertEqual(self.rows()[0]['status'], 'not_reviewed')
                self.assertIn('Chainguard vendor rationale', self.rows()[0]['finding_details'])
                self.assertEqual(meta['revision_drift'], {'unverified_revision': 2})

    def test_site_answers_preserve_vendor_evidence_and_scan_gate(self):
        self.vendor(vendor_fixture(('pass', 'notapplicable', 'fail')))
        _, meta = self.generate()
        answer = {'schema': MOD['ANSWER_SCHEMA'], 'stig': meta['stig'],
                  'answers': {'V-3': {'status': 'Not_Applicable', 'comments': 'Site reviewed.'}},
                  'category_comments': {'vendor': 'Site deployment assessed.'}}
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = common.Path(temp.name) / 'answers.json'
        path.write_text(json.dumps(answer))
        rc, meta = self.generate('--checklist-answers=' + str(path))
        self.assertEqual(rc, 0, meta)
        self.assertEqual(self.rows()[2]['status'], 'not_applicable')
        self.assertNotIn('Open', meta['status'])
        self.assertIn('Site deployment assessed.', self.rows()[1]['comments'])
        self.assertIn('Chainguard vendor rationale', self.rows()[1]['finding_details'])
        self.assertEqual(self.summary('require', 'true').returncode, 1)
        self.assertEqual(self.generate('--default-answers=container-host')[1]['outcome'], 'failed')

    def test_fingerprint_tool_native_ids_and_ambiguity(self):
        self.vendor(vendor_fixture(('pass',)))
        sk = skeleton()
        path = self.out / 'reference.xml'
        path.write_bytes(ET.tostring(sk))
        argv = [sys.executable, str(common.ROOT / 'tools/fingerprint-stig.py'),
                str(self.out / 'results.xml'), str(self.out / 'reference*.xml')]
        result = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(self.entry[4]['evidence_sha256'], result.stdout)
        (self.out / 'reference2.xml').write_bytes(ET.tostring(sk))
        self.assertNotEqual(subprocess.run(argv, capture_output=True).returncode, 0)

    def test_tailoring_is_explicitly_refused_before_reading_inputs(self):
        self.vendor()
        self.plan['tailoring_file'] = '/no-such-tailoring.xml'
        self.save_plan()
        rc, meta = self.generate()
        self.assertEqual(rc, 1)
        self.assertIn('tailoring is not supported', meta['reason'])

    def test_smoke_runs_on_tags_and_feeds_consumers_and_publish(self):
        config = (common.ROOT / '.circleci/test-deploy.yml').read_text()
        import re
        for name in ('checklist-validator', 'orb-tools/publish'):
            invocation = re.split(r'^      - ', config.split('      - ' + name + ':', 1)[1],
                                  maxsplit=1, flags=re.M)[0]
            self.assertIn('            - smoke-wolfi', invocation)
        self.assertIn('- smoke-wolfi:\n          filters: *filters', config)
        job = config.split('  smoke-wolfi:', 1)[1].split('  smoke-gate:', 1)[0]
        self.assertIn('outcome: generated', job)
        self.assertIn('artifact_name: wolfi', job)

    def test_native_metadata_does_not_change_ssg_mapping(self):
        root = common.fixture([('SV-999r1_rule', 1, 'pass', ())])
        res = MOD['parse_results'](io.BytesIO(ET.tostring(root)))
        self.assertFalse(res['vendor_srg'])
        self.assertEqual(res['rules']['SV-999r1_rule']['svs'], {'1': ['SV-1r1_rule']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
