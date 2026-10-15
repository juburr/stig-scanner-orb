"""Answer-file decisions, unchanged scan gates, source integrity and publication."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import checklist_test as common
from checklist_test import MOD, ROOT, fixture, H
from skeleton_test import skeleton


class AnswerTests(unittest.TestCase):
    prepare = common.ChecklistTests.prepare
    save_plan = common.ChecklistTests.save_plan
    generate = common.ChecklistTests.generate
    rows = common.ChecklistTests.rows
    guard = common.ChecklistTests.guard
    summary = common.ChecklistTests.summary
    wrapper = common.ChecklistTests.wrapper

    def setUp(self):
        common.ChecklistTests.setUp(self)
        self.inputs = tempfile.TemporaryDirectory()
        self.addCleanup(self.inputs.cleanup)
        self.path = Path(self.inputs.name) / 'answers.json'
        self.data = {
            'schema': MOD['ANSWER_SCHEMA'],
            'stig': {'benchmark_id': 'RHEL_9_STIG', 'version': '2',
                     'releaseinfo': 'Release: 9 Benchmark Date: 01 Jul 2026'},
            'answers': {'V-1': {'status': 'Not_Applicable', 'comments': 'Site decision < & >, reviewed by assessor.'}},
        }

    def save(self, *args):
        self.path.write_text(json.dumps(args[0] if args else self.data))
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def run_answers(self, *args, **kwargs):
        return self.generate('--checklist-answers=' + str(self.path), *args, **kwargs)

    def test_override_keeps_failing_evidence_and_gates_in_both_formats(self):
        self.prepare(fixture([('one', 1, 'fail', ())]))
        original_results = (self.out / 'results.xml').read_bytes()
        original_plan = (self.out / 'scan-plan.env').read_bytes()
        self.data['answers']['V-1']['finding_details_append'] = 'Manual assessment: café\nSee site record.'
        digest = self.save()
        rc, meta = self.run_answers()
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['status'], {'Not_Applicable': 1})
        self.assertEqual(meta['answers']['automatic_status'], {'Open': 1})
        self.assertEqual(meta['answers']['file']['sha256'], digest)
        self.assertEqual(meta['answers']['file_rows'], 1)
        row = self.rows()[0]
        self.assertEqual(row['status'], 'not_applicable')
        self.assertEqual(row['comments'], self.data['answers']['V-1']['comments'])
        self.assertIn('result before answer: Open; final result: Not_Applicable', row['finding_details'])
        self.assertIn('Manual assessment: café', row['finding_details'])
        self.assertIn(digest, row['finding_details'])
        self.assertIn('fail', row['finding_details'])
        xml = ET.parse(self.out / 'checklist.ckl').find('.//VULN')
        self.assertEqual(xml.findtext('STATUS'), 'Not_Applicable')
        self.assertEqual(xml.findtext('COMMENTS'), row['comments'])
        self.assertEqual(xml.findtext('FINDING_DETAILS'), row['finding_details'])
        self.assertEqual((self.out / 'results.xml').read_bytes(), original_results)
        self.assertEqual((self.out / 'scan-plan.env').read_bytes(), original_plan)
        self.assertEqual(self.guard(), 0)
        result = self.summary('require', findings='true')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        prov = json.loads((self.out / 'provenance.json').read_text())
        self.assertEqual(prov['checklist']['answers'], meta['answers'])
        self.assertIn(digest, result.stdout)
        self.assertTrue((self.out / 'checklist.cklb').exists())

    def test_all_statuses_and_non_status_answers(self):
        for status in MOD['ANSWER_STATUSES']:
            with self.subTest(status=status):
                self.data['answers']['V-1']['status'] = status
                self.save()
                rc, meta = self.run_answers()
                self.assertEqual(rc, 0, meta)
                self.assertEqual(meta['status'], {status: 1})
                if status == 'Not_Reviewed':
                    self.assertEqual(meta['not_reviewed_by_reason'], {'answer': 1})
        self.data['answers'] = {'V-1': {'finding_details_append': 'Supplemental evidence'}}
        self.save()
        self.assertEqual(self.run_answers()[1]['status'], {'NotAFinding': 1})
        self.assertIn('Supplemental evidence', self.rows()[0]['finding_details'])

    def test_categories_keep_original_comments_and_row_answer_wins(self):
        self.prepare(fixture([('one', 1, 'notapplicable', ('#system_with_kernel',)),
                              ('two', 2, 'notapplicable', ('#system_with_kernel',)),
                              ('three', 3, 'fail', ())]))
        self.data['category_comments'] = {'host': 'Site-approved host wording; inherited from CCP Example.'}
        self.save()
        rc, meta = self.run_answers()
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['answers']['category_rows'], 2)
        rows = self.rows()
        self.assertEqual(rows[0]['comments'], self.data['answers']['V-1']['comments'])
        self.assertEqual(rows[1]['comments'], self.data['category_comments']['host'])
        self.assertIn('Original comments:', rows[1]['finding_details'])
        self.assertIn('host operating system', rows[1]['finding_details'])
        self.assertEqual(rows[2]['status'], 'open')
        self.assertIn(meta['answers']['file']['sha256'], rows[2]['finding_details'])

    def test_mixed_categories_require_complete_replacement(self):
        self.prepare(fixture([('one', 1, 'notapplicable', ('#system_with_kernel',)),
                              ('two', 1, 'notapplicable', ('#package_gdm',))]))
        self.data.pop('answers')
        self.data['category_comments'] = {'host': 'Host comment'}
        self.save()
        self.assertEqual(self.run_answers()[1]['outcome'], 'failed')
        self.data['category_comments']['gui'] = 'GUI comment'
        self.save()
        rc, meta = self.run_answers()
        self.assertEqual(rc, 0, meta)
        self.assertEqual(set(self.rows()[0]['comments'].splitlines()), {'Host comment', 'GUI comment'})

    def test_strict_json_schema_types_text_and_release(self):
        invalid = [None, [], {}, {'schema': MOD['ANSWER_SCHEMA'], 'stig': self.data['stig']},
                   {**self.data, 'schema': 'future'}, {**self.data, 'extra': True},
                   {**self.data, 'stig': {**self.data['stig'], 'version': 2}},
                   {**self.data, 'answers': []}, {**self.data, 'category_comments': []},
                   {**self.data, 'category_comments': {'inherited': 'No'}},
                   {**self.data, 'category_comments': {'host': 1}}]
        invalid += [{**self.data, 'answers': {'V-1': answer}} for answer in
                    ({}, None, [], {'severity': 'low'}, {'status': 'pass', 'comments': 'X'},
                     {'status': 'Open'}, {'comments': ''}, {'comments': '  '}, {'comments': False},
                     {'comments': ['X']}, {'comments': '\x00'}, {'comments': '\ud800'},
                     {'comments': '\uffff'}, {'comments': 'a' * 16385})]
        invalid += [{**self.data, 'answers': {vid: {'comments': 'X'}}} for vid in ('SV-1', 'V-01', 'V-1x', 'V-999')]
        invalid += [{**self.data, 'stig': {**self.data['stig'], key: val}} for key, val in
                    [('benchmark_id', 'RHEL_8_STIG'), ('version', '99'), ('releaseinfo', 'Release: 10')]]
        for data in invalid:
            with self.subTest(data=repr(data)[:150]):
                self.save(data)
                # Publish a prior pair first: every rejection must remove it.
                self.generate()
                rc, meta = self.run_answers()
                self.assertEqual((rc, meta['outcome']), (1, 'failed'), meta)
                self.assertFalse((self.out / 'checklist.ckl').exists())
                self.assertFalse((self.out / 'checklist.cklb').exists())
                self.assertEqual(self.summary().returncode, 1)

    def test_duplicate_keys_nonfinite_encoding_and_bounds(self):
        valid = json.dumps(self.data)
        cases = [b'\xff', b'\xff\xfe{\x00}\x00', b'{', b'{}' + b' ' * (1 << 20),
                 (valid[:-1] + ',"answers":{}}').encode(),
                 valid.replace('"V-1": {', '"V-1": {}, "V-1": {').encode(),
                 valid.replace('"comments":', '"comments":"X","comments":').encode(),
                 valid.replace('"2"', 'NaN').encode(), valid.replace('"2"', 'Infinity').encode()]
        for raw in cases:
            with self.subTest(raw=raw[:80]):
                self.path.write_bytes(raw)
                self.assertEqual(self.run_answers()[1]['outcome'], 'failed')
        self.path.write_bytes(valid.encode() + b' ' * ((1 << 20) - len(valid)))
        self.assertEqual(self.run_answers()[0], 0)

    def test_non_regular_missing_inputs_and_mode_none(self):
        for path in (Path(self.inputs.name), Path(self.inputs.name) / 'missing'):
            self.path = path
            self.assertEqual(self.run_answers()[1]['outcome'], 'failed')
        fifo = Path(self.inputs.name) / 'fifo'
        os.mkfifo(fifo)
        self.path = fifo
        self.assertEqual(self.run_answers()[1]['outcome'], 'failed')
        self.assertEqual(self.run_answers('--mode=none')[1]['outcome'], 'skipped')

    def test_snapshot_is_read_once_and_stays_hash_bound(self):
        original = self.save()
        apply = MOD['apply_answers']
        def replace_after_read(*args, **kwargs):
            self.data['answers']['V-1']['comments'] = 'Changed after snapshot'
            self.save()
            return apply(*args, **kwargs)
        rc, meta = self.run_answers(fault=patch.dict(MOD, {'apply_answers': replace_after_read}))
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['answers']['file']['sha256'], original)
        self.assertNotIn('Changed after snapshot', self.rows()[0]['comments'])

    def test_skeleton_manual_and_revision_mismatch_can_be_explicitly_answered(self):
        path = Path(self.inputs.name) / 'skeleton.xml'
        path.write_bytes(ET.tostring(skeleton(revision=2)))
        self.data['stig'].update(version='99', releaseinfo='Release: 1 Benchmark Date: 01 Oct 2026')
        self.data['answers'] = {vid: {'status': 'NotAFinding', 'comments': 'Reviewed manually.'}
                                for vid in ('V-1', 'V-2')}
        self.save()
        rc, meta = self.run_answers('--stig-xccdf-path=' + str(path))
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['answers']['automatic_status'], {'Not_Reviewed': 2})
        self.assertEqual(meta['status'], {'NotAFinding': 2})
        self.assertIn('different revision', self.rows()[0]['finding_details'])
        self.assertIn('No scanner rule', self.rows()[1]['finding_details'])

    def test_collision_protection_in_all_cleanup_steps(self):
        self.generate()
        original = {p.name: p.read_bytes() for p in self.out.iterdir() if p.is_file()}
        for alias in ('direct', 'symlink', 'hardlink', 'directory'):
            for artifact in ('results.xml', 'checklist-meta.json', 'checklist.ckl', 'checklist.ckl.partial'):
                with self.subTest(alias=alias, artifact=artifact):
                    dest = self.out / artifact
                    if not dest.exists():
                        dest.write_bytes(b'input')
                    candidate = Path(self.inputs.name) / 'alias'
                    if candidate.is_symlink() or candidate.exists():
                        candidate.unlink()
                    if alias == 'direct':
                        candidate = dest
                    elif alias == 'symlink':
                        candidate.symlink_to(dest)
                    elif alias == 'hardlink':
                        os.link(dest, candidate)
                    else:
                        directory = Path(self.inputs.name) / 'dir'
                        if not directory.exists():
                            directory.symlink_to(self.out, target_is_directory=True)
                        candidate = directory / artifact
                    data = candidate.read_bytes()
                    for script in ('reserve-output.sh', 'scan.sh', 'checklist.sh'):
                        env = {**os.environ, 'PARAM_IMAGE': 'local/app:test', 'PARAM_OUTPUT_DIR': str(self.out),
                               'PARAM_CHECKLIST_ANSWERS': str(candidate)}
                        proc = subprocess.run(['bash', str(ROOT / 'src/scripts' / script)], env=env,
                                              capture_output=True, text=True, timeout=10)
                        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                        self.assertIn('checklist_answers', proc.stderr)
                        self.assertEqual(candidate.read_bytes(), data)
                    for name, content in original.items():
                        self.assertEqual((self.out / name).read_bytes(), content)

    def test_symlink_snapshot_and_unreadable_input(self):
        self.save()
        source = self.path
        self.path = Path(self.inputs.name) / 'linked.json'
        self.path.symlink_to(source)
        rc, meta = self.run_answers()
        self.assertEqual(rc, 0, meta)
        self.assertEqual(meta['answers']['file']['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        with patch.object(os, 'open', side_effect=PermissionError('unreadable answer file')):
            with self.assertRaises(PermissionError):
                MOD['read_answers'](str(source))
        # An isolation check failure must be a hard command failure, never a
        # suppressed conversion error that could accept a previous valid meta.
        rc, _ = self.run_answers(fault=patch.dict(MOD, {'answer_input_collision':
            lambda *args: (_ for _ in ()).throw(PermissionError('unreadable parent'))}))
        self.assertEqual(rc, 2)

    def test_shell_wrapper_and_dash_prefixed_input(self):
        self.save()
        proc = self.wrapper(PARAM_CHECKLIST_ANSWERS=str(self.path))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.rows()[0]['status'], 'not_applicable')
        proc = self.wrapper(PARAM_CHECKLIST_ANSWERS='--help')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads((self.out / 'checklist-meta.json').read_text())['outcome'], 'failed')
        self.assertFalse((self.out / 'checklist.ckl').exists())

    def test_publication_failure_cannot_leave_answered_artifacts(self):
        self.save()
        replace = os.replace
        def failure(src, dest):
            if str(dest).endswith('checklist.cklb'):
                raise OSError('publication failure')
            return replace(src, dest)
        self.assertEqual(self.run_answers(fault=patch.object(os, 'replace', failure))[1]['outcome'], 'failed')
        self.assertFalse((self.out / 'checklist.ckl').exists())
        self.assertFalse((self.out / 'checklist.cklb').exists())

    def test_answers_do_not_waive_hollow_or_inventory_eligibility(self):
        self.prepare(fixture([('one', 1, 'notapplicable', ())]))
        self.data['answers']['V-1'] = {'status': 'NotAFinding', 'comments': 'Site assessment'}
        self.save()
        self.assertEqual(self.run_answers()[1]['status'], {'NotAFinding': 1})
        self.assertEqual(self.summary('require').returncode, 1)
        self.plan.update(rpm_status='missing', rpm_status_reason='database unavailable')
        self.save_plan()
        self.assertEqual(self.run_answers()[1]['outcome'], 'skipped')
        self.assertFalse((self.out / 'checklist.cklb').exists())
        self.assertEqual(self.summary('require').returncode, 1)

    def test_answers_apply_after_tailoring_and_retain_selection_evidence(self):
        from tailoring_test import TailoringTests
        for name in ('preflight', 'save_meta', 'save_skeleton'):
            setattr(self, name, getattr(TailoringTests, name).__get__(self))
        TailoringTests.tailored(self)
        path = self.save_skeleton()
        # The fixture names an unknown release.
        self.data['stig'].update(version='99', releaseinfo='Release: 1 Benchmark Date: 01 Oct 2026')
        self.data['answers'] = {'V-2': {'status': 'NotAFinding', 'comments': 'Manually assessed omitted check'}}
        self.save()
        rc, meta = self.run_answers(path)
        self.assertEqual(rc, 0, meta)
        row = next(r for r in self.rows() if r['group_id'] == 'V-2')
        self.assertEqual(row['status'], 'not_a_finding')
        self.assertIn('Deselected by tailoring', row['finding_details'])
        self.assertIn('result before answer: Not_Reviewed', row['finding_details'])
        self.assertTrue(meta['tailoring'])

    def test_packed_entry_point_verifies_source_and_fits_linux_argument_limit(self):
        import runpy
        pack = runpy.run_path(str(ROOT / 'tools/pack-checklist.py'))
        source = (ROOT / 'src/scripts/checklist.sh').read_bytes()
        entry = (ROOT / 'src/scripts/checklist-packed.sh').read_text()
        pack['verify'](source, entry)
        self.assertLess(len(entry.encode()), 120000)
        for edited in (entry.replace('eval "${STIG_CHECKLIST_SCRIPT}"', 'true'),
                       entry.replace('source hash mismatch', 'edited wrapper')):
            with self.assertRaises(ValueError):
                pack['verify'](source, edited)
        with self.assertRaises(ValueError):
            pack['verify'](source + b'# changed', entry)
        # Exercise bash -c with the actual production entry as one argument,
        # including its embedded decoder and the generator's failure policy.
        self.save()
        proc = subprocess.run(['bash', '-c', entry], env={**os.environ,
            'PARAM_OUTPUT_DIR': str(self.out), 'PARAM_CHECKLIST_ANSWERS': str(self.path),
            'PARAM_CHECKLIST': 'none'}, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads((self.out / 'checklist-meta.json').read_text())['outcome'], 'skipped')

    def test_default_generator_runs_with_real_bundle_and_keeps_opt_in_explicit(self):
        h = next(h for h, d in MOD['BUNDLE_TABLE'].items() if d['alias'] == 'rhel9')
        baseline = MOD['load_bundle'](h, str(ROOT / 'src/scripts/stig-data'))
        # A synthetic mapped scanner row uses real official metadata, while the
        # default's actual manual-only requirement is copied unchanged.
        number = int(baseline['groups'][0]['vid'][2:])
        self.prepare(fixture([('one', number, 'pass', ())]))
        fault = lambda: patch.dict(MOD, {'load_bundle': lambda *args: copy.deepcopy(baseline)})
        rc, meta = self.generate(fault=fault())
        self.assertEqual(rc, 0, meta)
        row = next(r for r in self.rows() if r['group_id'] == 'V-257782')
        self.assertEqual(row['status'], 'not_reviewed')
        self.assertIsNone(meta['answers'])
        rc, meta = self.generate('--default-answers=container-host', fault=fault())
        self.assertEqual(rc, 0, meta)
        row = next(r for r in self.rows() if r['group_id'] == 'V-257782')
        self.assertEqual(row['status'], 'not_applicable')
        self.assertEqual(meta['answers']['default_rows'], 1)
        self.assertEqual(self.guard(), 0)
        self.assertEqual(self.summary('require').returncode, 0)
        self.assertEqual(self.generate('--default-answers=typo')[1]['outcome'], 'failed')

    def test_curated_default_exact_release_content_manual_only_and_opt_in(self):
        h = next(h for h, d in MOD['BUNDLE_TABLE'].items() if d['alias'] == 'rhel9')
        baseline = MOD['load_bundle'](h, str(ROOT / 'src/scripts/stig-data'))
        reference = next(g for g in baseline['groups'] if g['vid'] == 'V-257782')
        stig = {k: baseline[k] for k in ('benchmark_id', 'version', 'releaseinfo')}
        row = {**reference, 'status': 'Not_Reviewed', 'nr_reason': 'no_scanner_rule',
               'na_category': None, 'comments': 'Manual review', 'finding_details': 'No automated check'}
        plan = {'image_id': 'sha256:image'}
        rows = [copy.deepcopy(row)]
        self.assertIsNone(MOD['apply_answers'](stig, rows, plan))
        self.assertEqual(rows[0], row)
        info = MOD['apply_answers'](stig, rows, plan, default='container-host', baseline=baseline)
        self.assertEqual(info['default_rows'], 1)
        self.assertEqual(rows[0]['status'], 'Not_Applicable')
        self.assertIn(info['default_set']['sha256'], rows[0]['finding_details'])
        for mutate in ('version', 'releaseinfo', 'check_content', 'rule_id', 'manual', 'rootfs', 'reference'):
            ss, rr, pp, bb = copy.deepcopy((stig, row, plan, baseline))
            if mutate in ('version', 'releaseinfo'):
                ss[mutate] = 'different'
            elif mutate == 'manual':
                rr['nr_reason'] = 'deselected'
            elif mutate == 'rootfs':
                pp['rootfs_path'] = '/mounted/vm'
            elif mutate == 'reference':
                next(g for g in bb['groups'] if g['vid'] == 'V-257782')['check_content'] = 'edited'
            else:
                rr[mutate] = 'edited'
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                MOD['apply_answers'](ss, [rr], pp, default='container-host', baseline=bb)
        self.data['answers'] = {'V-257782': {'status': 'Open', 'comments': 'Site requires remediation'}}
        self.save()
        rows = [copy.deepcopy(row)]
        info = MOD['apply_answers'](stig, rows, plan, MOD['read_answers'](str(self.path)), 'container-host', baseline)
        self.assertEqual(rows[0]['status'], 'Open')
        self.assertIn('curated container-host', rows[0]['finding_details'])
        self.assertIn('answer file sha256:', rows[0]['finding_details'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
