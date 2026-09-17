"""Discovery retention and per-instance review; fixtures are not real scan results."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from test_supervision import SupervisionTests as _Fixture, audit
from test_report_contract import validator
from test_report_presentation import presentation_sample, renderer

SPEC = importlib.util.spec_from_file_location('candidate_ledger', Path(__file__).resolve().parents[1] / 'scripts/candidate_ledger.py')
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)
# Do not let unittest discover imported fixture tests a second time.
fixture_setup = _Fixture.setUp
del _Fixture


class CandidateLedgerTests(unittest.TestCase):
    def setUp(self):
        fixture_setup(self)
        self.data.update(schema_version='2.3.0', skill_version='2.3.0', rules_version='2.3.0')
        self.data['threat_model'] = presentation_sample()['threat_model']
        self.item = {key: self.data['findings'][0][key] for key in ('id', 'repo_id', 'type', 'location')}
        self.item.update(instance_key='Query.handle->execute:sort', entry='Query.handle', operation='execute:sort',
                         evidence=[self.review['receipts']['read']])
        self.data['findings'][0].update({k: self.item[k] for k in ('instance_key', 'entry', 'operation')})
        ledger.initialize(self.evidence, 'fixture')
        self.data['candidate_ledger'] = ledger.append(self.evidence, 'fixture', self.item)
        self.baseline = {'finding_id': 'F-1', 'mode': 'same_context_second_pass', 'scope': 'Registered entry and wrapper',
                         'observations': 'Synthetic fixture: A exists; invocation and output must be checked',
                         'reads': [self.need], 'controls': [{'name': 'A', 'assessment': 'Fixture implementation read',
                         'reads': [self.need]}], 'gaps': []}
        self.archive()

    def archive(self):
        self.review['source_review'] = ledger.save_review(self.evidence, 'fixture', self.baseline)
        self.review['reconciliation'] = 'Synthetic comparison of A definition, invocation and result use.'

    def errors(self):
        return validator.validate(self.data, self.evidence)

    def test_registered_instance_and_source_first_review_pass(self):
        self.assertEqual(self.errors(), [])

    def test_deleting_candidate_and_recounting_metrics_is_detected(self):
        self.data['findings'] = []
        self.data['supervision'] = []
        self.data['metrics'].update(candidates=0, reviewed=0, pending_review=0)
        self.data['threat_model']['boundaries'][0]['finding_ids'] = []
        self.assertTrue(any('every registered candidate' in x for x in self.errors()))

    def test_unregistered_and_relabelled_instances_fail(self):
        for key, value in [('id', 'invented'), ('instance_key', 'other call'), ('entry', 'other entry')]:
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data['findings'][0][key] = value
                self.assertTrue(ledger.validate_ledger(data, self.evidence))

    def test_pending_and_rejected_candidates_stay_in_report(self):
        self.data['findings'][0].update(status='待审查', source_closed=False, missing=['unresolved dispatch'])
        self.data['metrics'].update(reviewed=0, pending_review=1)
        self.review.update(decision='pending', gaps=['unresolved dispatch'])
        del self.review['source_review']
        self.assertEqual(self.errors(), [])
        self.data['findings'][0].update(status='误报', reason='Fixture counterevidence')
        self.data['metrics'].update(reviewed=1, pending_review=0)
        self.review.update(decision='pass', gaps=[])
        self.archive()
        self.assertEqual(self.errors(), [])

    def test_sibling_call_needs_own_review_even_with_same_root_cause(self):
        other = copy.deepcopy(self.item)
        other.update(id='F-2', instance_key='Export.handle->execute:sort', entry='Export.handle')
        self.data['candidate_ledger'] = ledger.append(self.evidence, 'fixture', other)
        sibling = copy.deepcopy(self.data['findings'][0])
        sibling.update({key: other[key] for key in ('id', 'instance_key', 'entry')})
        sibling['related_findings'] = ['F-1']
        self.data['findings'].append(sibling)
        self.data['metrics'].update(candidates=2, reviewed=2)
        self.assertTrue(any('supervision' in x for x in self.errors()))
        # Preserve a still-unreviewed sibling, without suppressing the first conclusion.
        sibling.update(status='待审查', source_closed=False, missing=['Export binding not read'])
        self.data['metrics'].update(reviewed=1, pending_review=1)
        self.data['supervision'].append({'finding_id': 'F-2', 'decision': 'pending', 'rationale': 'Different call',
                                        'repair_rounds': 0, 'gaps': ['Export binding not read']})
        self.assertEqual(self.errors(), [])

    def test_stale_snapshot_cannot_omit_later_discoveries(self):
        other = {**self.item, 'id': 'F-2', 'instance_key': 'other call'}
        ledger.append(self.evidence, 'fixture', other)
        self.assertTrue(any('full current discovery ledger' in x for x in self.errors()))

    def test_empty_discovery_requires_real_initialized_ledger(self):
        empty = self.root / 'empty-evidence'
        data = copy.deepcopy(self.data)
        data['findings'] = []
        self.assertTrue(ledger.validate_ledger(data, empty))
        data['candidate_ledger'] = ledger.initialize(empty, 'fixture')
        self.assertEqual(ledger.validate_ledger(data, empty), [])

    def test_append_retry_is_idempotent_and_conflicts_do_not_destroy_records(self):
        before = (self.evidence / ledger.NAME).read_bytes()
        ledger.append(self.evidence, 'fixture', self.item)
        with self.assertRaises(ValueError):
            ledger.append(self.evidence, 'fixture', {**self.item, 'location': 'rewrite original'})
        self.assertEqual(before, (self.evidence / ledger.NAME).read_bytes())
        ledger.append(self.evidence, 'fixture', {**self.item, 'id': 'F-2', 'instance_key': 'sibling'})
        self.assertEqual(len(ledger.load(self.evidence, 'fixture')[1]), 2)

    def test_init_cannot_overwrite_and_wrong_run_fails(self):
        before = (self.evidence / ledger.NAME).read_bytes()
        with self.assertRaises(FileExistsError):
            ledger.initialize(self.evidence, 'fixture')
        with self.assertRaises(ValueError):
            ledger.snapshot(self.evidence, 'other run')
        self.assertEqual(before, (self.evidence / ledger.NAME).read_bytes())
        self.assertFalse((self.evidence / (ledger.NAME + '.lock')).exists())

    def test_original_evidence_tampering_blocks_delivery(self):
        artifact = self.item['evidence'][0]
        (self.evidence / artifact['path']).write_text('{}', encoding='utf-8')
        self.assertTrue(any('digest mismatch' in x for x in ledger.validate_ledger(self.data, self.evidence)))

    def test_review_requires_actual_context_and_control_implementation(self):
        self.baseline['mode'] = 'independent-because-I-said-so'
        self.archive()
        self.assertTrue(self.errors())
        self.baseline['mode'] = 'same_context_second_pass'
        self.baseline['controls'][0]['reads'] = [{**self.need, 'start': 8, 'end': 10}]
        self.archive()
        self.assertTrue(any('implementation not read' in x for x in self.errors()))

    def test_review_identity_and_digest_are_bound(self):
        self.baseline['finding_id'] = 'F-2'
        self.archive()
        self.assertTrue(any('identity mismatch' in x for x in self.errors()))
        self.baseline['finding_id'] = 'F-1'
        self.archive()
        path = self.evidence / self.review['source_review']['path']
        path.write_text('{}', encoding='utf-8')
        self.assertTrue(any('digest mismatch' in x for x in self.errors()))

    def test_new_observations_need_reconciliation(self):
        self.baseline['gaps'] = ['Does caller consume A result?']
        self.archive()
        self.review['reconciliation'] = ''
        self.assertTrue(any('reconcile' in x for x in self.errors()))

    def test_new_fields_cannot_be_silently_downgraded(self):
        for version in ('2.0.0', '2.1.0', '2.2.0'):
            self.data.update(schema_version=version, skill_version=version, rules_version=version)
            self.assertTrue(self.errors())

    def test_classification_can_be_corrected_without_rewriting_discovery(self):
        finding = self.data['findings'][0]
        finding['type'] = 'XSS'
        self.assertTrue(ledger.validate_ledger(self.data, self.evidence))
        finding['classification_reason'] = 'Fixture: original classification was provisional'
        self.assertEqual(ledger.validate_ledger(self.data, self.evidence), [])
        self.assertEqual(ledger.load(self.evidence, 'fixture')[1][0]['type'], self.item['type'])

    def test_lock_and_truncated_file_fail_without_overwriting(self):
        lock = self.evidence / (ledger.NAME + '.lock')
        lock.write_text('another writer', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            ledger.append(self.evidence, 'fixture', self.item)
        self.assertTrue(lock.exists())
        lock.unlink()
        with (self.evidence / ledger.NAME).open('ab') as stream:
            stream.write(b'{partial')
        self.assertTrue(ledger.validate_ledger(self.data, self.evidence))

    def test_malformed_version_returns_errors(self):
        self.data['schema_version'] = []
        self.assertTrue(self.errors())

    def test_renderer_preserves_entry_operation_and_candidate_count(self):
        rendered = renderer.render(self.data, self.evidence)
        self.assertIn('Query.handle', rendered)
        self.assertIn('execute:sort', rendered)
        self.assertIn('候选调用实例', rendered)

    def test_cli_snapshot_and_review_archive(self):
        command = [sys.executable, str(Path(ledger.__file__)), '--evidence-root', str(self.evidence), '--run-id', 'fixture']
        result = subprocess.run(command + ['snapshot'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.data['candidate_ledger'])
        source = self.root / 'review.json'
        source.write_text(json.dumps(self.baseline), encoding='utf-8')
        result = subprocess.run(command + ['review', str(source)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.evidence / json.loads(result.stdout)['path']).is_file())


if __name__ == '__main__':
    unittest.main()
