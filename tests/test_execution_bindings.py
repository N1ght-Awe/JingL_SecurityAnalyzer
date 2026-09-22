"""Real harmless subprocesses verify evidence contracts, not business vulnerability accuracy."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from test_candidate_ledger import CandidateLedgerTests as _Fixture, audit, ledger, validator

fixture_setup, fixture_archive = _Fixture.setUp, _Fixture.archive
del _Fixture
SPEC = importlib.util.spec_from_file_location('execution_evidence', Path(__file__).resolve().parents[1] / 'scripts/execution_evidence.py')
execution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(execution)


class ExecutionBindingTests(unittest.TestCase):
    archive = fixture_archive

    def setUp(self):
        fixture_setup(self)
        self.data.update(skill_version='2.3.2', rules_version='2.3.2')
        self.finding = self.data['findings'][0]
        self.finding['validation'].update(goal='Synthetic contract subprocess succeeds', scope='isolated')
        self.roots = {'test': self.repo}

    def capture(self, code='print("contract fixture only")', ids=None, timeout=10):
        return execution.capture(self.data, ids or ['F-1'], self.roots,
                                 [sys.executable, '-c', code], self.root, self.evidence, 'Local synthetic test', timeout)

    def attach(self, receipt, artifact, finding=None, status='PASSED'):
        finding = finding or self.finding
        finding['validation'].update(execution_receipt=artifact, artifacts=[receipt['log']], status=status,
            target_executed=True, controls_passed=status == 'PASSED', result_supported=status == 'PASSED',
            **{k: receipt[k] for k in ('command', 'environment', 'executed_at', 'exit_code')})

    def errors(self):
        return execution.validate_execution_bindings(self.data, self.evidence)

    def sibling(self):
        other = {**self.item, 'id': 'F-2', 'instance_key': 'Export.handle->execute:sort', 'entry': 'Export.handle'}
        self.data['candidate_ledger'] = ledger.append(self.evidence, 'fixture', other)
        finding = copy.deepcopy(self.finding)
        finding.update({key: other[key] for key in ('id', 'instance_key', 'entry')})
        self.data['findings'].append(finding)
        review = copy.deepcopy(self.review)
        review['finding_id'] = 'F-2'
        review['source_review'] = ledger.save_review(self.evidence, 'fixture', {**self.baseline, 'finding_id': 'F-2'})
        self.data['supervision'].append(review)
        self.data['metrics'].update(candidates=2, reviewed=2)
        return finding, review

    def test_bound_success_passes_current_report(self):
        self.attach(*self.capture())
        self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_other_run_receipt_rejected_even_with_valid_hash(self):
        receipt, artifact = self.capture()
        receipt['run_id'] = 'older-run'
        self.attach(receipt, audit.save(self.evidence, receipt))
        self.assertTrue(any('run_id' in x for x in self.errors()))

    def test_identity_goal_scope_and_repository_changes_rejected(self):
        self.attach(*self.capture())
        for owner, key, value in [(self.finding, 'instance_key', 'another call'),
                                  (self.finding['validation'], 'goal', 'different assertion'),
                                  (self.finding['validation'], 'scope', 'end_to_end'),
                                  (self.data['repositories'][0], 'revision', 'new revision'),
                                  (self.data['repositories'][0], 'path', 'other repository')]:
            with self.subTest(key=key):
                old = owner[key]
                owner[key] = value
                self.assertTrue(self.errors())
                owner[key] = old

    def test_source_change_before_run_prevents_command(self):
        marker = self.root / 'must-not-run'
        self.source.write_text('changed before execution', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.capture('from pathlib import Path; Path(' + repr(str(marker)) + ').write_text("bad")')
        self.assertFalse(marker.exists())

    def test_source_change_during_run_blocks_passed_but_retains_failure(self):
        code = 'from pathlib import Path; Path(' + repr(str(self.source)) + ').write_text("changed during execution")'
        receipt, artifact = self.capture(code)
        self.assertFalse(receipt['source_unchanged'])
        self.attach(receipt, artifact)
        self.assertTrue(self.errors())
        self.attach(receipt, artifact, status='FAILED')
        self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_current_snapshot_cannot_be_replaced_after_execution(self):
        self.attach(*self.capture())
        self.source.write_text('class Changed {}\n', encoding='utf-8')
        _, artifact = audit.read_source(self.repo, 'Allowlist.java', 1, 1, self.evidence, 'fixture', 'test')
        self.review['receipts']['read'] = artifact
        self.assertTrue(self.errors())

    def test_unbound_extra_read_cannot_be_added_after_execution(self):
        self.attach(*self.capture())
        (self.repo / 'Extra.java').write_text('class Extra {}\n', encoding='utf-8')
        _, artifact = audit.read_source(self.repo, 'Extra.java', 1, 1, self.evidence, 'fixture', 'test')
        self.review['receipts']['extra'] = artifact
        self.assertTrue(self.errors())

    def test_log_tampering_and_missing_log_rejected(self):
        receipt, artifact = self.capture()
        self.attach(receipt, artifact)
        self.finding['validation']['artifacts'] = []
        self.assertTrue(any('missing' in x for x in self.errors()))
        self.finding['validation']['artifacts'] = [receipt['log']]
        (self.evidence / receipt['log']['path']).write_text('{}', encoding='utf-8')
        self.assertTrue(any('digest' in x for x in self.errors()))

    def test_arbitrary_hashed_log_cannot_replace_execution_receipt(self):
        self.attach(*self.capture())
        self.finding['validation']['execution_receipt'] = audit.save(self.evidence, {'run_id': 'fixture', 'note': 'unrelated'})
        self.assertTrue(self.errors())

    def test_explicit_suite_can_cover_two_instances_counted_separately(self):
        sibling, _ = self.sibling()
        sibling['related_findings'] = ['F-1']
        receipt, artifact = self.capture(ids=['F-1', 'F-2'])
        self.attach(receipt, artifact)
        self.attach(receipt, artifact, sibling)
        self.assertEqual(validator.validate(self.data, self.evidence), [])
        self.data['metrics'].update(candidates=1, reviewed=1)
        self.assertTrue(any('metrics.candidates' in x for x in validator.validate(self.data, self.evidence)))

    def test_unlisted_sibling_cannot_reuse_execution(self):
        sibling, _ = self.sibling()
        receipt, artifact = self.capture()
        self.attach(receipt, artifact)
        self.attach(receipt, artifact, sibling)
        self.assertTrue(any('did not cover' in x for x in self.errors()))

    def test_cross_repo_direct_read_is_bound_and_checked(self):
        library = self.root / 'library'
        library.mkdir()
        source = library / 'Allowlist.java'
        source.write_text('class LibraryGuard {}\n', encoding='utf-8')
        self.data['repositories'].append({'repo_id': 'library', 'path': 'library', 'revision': 'r1'})
        self.roots['library'] = library
        _, artifact = audit.read_source(library, 'Allowlist.java', 1, 1, self.evidence, 'fixture', 'library')
        self.review['receipts']['library'] = artifact
        receipt, artifact = self.capture()
        self.assertEqual({s['repo_id'] for s in receipt['targets'][0]['sources']}, {'test', 'library'})
        source.write_text('changed', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.capture()

    def test_shared_control_read_under_other_instance_is_bound(self):
        _, other_review = self.sibling()
        library = self.root / 'library'
        library.mkdir()
        source = library / 'Guard.java'
        source.write_text('class Guard {}\n', encoding='utf-8')
        self.roots['library'] = library
        self.data['repositories'].append({'repo_id': 'library', 'path': 'library', 'revision': 'r1'})
        read, artifact = audit.read_source(library, 'Guard.java', 1, 1, self.evidence, 'fixture', 'library')
        other_review['receipts']['shared'] = artifact
        self.data['control_knowledge'] = [{'id': 'A', 'repo_id': 'library', 'status': 'reviewed',
            'fingerprints': [{'path': 'Guard.java', 'sha256': read['source_sha256'].upper()}]}]
        self.data['control_applications'] = [{'control_id': 'A', 'outcome': 'applicable', 'finding_ids': ['F-1']}]
        receipt, artifact = self.capture()
        self.assertIn({'repo_id': 'library', 'path': 'Guard.java', 'sha256': read['source_sha256']}, receipt['targets'][0]['sources'])
        self.attach(receipt, artifact)
        self.assertEqual(self.errors(), [])
        source.write_text('changed shared guard', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.capture()

    def test_nonzero_and_timeout_cannot_pass_but_remain_deliverable(self):
        for code, timeout, status in [('import sys; sys.exit(3)', 10, 'FAILED'), ('import time; time.sleep(3)', .15, 'TIMEOUT')]:
            with self.subTest(status=status):
                receipt, artifact = self.capture(code, timeout=timeout)
                self.attach(receipt, artifact)
                self.assertTrue(self.errors())
                self.attach(receipt, artifact, status=status)
                self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_timeout_with_inherited_output_returns_without_waiting_for_child(self):
        code = 'import subprocess, sys, time; subprocess.Popen([sys.executable,"-c","import time; time.sleep(8)"]); time.sleep(8)'
        started = time.monotonic()
        receipt, artifact = self.capture(code, timeout=.2)
        elapsed = time.monotonic() - started
        # Restricted hosts may deny taskkill; allow the harmless fixture to exit before
        # removing its cwd, while still checking that capture returned promptly.
        if receipt['cleanup_error']:
            time.sleep(max(0, 8.5 - elapsed))
        self.assertTrue(receipt['timed_out'])
        self.assertLess(elapsed, 7)
        self.attach(receipt, artifact, status='TIMEOUT')
        self.assertEqual(self.errors(), [])

    def test_invalid_timeout_rejected_before_command(self):
        for value in (0, -1, float('nan'), float('inf'), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.capture(timeout=value)

    def test_cleanup_failure_is_preserved_and_cannot_be_passed(self):
        result = dict(command=[sys.executable, '-c', 'print("contract fixture only")'], exit_code=None,
                      timed_out=True, stdout='partial output', stderr='', cleanup_error='synthetic cleanup denied')
        with patch.object(execution, 'execute', return_value=result):
            receipt, artifact = self.capture()
        self.assertEqual(receipt['cleanup_error'], result['cleanup_error'])
        self.assertEqual(execution.load_artifact(self.evidence, receipt['log'])['cleanup_error'], result['cleanup_error'])
        self.attach(receipt, artifact)
        self.assertTrue(self.errors())
        self.attach(receipt, artifact, status='TIMEOUT')
        self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_current_rule_gate_checks_control_fingerprint_even_without_execution(self):
        self.finding['validation']['scope'] = 'none'
        sha = audit.load_receipt(self.evidence, self.review['receipts']['read'], 'fixture')['source_sha256']
        self.data['control_knowledge'] = [{'id': 'A', 'repo_id': 'test', 'symbol': 'Allowlist.A', 'revision': 'older-label',
            'status': 'reviewed', 'fingerprints': [{'path': 'Allowlist.java', 'sha256': sha}],
            'protects': [self.finding['type']], 'contract': 'Synthetic fixture', 'assumptions': 'Fixture only',
            'limitations': 'Not a security assessment', 'evidence_refs': ['Allowlist.java:2']}]
        self.data['control_applications'] = [{'id': 'A-call', 'control_id': 'A', 'repo_id': 'test',
            'location': 'Allowlist.java:6', 'finding_ids': ['F-1'], 'outcome': 'applicable', 'reason': 'Fixture only',
            'checks': {key: {'state': 'observed', 'result': 'pass', 'summary': 'Synthetic check', 'refs': ['Allowlist.java:6']}
                       for key in validator.APPLICATION_CHECKS}}]
        self.assertEqual(validator.validate(self.data, self.evidence), [])
        self.data['control_knowledge'][0]['fingerprints'][0]['sha256'] = '0' * 64
        self.assertTrue(any('control binding' in x for x in validator.validate(self.data, self.evidence)))
        self.data.update(skill_version='2.3.1', rules_version='2.3.1')
        self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_current_rules_need_receipt_and_historical_rules_keep_old_contract(self):
        self.attach(*self.capture())
        del self.finding['validation']['execution_receipt']
        self.assertTrue(any('execution binding' in x for x in validator.validate(self.data, self.evidence)))
        self.data.update(skill_version='2.3.1', rules_version='2.3.1')
        self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_new_evidence_cannot_silently_downgrade(self):
        self.attach(*self.capture())
        self.data.update(skill_version='2.3.1', rules_version='2.3.1')
        self.assertTrue(any('silently downgrade' in x for x in validator.validate(self.data, self.evidence)))

    def test_not_run_partial_delivery_needs_no_fabricated_execution(self):
        self.finding['validation'].update(status='NOT_RUN', scope='none')
        self.assertEqual(validator.validate(self.data, self.evidence), [])

    def test_malformed_metadata_is_rejected(self):
        original, artifact = self.capture()
        for key, value in [('executed_at', 'yesterday'), ('finished_at', None), ('timed_out', 0),
                           ('source_unchanged', True), ('source_changes', None), ('cwd', '')]:
            with self.subTest(key=key):
                receipt = copy.deepcopy(original)
                if key == 'source_unchanged':
                    receipt['source_changes'] = [{'path': 'changed'}]
                receipt[key] = value
                self.attach(receipt, audit.save(self.evidence, receipt))
                self.assertTrue(self.errors())

    def test_cli_uses_json_argument_array_and_emits_no_status_claim(self):
        report, roots, command = (self.root / name for name in ('report.json', 'roots.json', 'command.json'))
        report.write_text(json.dumps(self.data), encoding='utf-8')
        roots.write_text(json.dumps({'test': str(self.repo)}), encoding='utf-8')
        command.write_text(json.dumps([sys.executable, '-c', 'print("synthetic CLI")']), encoding='utf-8')
        result = subprocess.run([sys.executable, str(Path(execution.__file__)), str(report), '--repo-roots', str(roots),
            '--command-file', str(command), '--evidence-root', str(self.evidence), '--finding', 'F-1',
            '--cwd', str(self.root), '--environment', 'Synthetic CLI'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads(result.stdout)
        self.assertNotIn('status', metadata)
        self.assertIn('execution_receipt', metadata)


if __name__ == '__main__':
    unittest.main()
