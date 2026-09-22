"""Current-source/control reuse bindings; synthetic fixtures do not measure scan recall."""
import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('control_binding_audit', Path(__file__).resolve().parents[1] / 'scripts/audit_evidence.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class ControlBindingsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        (self.repo / 'src').mkdir(parents=True)
        self.source = self.repo / 'src/Allowlist.java'
        self.source.write_text('class Allowlist {\n boolean A(String x) { return "ok".equals(x); }\n}\n', encoding='utf-8')
        self.evidence = self.root / 'evidence'
        self.record, self.artifact = audit.read_source(self.repo, 'src/Allowlist.java', 1, 3,
                                                       self.evidence, 'current-run', 'library')
        self.control = {'id': 'A', 'repo_id': 'library', 'revision': 'reviewed-revision', 'status': 'reviewed',
                        'fingerprints': [{'path': 'src/Allowlist.java', 'sha256': self.record['source_sha256']}]}
        self.application = {'id': 'A-call', 'control_id': 'A', 'repo_id': 'caller', 'outcome': 'applicable'}
        self.review = {'finding_id': 'F-1', 'decision': 'pass', 'receipts': {'A-read': self.artifact}}
        self.data = {'run_id': 'current-run', 'repositories': [
            {'repo_id': 'library', 'revision': 'current-revision'}, {'repo_id': 'caller', 'revision': 'current-revision'}],
            'supervision': [self.review], 'control_knowledge': [self.control],
            'control_applications': [self.application]}

    def errors(self):
        return audit.validate_control_bindings(self.data, self.evidence)

    def test_matching_fingerprint_accepts_cross_repo_caller_and_different_revision(self):
        before = copy.deepcopy(self.data)
        self.assertEqual(self.errors(), [])
        self.assertEqual(self.data, before)

    def test_wrong_digest_requires_stale_and_unresolved_without_mutating_report(self):
        self.control['fingerprints'][0]['sha256'] = 'a' * 64
        before = copy.deepcopy(self.data)
        self.assertTrue(any('stale' in e and 'unresolved' in e for e in self.errors()))
        self.assertEqual(self.data, before)

    def test_missing_snapshot_cannot_apply_known_control(self):
        self.review['receipts'] = {}
        self.assertTrue(any('current read snapshot missing' in e for e in self.errors()))

    def test_identical_path_and_bytes_in_other_repository_do_not_substitute(self):
        self.review['receipts']['A-read'] = audit.save(self.evidence, {**self.record, 'repo_id': 'caller'})
        self.assertTrue(any('library:src/Allowlist.java' in e for e in self.errors()))

    def test_unknown_repository_not_added_to_snapshot_index(self):
        self.review['receipts']['A-read'] = audit.save(self.evidence, {**self.record, 'repo_id': 'unknown'})
        snapshots, errors = audit.collect_read_snapshots(self.data, self.evidence)
        self.assertEqual(snapshots, {})
        self.assertTrue(any('unknown receipt repo_id' in e for e in errors))

    def test_corrupt_receipt_not_added_to_snapshot_index(self):
        (self.evidence / self.artifact['path']).write_bytes(b'{}')
        snapshots, errors = audit.collect_read_snapshots(self.data, self.evidence)
        self.assertEqual(snapshots, {})
        self.assertTrue(any('receipt digest mismatch' in e for e in errors))

    def test_corrupt_source_snapshot_cannot_satisfy_binding(self):
        (self.evidence / self.record['snapshot']).write_bytes(b'changed')
        self.assertTrue(any('snapshot digest mismatch' in e for e in self.errors()))

    def test_forged_excerpt_with_updated_receipt_hash_still_rejected(self):
        self.review['receipts']['A-read'] = audit.save(self.evidence, {**self.record, 'content': 'invented source'})
        self.assertTrue(any('content does not match snapshot' in e for e in self.errors()))

    def test_mixed_versions_across_reviews_are_not_resolved_by_order(self):
        self.source.write_text('class Allowlist { boolean A(String x) { return true; } }\n', encoding='utf-8')
        _, changed = audit.read_source(self.repo, 'src/Allowlist.java', 1, 1, self.evidence, 'current-run', 'library')
        self.data['supervision'].append({'finding_id': 'F-2', 'decision': 'pending', 'receipts': {'changed': changed}})
        for records in (self.data['supervision'], list(reversed(self.data['supervision']))):
            self.data['supervision'] = records
            snapshots, errors = audit.collect_read_snapshots(self.data, self.evidence)
            self.assertNotIn(('library', 'src/Allowlist.java'), snapshots)
            self.assertTrue(any('mixed source snapshots' in e for e in errors))
            self.assertTrue(any('missing/conflicting' in e for e in self.errors()))

    def test_unused_historical_knowledge_needs_no_current_source(self):
        for status in ('reviewed', 'stale'):
            with self.subTest(status=status):
                self.control['status'] = status
                self.control['fingerprints'][0]['sha256'] = 'a' * 64
                self.data['control_applications'] = []
                self.data['supervision'] = []
                self.assertEqual(self.errors(), [])

    def test_unresolved_partial_delivery_needs_no_read_or_live_repository(self):
        self.application['outcome'] = 'unresolved'
        self.control['status'] = 'stale'
        self.review.update(decision='blocked', gaps=['Implementation not supplied'])
        self.review.pop('receipts')
        self.source.unlink()
        self.assertEqual(self.errors(), [])

    def test_not_applicable_control_does_not_require_reusing_its_fingerprint(self):
        self.application['outcome'] = 'not_applicable'
        self.control['fingerprints'][0]['sha256'] = 'a' * 64
        self.review['receipts'] = {}
        self.assertEqual(self.errors(), [])

    def test_stale_control_cannot_be_applied_even_if_bytes_match(self):
        self.control['status'] = 'stale'
        self.assertTrue(any('stale/unknown' in e for e in self.errors()))

    def test_every_fingerprint_including_configuration_must_match(self):
        config = self.repo / 'src/allowlist.txt'
        config.write_text('ok\n', encoding='utf-8')
        record, artifact = audit.read_source(self.repo, 'src/allowlist.txt', 1, 1, self.evidence, 'current-run', 'library')
        self.control['fingerprints'].append({'path': 'src/allowlist.txt', 'sha256': record['source_sha256']})
        self.assertTrue(any('allowlist.txt' in e for e in self.errors()))
        self.review['receipts']['config'] = artifact
        self.assertEqual(self.errors(), [])

    def test_cross_run_receipt_cannot_satisfy_binding(self):
        self.review['receipts']['A-read'] = audit.save(self.evidence, {**self.record, 'run_id': 'prior-run'})
        self.assertTrue(any('run_id mismatch' in e for e in self.errors()))

    def test_unsafe_fingerprint_or_receipt_path_cannot_satisfy_binding(self):
        invalid = ('../Allowlist.java', '/src/Allowlist.java', 'C:\\src\\Allowlist.java',
                   '\\src\\Allowlist.java', 'src/../Allowlist.java', 'src//Allowlist.java',
                   './src/Allowlist.java', 'src/Allowlist.java:stream', 'src/\x00Allowlist.java')
        for path in invalid:
            with self.subTest(path=path):
                self.control['fingerprints'][0]['path'] = path
                self.assertTrue(self.errors())
                self.control['fingerprints'][0]['path'] = 'src/Allowlist.java'
                self.review['receipts']['A-read'] = audit.save(self.evidence, {**self.record, 'path': path})
                snapshots, errors = audit.collect_read_snapshots(self.data, self.evidence)
                self.assertEqual(snapshots, {})
                self.assertTrue(errors)
                self.review['receipts']['A-read'] = self.artifact

    def test_safe_separator_and_digest_case_normalization(self):
        self.control['fingerprints'][0].update(path='src\\Allowlist.java', sha256=self.record['source_sha256'].upper())
        self.assertEqual(self.errors(), [])

    def test_path_case_or_different_file_identity_is_not_guessed(self):
        self.control['fingerprints'][0]['path'] = 'src/allowlist.java'
        self.assertTrue(any('missing/conflicting' in e for e in self.errors()))

    def test_saved_evidence_suffices_without_access_to_live_business_source(self):
        self.source.unlink()
        self.assertEqual(self.errors(), [])

    def test_malformed_receipts_return_errors_without_crashing(self):
        for value in (None, [], 'receipt'):
            with self.subTest(value=value):
                self.review['receipts'] = value
                self.assertTrue(self.errors())
        self.review['receipts'] = {'A-read': []}
        self.assertTrue(self.errors())
        self.assertTrue(audit.validate_control_bindings(None, self.evidence))


if __name__ == '__main__':
    unittest.main()
