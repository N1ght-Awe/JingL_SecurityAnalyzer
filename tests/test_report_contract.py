"""Contract regressions, never loaded by a scan. Synthetic data is not a vulnerability POC."""
import copy
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('report_validator', Path(__file__).resolve().parents[1] / 'scripts/validate-report.py')
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def sample():
    finding = {
        'id': 'F-1', 'repo_id': 'test', 'location': 'src/Target.java:8', 'type': 'SQL注入',
        'initial_priority': 'P1', 'priority': 'P1', 'grade_provisional': False,
        'grade_basis': 'Synthetic high-impact fixture', 'status': '源码确认', 'source_closed': True,
        'evidence': {d: {'state': 'observed', 'summary': 'Contract fixture only', 'refs': ['src/Target.java:8']} for d in validator.DIMENSIONS},
        'validation': {'status': 'NOT_RUN', 'scope': 'none', 'goal': 'Fixture target', 'reason': 'No target project',
                       'target_executed': False, 'controls_passed': False, 'result_supported': False,
                       'command': None, 'environment': None, 'exit_code': None, 'executed_at': None, 'artifacts': []},
        'trigger': 'Fixture input', 'exploitation': 'Source-only scope', 'reason': 'Fixture root cause',
        'remediation': 'Fixture binding', 'missing': [], 'related_findings': [],
    }
    return {**{k: validator.VERSION for k in ('schema_version', 'skill_version', 'rules_version')},
            'run_id': 'fixture', 'repositories': [{'repo_id': 'test', 'revision': 'fixture', 'path': '.'}],
            'findings': [finding], 'transport_links': [], 'cross_repo_chains': [], 'limitations': ['Synthetic contract fixture'],
            'metrics': {'candidates': 1, 'reviewed': 1, 'pending_review': 0}}


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = sample()
        self.f = self.data['findings'][0]

    def errors(self):
        return validator.validate(self.data, self.root)

    def confirmed(self):
        raw = b'synthetic tool transcript for contract validation only'
        (self.root/'run.log').write_bytes(raw)
        self.f['status'] = '确认'
        self.f['validation'].update(status='PASSED', scope='isolated', target_executed=True,
            controls_passed=True, result_supported=True, command='fixture-run', environment='fixture',
            exit_code=0, executed_at='2026-09-07T00:00:00Z',
            artifacts=[{'path': 'run.log', 'sha256': hashlib.sha256(raw).hexdigest()}])

    def test_source_only_high_severity_valid(self):
        self.f['priority'] = 'P0'
        self.assertEqual(self.errors(), [])

    def test_patch_rules_keep_report_schema_compatible(self):
        self.data.update(skill_version='2.0.1', rules_version='2.0.1')
        self.assertEqual(self.errors(), [])
        self.data['schema_version'] = '2.0.1'
        self.assertTrue(self.errors())

    def test_claim_without_execution_rejected(self):
        self.f['status'] = '确认'
        self.assertTrue(self.errors())

    def test_confirmed_with_integrity_valid(self):
        self.confirmed()
        self.assertEqual(self.errors(), [])

    def test_missing_target_or_control_or_assertion_rejected(self):
        self.confirmed()
        for key in ('target_executed', 'controls_passed', 'result_supported'):
            with self.subTest(key=key):
                self.f['validation'][key] = False
                self.assertTrue(self.errors())
                self.f['validation'][key] = True

    def test_artifact_tamper_and_missing_rejected(self):
        self.confirmed()
        (self.root/'run.log').write_text('tampered')
        self.assertTrue(self.errors())
        (self.root/'run.log').unlink()
        self.assertTrue(self.errors())

    def test_artifact_cannot_escape_root(self):
        self.confirmed()
        self.f['validation']['artifacts'][0]['path'] = '../outside.log'
        self.assertTrue(self.errors())

    def test_unknown_evidence_prevents_confirmation(self):
        for state in ('inferred', 'missing', 'not_applicable'):
            with self.subTest(state=state):
                self.f['evidence']['Sink']['state'] = state
                self.assertTrue(self.errors())

    def test_pending_high_risk_must_count(self):
        self.f.update(status='待审查', source_closed=False, priority='P0', grade_provisional=True)
        self.assertTrue(self.errors())
        self.data['metrics'].update(reviewed=0, pending_review=1)
        self.assertEqual(self.errors(), [])

    def test_null_grade_is_provisional(self):
        self.f['priority'] = None
        self.assertTrue(self.errors())
        self.f['grade_provisional'] = True
        self.assertEqual(self.errors(), [])

    def test_failed_test_keeps_source_finding(self):
        self.f['validation'].update(status='FAILED', scope='isolated', reason='Target assertion not reproduced', exit_code=1)
        self.assertEqual(self.errors(), [])
        self.f['status'] = '确认'
        self.assertTrue(self.errors())

    def test_legacy_is_not_silently_accepted(self):
        self.data['schema_version'] = '1.1.0'
        self.assertTrue(self.errors())

    def test_duplicate_and_dangling_identifiers(self):
        self.data['findings'].append(copy.deepcopy(self.f))
        self.assertTrue(self.errors())
        self.data['findings'].pop()
        self.f['related_findings'] = ['missing']
        self.assertTrue(self.errors())

    def test_invalid_shapes_report_errors_not_crash(self):
        for key in ('status', 'priority', 'type'):
            with self.subTest(key=key):
                data = sample()
                data['findings'][0][key] = []
                self.assertTrue(validator.validate(data, self.root))

    def test_missing_gap_rejected(self):
        self.f.update(status='待验证', source_closed=False)
        self.assertTrue(self.errors())
        self.f['missing'] = ['Runtime profile unknown']
        self.assertEqual(self.errors(), [])

    def test_zero_tests_cannot_be_marked_passed_without_assertions(self):
        self.confirmed()
        self.f['validation'].update(controls_passed=False, result_supported=False)
        self.assertTrue(self.errors())


if __name__ == '__main__':
    unittest.main()
