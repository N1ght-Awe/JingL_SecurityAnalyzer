"""Synthetic source/evidence behavior, not a real-project accuracy benchmark."""
import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_report_extensions import current_sample
from test_report_contract import validator

SPEC = importlib.util.spec_from_file_location('audit_evidence', Path(__file__).resolve().parents[1] / 'scripts/audit_evidence.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


class SupervisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.source = self.repo / 'Allowlist.java'
        self.source.write_text('class Allowlist {\n static boolean A(String s) {\n  return "ok".equals(s);\n }\n static void handle(String s) {\n  if (!A(s)) { return; }\n }}\n', encoding='utf-8')
        self.data = current_sample()
        self.data.update(schema_version='2.2.0', skill_version='2.2.0', rules_version='2.2.0')
        _, read = audit.read_source(self.repo, 'Allowlist.java', 1, 7, self.evidence, 'fixture', 'test')
        # Synthetic discovery log for contract tests; actual subprocess behavior tested separately.
        search = audit.save(self.evidence, {'kind': 'search', 'run_id': 'fixture', 'repo_id': 'test',
            'runs': {'grep': {'command': ['synthetic-fixture-search'], 'exit_code': 0, 'timed_out': False, 'stdout': 'A', 'stderr': ''}}})
        self.need = {'receipt_id': 'read', 'repo_id': 'test', 'path': 'Allowlist.java', 'start': 1, 'end': 7}
        self.review = {'finding_id': 'F-1', 'decision': 'pass', 'rationale': 'Synthetic review only',
            'repair_rounds': 0, 'gaps': [], 'receipts': {'read': read, 'search': search},
            'checks': {name: {'state': 'resolved', 'reason': 'Fixture obligation', 'reads': [copy.deepcopy(self.need)]}
                       for name in audit.OBLIGATIONS},
            'discovery_receipt_ids': ['search'], 'discovery_assessment': 'Fixture registered wrapper examined',
            'edges': [{'from': 'Handle.s', 'to': 'A.s', 'resolution': 'resolved',
                       'reason': 'Fixture source binding', 'reads': [copy.deepcopy(self.need)]}]}
        self.data['supervision'] = [self.review]

    def errors(self):
        return validator.validate(self.data, self.evidence)

    def test_current_report_and_legacy_are_supported(self):
        self.assertEqual(self.errors(), [])
        self.assertEqual(validator.validate(current_sample(), self.evidence), [])

    def test_final_statuses_all_require_supervision(self):
        for status in ('源码确认', '确认', '误报'):
            with self.subTest(status=status):
                self.data['findings'][0]['status'] = status
                self.data['supervision'] = []
                self.assertTrue(any('supervision' in x for x in self.errors()))

    def test_missing_allowlist_implementation_blocks_final(self):
        _, call = audit.read_source(self.repo, 'Allowlist.java', 5, 7, self.evidence, 'fixture', 'test')
        self.review['receipts']['read'] = call
        self.assertTrue(any('not read' in x for x in self.errors()))

    def test_targeted_reread_closes_required_range(self):
        _, implementation = audit.read_source(self.repo, 'Allowlist.java', 2, 4, self.evidence, 'fixture', 'test')
        self.review['receipts']['implementation'] = implementation
        self.review['checks']['Guard']['reads'] = [{**self.need, 'receipt_id': 'implementation', 'start': 2, 'end': 4}]
        self.review['repair_rounds'] = 1
        self.assertEqual(self.errors(), [])

    def test_unresolved_edge_blocks_false_positive(self):
        self.data['findings'][0]['status'] = '误报'
        self.review['edges'][0]['resolution'] = 'unresolved'
        self.assertTrue(any('unresolved edge' in x for x in self.errors()))

    def test_counterevidence_cannot_be_skipped(self):
        self.review['checks']['counterevidence']['state'] = 'not_applicable'
        self.assertTrue(self.errors())

    def test_partial_finding_can_be_delivered_without_fabricated_receipts(self):
        self.data['findings'][0].update(status='待验证', source_closed=False, missing=['Unresolved interface receiver'])
        self.review.update(decision='blocked', gaps=['Unresolved interface receiver'], receipts={}, checks={}, edges=[])
        self.assertEqual(self.errors(), [])

    def test_new_contract_cannot_be_silently_downgraded(self):
        self.data['schema_version'] = '2.1.0'
        self.assertTrue(self.errors())
        self.data.update(skill_version='2.1.0', rules_version='2.1.0')
        self.assertTrue(self.errors())

    def test_receipt_tampering_is_rejected(self):
        p = self.evidence / self.review['receipts']['read']['path']
        p.write_text('{}', encoding='utf-8')
        self.assertTrue(any('digest mismatch' in x for x in self.errors()))

    def test_snapshot_tampering_is_rejected(self):
        artifact = self.review['receipts']['read']
        r = json.loads((self.evidence / artifact['path']).read_text(encoding='utf-8'))
        (self.evidence / r['snapshot']).write_bytes(b'changed')
        self.assertTrue(any('snapshot digest mismatch' in x for x in self.errors()))

    def test_forged_excerpt_rejected_even_with_new_receipt_digest(self):
        a = self.review['receipts']['read']
        r = json.loads((self.evidence / a['path']).read_text(encoding='utf-8'))
        r['content'] = 'not the source'
        self.review['receipts']['read'] = audit.save(self.evidence, r)
        self.assertTrue(any('content does not match' in x for x in self.errors()))

    def test_cross_run_receipt_rejected(self):
        self.data['run_id'] = 'another-run'
        self.assertTrue(any('run_id mismatch' in x for x in self.errors()))

    def test_mixed_versions_of_same_file_rejected(self):
        self.source.write_text('class Changed {}\n', encoding='utf-8')
        _, other = audit.read_source(self.repo, 'Allowlist.java', 1, 1, self.evidence, 'fixture', 'test')
        self.review['receipts']['other'] = other
        self.assertTrue(any('mixed source' in x for x in self.errors()))

    def test_paths_cannot_escape_roots(self):
        for path in ('../outside', 'C:\\secret', '/etc/passwd', '\\server\\secret'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.local(self.evidence, path)

    def test_invalid_or_excessive_ranges_fail_before_receipt(self):
        for start, end in ((0, 7), (1, 8), (5, 2)):
            with self.assertRaises(ValueError):
                audit.read_source(self.repo, 'Allowlist.java', start, end, self.evidence, 'fixture', 'test')
        self.source.write_text('x' * 16001, encoding='utf-8')
        with self.assertRaises(ValueError):
            audit.read_source(self.repo, 'Allowlist.java', 1, 1, self.evidence, 'fixture', 'test')

    def test_unknown_receipts_and_wrong_shapes_rejected(self):
        for key, value in [('supervision', None), ('findings', None), ('repositories', None)]:
            data = copy.deepcopy(self.data)
            data[key] = value
            self.assertTrue(validator.validate(data, self.evidence))
        self.review['checks']['Guard']['reads'][0]['receipt_id'] = 'unknown'
        self.assertTrue(self.errors())

    def test_retry_limit_and_no_gaps_on_pass(self):
        self.review['repair_rounds'] = 3
        self.assertTrue(self.errors())
        self.review['repair_rounds'] = 2
        self.review['gaps'] = ['Still missing A']
        self.assertTrue(self.errors())

    @unittest.skipUnless(shutil.which('rg'), 'rg unavailable')
    def test_real_rg_search_with_ast_unavailable(self):
        rg = shutil.which('rg')
        with patch.object(audit.shutil, 'which', side_effect=lambda name: rg if name == 'rg' else None):
            record, artifact = audit.search(self.repo, '.', 'A', 'A($$$ARGS)', 'Java', self.evidence, 'fixture', 'test')
        self.assertFalse(record['ast_available'])
        self.assertEqual(record['runs']['grep']['exit_code'], 0)
        self.assertIn('Allowlist.java', record['runs']['grep']['stdout'])
        self.assertEqual(audit.load_receipt(self.evidence, artifact, 'fixture'), record)

    def test_ast_adapter_passes_literal_arguments_without_shell(self):
        result = subprocess.CompletedProcess([], 0, b'[]', b'')
        with patch.object(audit.shutil, 'which', side_effect=lambda n: n), patch.object(audit.subprocess, 'run', return_value=result) as run:
            record, _ = audit.search(self.repo, '.', 'A', 'A($$$ARGS)', 'Java', self.evidence, 'fixture', 'test')
        argv = record['runs']['ast']['command']
        self.assertIn('A($$$ARGS)', argv)
        self.assertIn('--json=compact', argv)
        self.assertFalse(any(call.kwargs.get('shell') for call in run.call_args_list))

    def test_tool_timeout_preserves_partial_raw_output(self):
        with patch.object(audit.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['rg'], 1, b'partial')):
            result = audit.execute(['rg'], self.repo, timeout=1)
        self.assertTrue(result['timed_out'])
        self.assertEqual(result['stdout'], 'partial')

    def test_failed_discovery_cannot_pass(self):
        r = {'kind': 'search', 'run_id': 'fixture', 'repo_id': 'test',
             'runs': {'grep': {'command': ['synthetic-fixture-search'], 'exit_code': 2, 'timed_out': False, 'stdout': '', 'stderr': 'fixture failure'}}}
        self.review['receipts']['search'] = audit.save(self.evidence, r)
        self.assertTrue(any('discovery failed' in x for x in self.errors()))

    @unittest.skipUnless(shutil.which('ast-grep'), 'optional ast-grep unavailable')
    def test_real_ast_search_distinguishes_call_from_comment(self):
        with self.source.open('a', encoding='utf-8') as stream:
            stream.write('// A("comment")\n')
        record, _ = audit.search(self.repo, '.', 'A', 'A($$$ARGS)', 'Java', self.evidence, 'fixture', 'test')
        self.assertEqual(record['runs']['ast']['exit_code'], 0, record['runs']['ast']['stderr'])
        matches = json.loads(record['runs']['ast']['stdout'])
        self.assertEqual([match['text'] for match in matches], ['A(s)'])

    def test_no_tools_returns_an_honest_empty_execution_record(self):
        with patch.object(audit.shutil, 'which', return_value=None):
            record, artifact = audit.search(self.repo, '.', 'A', 'A($$$ARGS)', 'Java', self.evidence, 'fixture', 'test')
        self.assertEqual(record['runs'], {})
        self.review['receipts']['search'] = artifact
        self.assertTrue(any('discovery failed' in x for x in self.errors()))

    def test_success_flag_without_raw_execution_record_is_rejected(self):
        record = {'kind': 'search', 'run_id': 'fixture', 'repo_id': 'test',
                  'runs': {'grep': {'exit_code': 0, 'timed_out': False}}}
        self.review['receipts']['search'] = audit.save(self.evidence, record)
        self.assertTrue(any('record incomplete' in x for x in self.errors()))

    def test_evidence_does_not_pollute_scanned_repository(self):
        with self.assertRaises(ValueError):
            audit.read_source(self.repo, 'Allowlist.java', 1, 7, self.repo / 'evidence', 'fixture', 'test')
        with self.assertRaises(ValueError):
            audit.search(self.repo, '.', 'A', None, None, self.repo / 'evidence', 'fixture', 'test')
        self.assertFalse((self.repo / 'evidence').exists())


if __name__ == '__main__':
    unittest.main()
