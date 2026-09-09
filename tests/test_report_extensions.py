"""Contract behavior for coverage gaps and reusable control reviews, not exploit PoCs."""
import copy
import unittest
from test_report_contract import sample, validator


def current_sample():
    data = sample()
    data.update(schema_version='2.1.0', skill_version='2.1.0', rules_version='2.1.0',
                scan_types=['SQL注入'], coverage_status='complete',
                assets=[{'asset_id': 'backend', 'repo_id': 'test', 'path': 'src',
                         'kind': 'backend', 'evidence_refs': ['inventory:src']}],
                coverage=[{'type': 'SQL注入', 'required_asset_ids': ['backend'],
                           'reviewed_asset_ids': ['backend'], 'status': 'complete',
                           'gaps': [], 'evidence_refs': ['scope:backend']}],
                control_knowledge=[], control_applications=[], control_observations=[])
    return data


def add_review(data):
    data['control_knowledge'] = [{
        'id': 'A-review', 'repo_id': 'test', 'symbol': 'Allowlist.A', 'revision': 'fixture',
        'status': 'reviewed', 'fingerprints': [{'path': 'src/Allowlist.java', 'sha256': 'a' * 64}],
        'protects': ['SQL注入'], 'contract': 'Maps selected sort field to fixed SQL identifier',
        'assumptions': 'Caller rejects failed lookup and uses returned value',
        'limitations': 'Does not authorize data access', 'evidence_refs': ['Allowlist.java:4'],
    }]
    data['control_applications'] = [{
        'id': 'A-call-1', 'control_id': 'A-review', 'repo_id': 'test', 'location': 'Query.java:9',
        'finding_ids': [], 'outcome': 'applicable', 'reason': 'Same contract, output used without transformation',
        'checks': {name: {'state': 'observed', 'result': 'pass', 'summary': 'Synthetic path check: ' + name,
                          'refs': ['Query.java:9']} for name in validator.APPLICATION_CHECKS},
    }]


class ExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.data = current_sample()

    def errors(self):
        return validator.validate(self.data, '.')

    def xss(self):
        self.data['scan_types'] = ['XSS']
        self.data['findings'][0]['type'] = 'XSS'
        self.data['coverage'][0]['type'] = 'XSS'
        self.data['assets'].append({'asset_id': 'frontend', 'repo_id': 'test', 'path': 'web/src',
                                   'kind': 'frontend', 'evidence_refs': ['inventory:web']})

    def test_current_and_legacy_reports_accepted(self):
        self.assertEqual(self.errors(), [])
        self.assertEqual(validator.validate(sample(), '.'), [])

    def test_no_findings_still_requires_frontend_accounting(self):
        self.xss()
        self.data['findings'] = []
        self.data['metrics'].update(candidates=0, reviewed=0)
        self.assertTrue(self.errors())

    def test_templates_cannot_disappear_from_xss(self):
        self.xss()
        self.data['assets'][-1]['kind'] = 'templates'
        self.assertTrue(self.errors())

    def test_partial_report_preserves_local_source_finding(self):
        self.xss()
        self.data['coverage'][0].update(required_asset_ids=['backend', 'frontend'], status='partial',
                                        gaps=['Frontend present but not reviewed'])
        self.data['coverage_status'] = 'partial'
        self.assertEqual(self.errors(), [])
        self.assertEqual(self.data['findings'][0]['status'], '源码确认')
        self.data['coverage_status'] = 'complete'
        self.assertTrue(self.errors())

    def test_full_asset_set_with_framework_gap_is_not_complete(self):
        self.data['coverage'][0]['gaps'] = ['Some framework routes unsupported']
        self.assertTrue(self.errors())
        self.data['coverage'][0]['status'] = 'partial'
        self.data['coverage_status'] = 'partial'
        self.assertEqual(self.errors(), [])

    def test_selected_type_cannot_be_omitted(self):
        self.data['scan_types'].append('XSS')
        self.assertTrue(self.errors())

    def test_current_rules_cannot_downgrade_schema(self):
        data = sample()
        data.update(skill_version='2.1.0', rules_version='2.1.0')
        self.assertTrue(validator.validate(data, '.'))

    def test_legacy_cannot_silently_ignore_new_contract(self):
        data = sample()
        data['coverage_status'] = 'complete'
        self.assertTrue(validator.validate(data, '.'))

    def test_old_poc_mode_does_not_substitute_execution(self):
        self.data['findings'][0].update(status='确认', poc_validation_mode='HTTP_POC_DERIVED')
        self.assertTrue(self.errors())

    def test_control_absence_is_observed_fact_not_missing_evidence(self):
        e = self.data['findings'][0]['evidence']['Guard']
        e.update(state='observed', summary='Exact route checked; applicable control absent')
        self.assertEqual(self.errors(), [])
        e['state'] = 'missing'
        self.assertTrue(self.errors())

    def test_review_can_be_reused_with_distinct_call_evidence(self):
        add_review(self.data)
        second = copy.deepcopy(self.data['control_applications'][0])
        second.update(id='A-call-2', location='OtherQuery.java:5')
        for check in second['checks'].values():
            check['refs'] = ['OtherQuery.java:5']
        self.data['control_applications'].append(second)
        self.assertEqual(self.errors(), [])

    def test_stale_review_cannot_be_applied(self):
        add_review(self.data)
        self.data['control_knowledge'][0]['status'] = 'stale'
        self.assertTrue(self.errors())
        self.data['control_applications'][0]['outcome'] = 'unresolved'
        self.assertEqual(self.errors(), [])

    def test_missing_current_path_check_blocks_application(self):
        add_review(self.data)
        application = self.data['control_applications'][0]
        for name in validator.APPLICATION_CHECKS:
            with self.subTest(name=name):
                application['checks'][name]['state'] = 'missing'
                self.assertTrue(self.errors())
                application['checks'][name]['state'] = 'observed'

    def test_changed_downstream_keeps_review_but_not_application(self):
        add_review(self.data)
        app = self.data['control_applications'][0]
        app.update(outcome='not_applicable', reason='Output decoded again after allowlist')
        app['checks']['downstream']['summary'] = 'Transformation invalidates reviewed contract'
        app['checks']['downstream']['result'] = 'fail'
        self.assertEqual(self.errors(), [])
        self.assertEqual(self.data['control_knowledge'][0]['status'], 'reviewed')
        app['outcome'] = 'applicable'
        self.assertTrue(self.errors())

    def test_sql_control_does_not_protect_authorization(self):
        add_review(self.data)
        self.data['control_knowledge'][0]['protects'] = ['权限控制']
        self.data['control_applications'][0]['finding_ids'] = ['F-1']
        self.assertTrue(self.errors())

    def test_unknown_control_or_finding_reference_rejected(self):
        add_review(self.data)
        app = self.data['control_applications'][0]
        app['control_id'] = 'unknown'
        self.assertTrue(self.errors())
        app['control_id'] = 'A-review'
        app['finding_ids'] = ['unknown']
        self.assertTrue(self.errors())

    def test_evidence_and_fingerprint_required_for_reuse(self):
        add_review(self.data)
        self.data['control_applications'][0]['checks']['identity']['refs'] = []
        self.assertTrue(self.errors())
        self.data['control_applications'][0]['checks']['identity']['refs'] = ['Query.java:9']
        self.data['control_knowledge'][0]['fingerprints'] = []
        self.assertTrue(self.errors())

    def test_fingerprint_paths_are_portably_relative(self):
        add_review(self.data)
        fp = self.data['control_knowledge'][0]['fingerprints'][0]
        for value in ('../secret', '/etc/config', 'C:\\config', '\\config', 'src/../../config'):
            with self.subTest(value=value):
                fp['path'] = value
                self.assertTrue(self.errors())

    def test_control_gap_is_separate_from_vulnerability_count(self):
        self.data['control_observations'] = [{
            'id': 'O-1', 'repo_id': 'test', 'kind': 'control_gap', 'location': 'Filter.java:1',
            'expected_control': 'Policy requires control on route', 'observation': 'Not registered',
            'risk_boundary': 'No exploitable rendering chain demonstrated',
            'evidence_refs': ['Filter.java:1'], 'related_findings': [],
        }]
        self.assertEqual(self.errors(), [])
        self.data['metrics']['candidates'] = 2
        self.assertTrue(self.errors())
        self.data['metrics']['candidates'] = 1
        self.data['control_observations'][0]['priority'] = 'P1'
        self.assertTrue(self.errors())

    def test_wrong_shapes_return_errors_not_crash(self):
        add_review(self.data)
        for key in validator.EXTENSIONS:
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data[key] = None
                self.assertTrue(validator.validate(data, '.'))
        for key in ('control_id', 'outcome', 'checks'):
            data = copy.deepcopy(self.data)
            data['control_applications'][0][key] = []
            self.assertTrue(validator.validate(data, '.'))


if __name__ == '__main__':
    unittest.main()
