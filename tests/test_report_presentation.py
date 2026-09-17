"""Presentation preserves conclusions; threat mapping never manufactures findings."""
import copy
import importlib.util
from pathlib import Path
import unittest
from test_report_extensions import current_sample
from test_report_contract import validator

SPEC = importlib.util.spec_from_file_location('report_renderer', Path(__file__).resolve().parents[1] / 'scripts/render-report.py')
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


def presentation_sample():
    data = current_sample()
    data.update(schema_version='2.2.0', skill_version='2.2.1', rules_version='2.2.1')
    f = data['findings'][0]
    f.update(status='待验证', source_closed=False, missing=['需要核实实际绑定的白名单配置'])
    data['supervision'] = [{'finding_id': f['id'], 'decision': 'blocked', 'rationale': '配置尚未提供',
                            'repair_rounds': 0, 'gaps': ['缺有效配置']}]
    data['threat_model'] = {
        'summary': '合成示例：租户查询服务；不代表实际扫描结果。',
        'actors': ['普通租户可控制排序参数；不能自定数据库字段'],
        'boundaries': [{'name': '租户请求 → 数据查询', 'asset_ids': ['backend'],
            'rule': '排序参数不得改变允许字段之外的查询结构', 'control': '白名单映射，实际配置待核实',
            'evidence': {'state': 'inferred', 'summary': '示例假设，不是目标源码事实', 'refs': []},
            'finding_ids': ['F-1']}],
        'assumptions': ['未获得实际部署配置，不能判断白名单是否生效。'],
    }
    return data


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.data = presentation_sample()

    def test_valid_model_renders_without_mutating_source_or_promoting_status(self):
        before = copy.deepcopy(self.data)
        text = renderer.render(self.data, '.')
        self.assertEqual(self.data, before)
        self.assertIn('待验证', text)
        self.assertIn('源码确认 **0**', text)
        self.assertIn('真实验证确认 **0**', text)
        self.assertIn('白名单映射', text)

    def test_new_rules_require_model_but_old_reports_remain_readable(self):
        del self.data['threat_model']
        self.assertTrue(validator.validate(self.data, '.'))
        text = renderer.render(current_sample(), '.')
        self.assertIn('历史报告未提供威胁概览', text)

    def test_observed_boundary_needs_evidence(self):
        self.data['threat_model']['boundaries'][0]['evidence']['state'] = 'observed'
        self.assertTrue(validator.validate(self.data, '.'))

    def test_unknown_asset_and_finding_cannot_be_invented(self):
        for key in ('asset_ids', 'finding_ids'):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data['threat_model']['boundaries'][0][key] = ['unknown']
                self.assertTrue(validator.validate(data, '.'))

    def test_missing_information_must_remain_visible(self):
        self.data['threat_model']['assumptions'] = []
        self.assertTrue(validator.validate(self.data, '.'))

    def test_partial_empty_result_is_not_a_clean_bill_of_health(self):
        self.data['findings'] = []
        self.data['supervision'] = []
        self.data['metrics'].update(candidates=0, reviewed=0)
        self.data['threat_model']['boundaries'][0]['finding_ids'] = []
        self.data['coverage_status'] = 'partial'
        self.data['coverage'][0].update(status='partial', reviewed_asset_ids=[], gaps=['源码未审完'])
        text = renderer.render(self.data, '.')
        self.assertIn('未覆盖部分不能作无漏洞结论', text)
        self.assertIn('源码未审完', text)

    def test_rejected_candidates_do_not_disappear_or_count_as_vulnerabilities(self):
        # Historical fixture avoids fabricating passing supervision just for display tests.
        data = current_sample()
        data['findings'][0].update(status='误报', reason='同路径参数化绑定排除该候选')
        text = renderer.render(data, '.')
        self.assertIn('已排除 **1**', text)
        self.assertIn('同路径参数化绑定排除该候选', text)
        self.assertIn('源码确认 **0**', text)

    def test_untrusted_source_text_cannot_break_table_or_embed_html(self):
        self.data['findings'][0]['reason'] = '<script>alert(1)</script>|[link](bad)\nnext'
        text = renderer.render(self.data, '.')
        self.assertNotIn('<script>', text)
        self.assertIn('\\|\\[link\\]', text)
        self.assertIn('<br>next', text)

    def test_invalid_report_is_not_rendered(self):
        self.data['findings'][0]['status'] = '确认'
        with self.assertRaises(ValueError):
            renderer.render(self.data, '.')

    def test_model_shapes_and_legacy_downgrade_fail(self):
        for value in (None, [], {'summary': 'x', 'actors': [], 'boundaries': [], 'assumptions': []}):
            data = copy.deepcopy(self.data)
            data['threat_model'] = value
            self.assertTrue(validator.validate(data, '.'))
        self.data.update(schema_version='2.1.0', skill_version='2.1.0', rules_version='2.1.0')
        self.assertTrue(validator.validate(self.data, '.'))

    def test_link_records_are_preserved_without_inventing_execution(self):
        self.data['transport_links'] = [{'caller': 'Query', 'protocol': 'HTTP', 'execution': '未执行', 'extra': '原记录补充字段'}]
        self.data['cross_repo_chains'] = [{'caller': 'A', 'callee': 'unknown', 'missing': ['下游未提供']}]
        text = renderer.render(self.data, '.')
        self.assertIn('原记录补充字段', text)
        self.assertIn('下游未提供', text)


if __name__ == '__main__':
    unittest.main()
