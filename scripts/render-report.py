"""Render a validated JingL JSON report as one consistent Markdown document."""
import argparse
from collections import Counter
import html
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('report_contract', Path(__file__).with_name('validate-report.py'))
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
EXECUTION = {'NOT_RUN': '未运行', 'BLOCKED': '受阻', 'PASSED': '通过',
             'FAILED': '失败', 'TIMEOUT': '超时', 'SKIPPED': '未执行（已说明原因）'}
SCOPE = {'none': '无执行', 'isolated': '局部真实目标', 'integration': '集成', 'end_to_end': '端到端'}
STATE = {'observed': '已观察', 'inferred': '推断', 'missing': '缺证据', 'not_applicable': '不适用'}
DIMENSIONS = dict(zip(CONTRACT.DIMENSIONS, ('来源', '传播', '敏感操作', '净化', '权限防护', '传输', '前提', '影响')))
LABELS = {'candidates': '候选总数', 'reviewed': '已审候选', 'pending_review': '待审候选',
          'total_wall_seconds': '总耗时（秒）', 'input_tokens': '输入token', 'output_tokens': '输出token',
          'cached_tokens': '缓存token', 'caller': '调用方', 'callee': '被调用方', 'protocol': '协议',
          'endpoint_or_topic': '端点或消息主题', 'data_mapping': '字段映射', 'auth_context': '身份上下文',
          'evidence_refs': '证据引用', 'missing': '缺口', 'related_findings': '关联候选',
          'execution': '执行情况', 'tool': '工具', 'environment': '环境', 'id': '编号'}


def display(value):
    if value is None:
        return '未记录'
    if isinstance(value, list):
        return '；'.join(display(x) for x in value) if value else '无记录'
    if isinstance(value, dict):
        return '；'.join(f'{k}：{display(v)}' for k, v in value.items())
    return str(value)


def safe(value):
    text = html.escape(display(value), quote=False).replace('\\', '\\\\')
    for char in ('|', '`', '*', '_', '[', ']', '#', '!'):
        text = text.replace(char, '\\' + char)
    return text.replace('\r\n', '\n').replace('\r', '\n').replace('\n', '<br>')


def table(headers, rows):
    return ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |'] + [
        '| ' + ' | '.join(safe(v) for v in row) + ' |' for row in rows] + ['']


def ordered(findings):
    rank = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3, None: 4}
    return sorted(findings, key=lambda f: (rank[f['priority']], f['id']))


def render(data, evidence_root, source_name='report.json'):
    errors = CONTRACT.validate(data, evidence_root)
    if errors:
        raise ValueError('\n'.join(errors))
    findings = ordered(data['findings'])
    active = [f for f in findings if f['status'] != '误报']
    excluded = [f for f in findings if f['status'] == '误报']
    counts = Counter(f['status'] for f in findings)
    partial = data.get('coverage_status') == 'partial'
    coverage_label = {'complete': '已完成声明范围', 'partial': '部分完成，详见扫描统计'}.get(data.get('coverage_status'), '历史报告未提供覆盖状态')
    lines = ['# JingL 安全分析报告', '', f"运行：{safe(data['run_id'])} · 规则：{safe(data['rules_version'])}", '',
             '## 漏洞扫描报告', '', '### 结果总览', '',
             f'覆盖：**{coverage_label}**。', '',
             f"真实验证确认 **{counts['确认']}** 项，源码确认 **{counts['源码确认']}** 项，待审查/待验证/缺源码 **{sum(counts[s] for s in ('待审查', '待验证', '缺失关键源码'))}** 项，已排除 **{counts['误报']}** 项。", '',
             '未执行不表示低风险；源码确认与真实运行确认分别统计。', '']
    if not active:
        lines += ['当前报告没有未排除候选；这不证明系统不存在漏洞。' if not partial else '当前已审范围没有未排除候选；未覆盖部分不能作无漏洞结论。', '']
    lines += ['### 系统与威胁边界', '']
    model = data.get('threat_model')
    if model:
        lines += [safe(model['summary']), '', '**主体与初始能力：** ' + safe(model['actors']), '']
        assets = {a['asset_id']: a for a in data['assets']}
        rows = []
        for b in model['boundaries']:
            e = b['evidence']
            rows.append((b['name'], [f"{a}：{assets[a]['path']}" for a in b['asset_ids']], b['rule'],
                         b['control'], f"{STATE[e['state']]}：{e['summary']}；依据：{display(e['refs'])}",
                         b['finding_ids'] or '无关联候选（不代表已证安全）'))
        if rows:
            lines += table(('边界', '保护资产', '必须守住的规则', '当前防护', '依据', '关联候选'), rows)
        else:
            lines += ['边界尚未建立，缺口见下方。', '']
        lines += ['**假设与待核实条件：** ' + safe(model['assumptions'] or ['未记录额外假设']), '']
    else:
        lines += ['历史报告未提供威胁概览；未根据漏洞清单反向编造。', '']
    lines += ['### 问题清单', '']

    def finding_row(f):
        v = f['validation']
        grade = f['priority'] or '待定'
        if f['grade_provisional']:
            grade += '（暂定）'
        return (f['id'], f.get('title') or f['type'], grade, f['status'],
                EXECUTION[v['status']] + ' / ' + SCOPE[v['scope']], f['repo_id'] + ':' + f['location'])

    headers = ('编号', '问题', '级别', '结论', '执行验证', '位置')
    lines += table(headers, [finding_row(f) for f in active]) if active else ['无未排除候选。', '']
    lines += ['### 问题详情', '']
    for f in active:
        v = f['validation']
        lines += [f"#### {safe(f['id'])} · {safe(f.get('title') or f['type'])}", '']
        details = [('结论与级别', f"{f['status']}；{f['priority'] or '待定'}；{f['grade_basis']}"),
                   ('位置', f"{f['repo_id']}:{f['location']}"), ('触发与前提', f['trigger']),
                   ('已支持的影响与利用范围', f['exploitation']), ('根因', f['reason']),
                   ('验证情况', f"{EXECUTION[v['status']]} / {SCOPE[v['scope']]}；目标：{v['goal']}；说明：{v['reason']}"),
                   ('待补证据', f['missing']), ('修复方向', f['remediation']), ('关联候选', f['related_findings'])]
        lines += table(('项目', '内容'), details)
        lines += ['<details>', '<summary>查看八维证据</summary>', '']
        lines += table(('维度', '状态', '事实及范围', '引用'), [
            (DIMENSIONS[name], STATE[f['evidence'][name]['state']], f['evidence'][name]['summary'], f['evidence'][name]['refs']) for name in DIMENSIONS])
        lines += ['</details>', '']
    lines += ['### 已排除候选', '']
    lines += table((*headers, '排除依据'), [(*finding_row(f), f['reason']) for f in excluded]) if excluded else ['无。', '']
    lines += ['### 防护体系观察', '']
    observations = data.get('control_observations', [])
    lines += table(('编号', '位置', '期望防护', '观察', '证据边界', '依据'), [
        (o['id'], o['location'], o['expected_control'], o['observation'], o['risk_boundary'], o['evidence_refs']) for o in observations]) if observations else ['无独立记录；不据此认定防护体系完整。', '']

    def link_section(title, key):
        lines.extend(['## ' + title, ''])
        if not data[key]:
            lines.extend(['本次无记录；不推断链路不存在或已完成运行验证。', ''])
        # Existing contracts allow different record shapes; preserve every field in a compact two-column view.
        for n, record in enumerate(data[key], 1):
            lines.extend([f'### 链路 {n}', ''])
            lines.extend(table(('项目', '记录'), [(LABELS.get(k, k), v) for k, v in record.items()] if isinstance(record, dict) else [('内容', record)]))

    link_section('传输链路探测分析', 'transport_links')
    lines += ['## 扫描统计', '']
    lines += table(('仓库', '版本', '范围位置'), [(r['repo_id'], r['revision'], r['path']) for r in data['repositories']])
    lines += table(('类型', '必需资产', '已审资产', '状态', '缺口'), [
        (c['type'], c['required_asset_ids'], c['reviewed_asset_ids'], '完整' if c['status'] == 'complete' else '部分', c['gaps']) for c in data.get('coverage', [])])
    lines += table(('统计项', '值'), [(LABELS.get(k, k), v) for k, v in data['metrics'].items()])
    lines += ['**局限与未完成工作：** ' + safe(data['limitations'] or ['未记录额外限制；不表示不存在未知风险']), '']
    link_section('跨代码仓调用链分析', 'cross_repo_chains')
    lines += ['---', '', '结构化原件：' + safe(source_name) + '。执行命令、原始日志、监督回执和摘要保留在JSON及其证据目录；本文件仅作一致展示。', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--evidence-root', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    output = args.out or args.report.with_suffix('.md')
    try:
        if output.resolve() == args.report.resolve():
            raise ValueError('output must not overwrite the JSON source')
        data = json.loads(args.report.read_text(encoding='utf-8-sig'))
        content = render(data, args.evidence_root or args.report.parent, args.report.name)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding='utf-8', newline='\n')
    except (OSError, ValueError) as exc:
        parser.exit(1, str(exc) + '\n')
    print(f'PASS: rendered {output}')


if __name__ == '__main__':
    main()
