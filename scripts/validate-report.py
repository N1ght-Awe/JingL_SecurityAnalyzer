"""Validate JingL 2.0 report contracts and evidence integrity; not vulnerability truth."""
import argparse
import hashlib
import json
import re
from pathlib import Path

VERSION = '2.0.0'
DIMENSIONS = ('Source', 'Propagation', 'Sink', 'Sanitizer', 'Guard',
              'Transport', 'Preconditions', 'Impact')
STATES = {'observed', 'inferred', 'missing', 'not_applicable'}
STATUSES = {'待审查', '缺失关键源码', '待验证', '源码确认', '确认', '误报'}
EXECUTIONS = {'NOT_RUN', 'BLOCKED', 'PASSED', 'FAILED', 'TIMEOUT', 'SKIPPED'}
SCOPES = {'none', 'isolated', 'integration', 'end_to_end'}
GRADES = {None, 'P0', 'P1', 'P2', 'P3'}
TYPES = {p.name for p in (Path(__file__).resolve().parents[1] / 'skill').iterdir()
         if p.is_dir()}


def validate(data, evidence_root):
    errors = []
    root = Path(evidence_root).resolve()

    def check(ok, message):
        if not ok:
            errors.append(message)

    def string(value):
        return isinstance(value, str) and bool(value.strip())

    def member(value, choices):
        return isinstance(value, (str, type(None))) and value in choices

    if not isinstance(data, dict):
        return ['Report must be an object']
    for key in ('schema_version', 'skill_version', 'rules_version'):
        check(data.get(key) == VERSION, f'{key}: expected {VERSION}; adapt legacy data explicitly')
    check(string(data.get('run_id')), 'run_id required')
    for key in ('repositories', 'findings', 'transport_links', 'cross_repo_chains', 'limitations'):
        check(isinstance(data.get(key), list), f'{key}: expected array')
    repos = data.get('repositories', [])
    repos = repos if isinstance(repos, list) else []
    repo_ids = []
    for repo in repos:
        if not isinstance(repo, dict):
            errors.append('repository must be an object')
            continue
        for key in ('repo_id', 'revision', 'path'):
            check(string(repo.get(key)), f'repository.{key} required')
        if string(repo.get('repo_id')):
            repo_ids.append(repo['repo_id'])
    check(len(repo_ids) == len(set(repo_ids)), 'duplicate repo_id')
    findings = data.get('findings', [])
    findings = findings if isinstance(findings, list) else []
    ids = []
    relations = []
    pending = 0
    for pos, f in enumerate(findings):
        label = f'findings[{pos}]'
        if not isinstance(f, dict):
            errors.append(f'{label}: expected object')
            continue
        for key in ('id', 'location', 'type', 'grade_basis', 'trigger', 'exploitation', 'reason', 'remediation'):
            check(string(f.get(key)), f'{label}.{key} required')
        if string(f.get('id')):
            ids.append(f['id'])
        check(f.get('repo_id') in repo_ids, f'{label}: unknown repo_id')
        check(member(f.get('type'), TYPES), f'{label}: unknown vulnerability type')
        for key in ('initial_priority', 'priority'):
            check(key in f and member(f.get(key), GRADES), f'{label}.{key}: invalid or missing grade')
        check(type(f.get('grade_provisional')) is bool, f'{label}.grade_provisional: expected boolean')
        if f.get('priority') is None:
            check(f.get('grade_provisional') is True, f'{label}: ungraded finding must be provisional')
        check(type(f.get('source_closed')) is bool, f'{label}.source_closed: expected boolean')
        status = f.get('status')
        check(member(status, STATUSES), f'{label}: invalid status')
        pending += status == '待审查'
        for key in ('missing', 'related_findings'):
            arr = f.get(key)
            check(isinstance(arr, list) and all(string(x) for x in arr), f'{label}.{key}: expected string array')
        if isinstance(f.get('related_findings'), list):
            relations.extend(x for x in f['related_findings'] if string(x))
        if status in ('缺失关键源码', '待验证'):
            check(bool(f.get('missing')), f'{label}: unresolved status needs explicit gap')
        if status == '待审查':
            check(f.get('source_closed') is False, f'{label}: pending review cannot be source-closed')
        evidence = f.get('evidence')
        check(isinstance(evidence, dict), f'{label}.evidence: expected object')
        evidence = evidence if isinstance(evidence, dict) else {}
        for dim in DIMENSIONS:
            item = evidence.get(dim)
            if not isinstance(item, dict):
                errors.append(f'{label}.evidence.{dim}: required object')
                continue
            check(member(item.get('state'), STATES), f'{label}.{dim}: invalid evidence state')
            check(string(item.get('summary')), f'{label}.{dim}: summary required')
            refs = item.get('refs')
            check(isinstance(refs, list) and all(string(x) for x in refs), f'{label}.{dim}: refs array required')
            if item.get('state') == 'observed':
                check(bool(refs), f'{label}.{dim}: observed fact requires reference')
            if status in ('源码确认', '确认'):
                allowed = {'observed'} if dim in ('Source', 'Propagation', 'Sink', 'Impact') else {'observed', 'not_applicable'}
                check(member(item.get('state'), allowed), f'{label}.{dim}: source closure not supported')
        if status in ('源码确认', '确认'):
            check(f.get('source_closed') is True, f'{label}: source closure required')

        v = f.get('validation')
        if not isinstance(v, dict):
            errors.append(f'{label}.validation: required object')
            continue
        check(member(v.get('status'), EXECUTIONS), f'{label}: invalid execution status')
        check(member(v.get('scope'), SCOPES), f'{label}: invalid verification scope')
        for key in ('goal', 'reason'):
            check(string(v.get(key)), f'{label}.validation.{key} required')
        for key in ('target_executed', 'controls_passed', 'result_supported'):
            check(type(v.get(key)) is bool, f'{label}.{key}: expected boolean')
        for key in ('command', 'environment', 'executed_at'):
            check(key in v and (v.get(key) is None or string(v.get(key))), f'{label}.{key}: string or null required')
        check('exit_code' in v and (v.get('exit_code') is None or type(v.get('exit_code')) is int), f'{label}: exit_code integer or null required')
        artifacts = v.get('artifacts')
        check(isinstance(artifacts, list), f'{label}.artifacts: expected array')
        for artifact in artifacts if isinstance(artifacts, list) else []:
            if not isinstance(artifact, dict) or not string(artifact.get('path')):
                errors.append(f'{label}: artifact path required')
                continue
            path = Path(artifact['path'])
            target = (root / path).resolve()
            digest = artifact.get('sha256')
            if path.is_absolute() or not target.is_relative_to(root):
                errors.append(f'{label}: artifact must stay within evidence root')
                continue
            if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', digest):
                errors.append(f'{label}: invalid artifact SHA-256')
                continue
            try:
                with target.open('rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                check(actual == digest.lower(), f'{label}: artifact digest mismatch: {path}')
            except OSError:
                errors.append(f'{label}: artifact not readable: {path}')
        if v.get('status') == 'PASSED':
            check(v.get('scope') != 'none', f'{label}: PASSED needs execution scope')
            for key in ('target_executed', 'controls_passed', 'result_supported'):
                check(v.get(key) is True, f'{label}: PASSED needs {key}')
            check(type(v.get('exit_code')) is int and v['exit_code'] == 0, f'{label}: PASSED needs zero exit code')
            for key in ('command', 'environment', 'executed_at'):
                check(string(v.get(key)), f'{label}: PASSED needs {key}')
            check(bool(artifacts), f'{label}: PASSED needs original artifacts')
            check(status != '误报', f'{label}: vulnerability-goal PASSED contradicts false-positive status')
        else:
            check(v.get('result_supported') is False, f'{label}: unsuccessful attempt cannot claim supported result')
        if v.get('status') in ('NOT_RUN', 'SKIPPED'):
            check(v.get('target_executed') is False and v.get('scope') == 'none', f'{label}: unexecuted attempt cannot claim target execution')
        if status == '确认':
            check(v.get('status') == 'PASSED', f'{label}: confirmed finding needs PASSED verification')
    check(len(ids) == len(set(ids)), 'duplicate finding id')
    for related in relations:
        check(related in ids, f'unknown related finding: {related}')
    metrics = data.get('metrics')
    if not isinstance(metrics, dict):
        errors.append('metrics object required')
    else:
        for key, expected in [('candidates', len(findings)), ('pending_review', pending), ('reviewed', len(findings)-pending)]:
            check(type(metrics.get(key)) is int and metrics[key] == expected, f'metrics.{key}: expected {expected}')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--evidence-root', type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding='utf-8-sig'))
        errors = validate(report, args.evidence_root or args.report.parent)
    except (OSError, ValueError) as exc:
        errors = [str(exc)]
    if errors:
        print('\n'.join('ERROR: ' + error for error in errors))
        return 1
    print('PASS: report contract and evidence integrity; vulnerability reasoning still requires review.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
