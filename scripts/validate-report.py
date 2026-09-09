"""Validate JingL 2.0/2.1 report contracts and evidence integrity; not vulnerability truth."""
import argparse
import hashlib
import json
import re
from pathlib import Path, PureWindowsPath

VERSION = '2.1.0'
LEGACY_VERSION = '2.0.0'
DIMENSIONS = ('Source', 'Propagation', 'Sink', 'Sanitizer', 'Guard',
              'Transport', 'Preconditions', 'Impact')
STATES = {'observed', 'inferred', 'missing', 'not_applicable'}
STATUSES = {'待审查', '缺失关键源码', '待验证', '源码确认', '确认', '误报'}
EXECUTIONS = {'NOT_RUN', 'BLOCKED', 'PASSED', 'FAILED', 'TIMEOUT', 'SKIPPED'}
SCOPES = {'none', 'isolated', 'integration', 'end_to_end'}
GRADES = {None, 'P0', 'P1', 'P2', 'P3'}
TYPES = {p.name for p in (Path(__file__).resolve().parents[1] / 'skill').iterdir()
         if p.is_dir()}

EXTENSIONS = ('scan_types', 'assets', 'coverage', 'coverage_status',
              'control_knowledge', 'control_applications', 'control_observations')
APPLICATION_CHECKS = ('identity', 'invocation', 'result_used', 'applicability', 'downstream', 'boundary')


def validate_extensions(data, check, string, member, repo_ids, finding_ids):
    """Check declared coverage and review reuse; does not infer source-code truth."""
    def array(obj, key, label):
        value = obj.get(key)
        check(isinstance(value, list), f'{label}.{key}: expected array')
        return value if isinstance(value, list) else []

    def strings(obj, key, label, nonempty=False):
        values = array(obj, key, label)
        check(all(string(x) for x in values), f'{label}.{key}: expected strings')
        if nonempty:
            check(bool(values), f'{label}.{key}: nonempty evidence/value required')
        return [x for x in values if string(x)]

    def records(key):
        items = array(data, key, 'report')
        for i, item in enumerate(items):
            label = f'{key}[{i}]'
            if not isinstance(item, dict):
                check(False, f'{label}: expected object')
                continue
            yield item, label

    def fields(item, names, label):
        for name in names:
            check(string(item.get(name)), f'{label}.{name}: required string')

    def unique(values, label):
        check(len(values) == len(set(values)), f'{label}: duplicate identifiers')

    scan_types = strings(data, 'scan_types', 'report', True)
    unique(scan_types, 'scan_types')
    check(all(x in TYPES for x in scan_types), 'scan_types: unknown type')
    assets = {}
    for item, label in records('assets'):
        fields(item, ('asset_id', 'repo_id', 'path'), label)
        check(item.get('repo_id') in repo_ids, f'{label}: unknown repo_id')
        check(member(item.get('kind'), {'frontend', 'backend', 'templates', 'gateway', 'config', 'library', 'other', 'unknown'}), f'{label}: invalid asset kind')
        strings(item, 'evidence_refs', label, True)
        asset_id = item.get('asset_id')
        if string(asset_id):
            check(asset_id not in assets, f'{label}: duplicate asset_id')
            assets[asset_id] = item
    check(bool(assets), 'assets: enumerate scope, including unknown/unprovided assets')
    coverage_types = []
    all_complete = True
    for item, label in records('coverage'):
        kind = item.get('type')
        check(string(kind) and kind in scan_types, f'{label}: type outside scan_types')
        if string(kind):
            coverage_types.append(kind)
        required = strings(item, 'required_asset_ids', label, True)
        reviewed = strings(item, 'reviewed_asset_ids', label)
        gaps = strings(item, 'gaps', label)
        strings(item, 'evidence_refs', label, True)
        unique(required, label + '.required_asset_ids')
        unique(reviewed, label + '.reviewed_asset_ids')
        check(all(x in assets for x in required + reviewed), f'{label}: unknown asset_id')
        check(set(reviewed) <= set(required), f'{label}: reviewed assets outside required scope')
        if kind == 'XSS':
            mandatory = {key for key, value in assets.items() if value.get('kind') in ('frontend', 'templates')}
            check(mandatory <= set(required), f'{label}: XSS omitted frontend/templates assets')
        status = item.get('status')
        check(member(status, {'complete', 'partial'}), f'{label}: invalid coverage status')
        if status == 'complete':
            check(set(required) == set(reviewed) and not gaps, f'{label}: complete coverage has unreviewed assets/gaps')
        else:
            all_complete = False
            check(bool(gaps), f'{label}: partial coverage requires gaps')
    unique(coverage_types, 'coverage.type')
    check(set(coverage_types) == set(scan_types), 'coverage: must account for all scan_types')
    expected = 'complete' if all_complete and coverage_types else 'partial'
    check(data.get('coverage_status') == expected, f'coverage_status: expected {expected}')
    if expected == 'partial':
        check(bool(data.get('limitations')), 'partial coverage requires report limitations')
    for f in data.get('findings', []) if isinstance(data.get('findings'), list) else []:
        if isinstance(f, dict):
            check(string(f.get('type')) and f['type'] in scan_types, 'finding type outside scan_types')

    knowledge = {}
    for item, label in records('control_knowledge'):
        fields(item, ('id', 'repo_id', 'symbol', 'revision', 'contract', 'assumptions', 'limitations'), label)
        check(item.get('repo_id') in repo_ids, f'{label}: unknown repo_id')
        check(member(item.get('status'), {'reviewed', 'stale'}), f'{label}: invalid knowledge status')
        protects = strings(item, 'protects', label, True)
        check(all(x in TYPES for x in protects), f'{label}: unknown protects type')
        strings(item, 'evidence_refs', label, True)
        fingerprints = array(item, 'fingerprints', label)
        check(bool(fingerprints), f'{label}: fingerprints required')
        paths = []
        for fingerprint in fingerprints:
            if not isinstance(fingerprint, dict):
                check(False, f'{label}: invalid fingerprint')
                continue
            path = fingerprint.get('path')
            digest = fingerprint.get('sha256')
            valid_path = string(path) and not Path(path).is_absolute() and not PureWindowsPath(path).drive and not PureWindowsPath(path).root and '..' not in path.replace('\\', '/').split('/') and '\x00' not in path
            check(valid_path, f'{label}: fingerprint path must be repository-relative')
            if string(path):
                paths.append(path)
            check(isinstance(digest, str) and bool(re.fullmatch(r'[0-9a-fA-F]{64}', digest)), f'{label}: invalid fingerprint SHA-256')
        unique(paths, label + '.fingerprints')
        key = item.get('id')
        if string(key):
            check(key not in knowledge, f'{label}: duplicate knowledge id')
            knowledge[key] = item

    application_ids = []
    for item, label in records('control_applications'):
        fields(item, ('id', 'control_id', 'repo_id', 'location', 'reason'), label)
        if string(item.get('id')):
            application_ids.append(item['id'])
        check(item.get('repo_id') in repo_ids, f'{label}: unknown repo_id')
        linked = strings(item, 'finding_ids', label)
        check(all(x in finding_ids for x in linked), f'{label}: unknown finding reference')
        control_id = item.get('control_id')
        control = knowledge.get(control_id) if string(control_id) else None
        check(control is not None, f'{label}: unknown control_id')
        outcome = item.get('outcome')
        check(member(outcome, {'applicable', 'not_applicable', 'unresolved'}), f'{label}: invalid outcome')
        if outcome == 'applicable':
            check(control is not None and control.get('status') == 'reviewed', f'{label}: stale/unknown control cannot be applied')
            if control is not None and isinstance(control.get('protects'), list):
                for f in data.get('findings', []) if isinstance(data.get('findings'), list) else []:
                    if isinstance(f, dict) and f.get('id') in linked:
                        check(f.get('type') in control['protects'], f'{label}: reviewed control does not protect linked finding type')
        checks = item.get('checks')
        check(isinstance(checks, dict), f'{label}: checks required')
        checks = checks if isinstance(checks, dict) else {}
        for name in APPLICATION_CHECKS:
            evidence = checks.get(name)
            if not isinstance(evidence, dict):
                check(False, f'{label}.{name}: check required')
                continue
            fields(evidence, ('summary',), label + '.' + name)
            check(member(evidence.get('state'), {'observed', 'inferred', 'missing'}), f'{label}.{name}: invalid check state')
            check(member(evidence.get('result'), {'pass', 'fail', 'unknown'}), f'{label}.{name}: invalid check result')
            refs = strings(evidence, 'refs', label + '.' + name)
            if evidence.get('state') == 'observed':
                check(bool(refs), f'{label}.{name}: observed check requires refs')
            if outcome == 'applicable':
                check(evidence.get('state') == 'observed', f'{label}.{name}: applicable requires current observed evidence')
                check(evidence.get('result') == 'pass', f'{label}.{name}: applicable requires satisfied condition')
    unique(application_ids, 'control_applications.id')

    observation_ids = []
    for item, label in records('control_observations'):
        fields(item, ('id', 'repo_id', 'location', 'expected_control', 'observation', 'risk_boundary'), label)
        if string(item.get('id')):
            observation_ids.append(item['id'])
        check(item.get('repo_id') in repo_ids, f'{label}: unknown repo_id')
        check(member(item.get('kind'), {'control_gap', 'improvement'}), f'{label}: invalid observation kind')
        check('priority' not in item and 'status' not in item, f'{label}: control observation is not a graded vulnerability')
        strings(item, 'evidence_refs', label, True)
        related = strings(item, 'related_findings', label)
        check(all(x in finding_ids for x in related), f'{label}: unknown related finding')
    unique(observation_ids, 'control_observations.id')


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
        supported = {VERSION, LEGACY_VERSION} if key == 'schema_version' else {'2.0.0', '2.0.1', '2.1.0'}
        check(member(data.get(key), supported), f'{key}: unsupported version; adapt legacy data explicitly')
    check(string(data.get('run_id')), 'run_id required')
    if data.get('schema_version') == LEGACY_VERSION:
        check(not any(key in data for key in EXTENSIONS), '2.1 extensions require schema_version 2.1.0; legacy checks cannot validate coverage/reuse')
        check(data.get('skill_version') != VERSION and data.get('rules_version') != VERSION, '2.1 rules require schema_version 2.1.0')
    check('report_validation_mode' not in data, 'use finding.validation, not legacy report_validation_mode')
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
        check(not any(key in f for key in ('poc_validation_mode', 'exploitation_method', 'http_interface', 'http_poc')), f'{label}: use canonical exploitation/validation fields')
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
        check('poc_validation_mode' not in v, f'{label}: use validation.status/scope, not poc_validation_mode')
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
    if data.get('schema_version') == VERSION:
        validate_extensions(data, check, string, member, repo_ids, ids)
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
