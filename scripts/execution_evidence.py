"""Capture an authorized test command with run/instance/source bindings; never infer PASSED."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import tempfile

SPEC = importlib.util.spec_from_file_location('execution_audit', Path(__file__).with_name('audit_evidence.py'))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def records(data, key):
    value = data.get(key)
    return value if isinstance(value, list) else []


def target_binding(data, finding, root):
    """Bind all read snapshots retained for this instance, including cross-repository files."""
    reviews = [r for r in records(data, 'supervision') if isinstance(r, dict) and r.get('finding_id') == finding.get('id')]
    if len(reviews) != 1 or not isinstance(reviews[0].get('receipts'), dict):
        raise ValueError('one supervision receipt map required for execution target')
    repos = {r.get('repo_id') for r in records(data, 'repositories') if isinstance(r, dict) and text(r.get('repo_id'))}
    sources = {}
    for artifact in reviews[0]['receipts'].values():
        item = AUDIT.load_receipt(root, artifact, data.get('run_id'))
        if item['kind'] != 'read':
            continue
        if item.get('repo_id') not in repos or not text(item.get('path')):
            raise ValueError('unknown source repository or path')
        key = (item['repo_id'], AUDIT.source_path(item['path']))
        old = sources.setdefault(key, item['source_sha256'])
        if old != item['source_sha256']:
            raise ValueError('mixed source snapshots for execution target')
    # A reused implementation may have been read under another instance/repository.
    applications = [a for a in records(data, 'control_applications') if isinstance(a, dict)
                    and a.get('outcome') == 'applicable' and finding.get('id') in (a.get('finding_ids') or [])]
    if applications:
        snapshots, errors = AUDIT.collect_read_snapshots(data, root)
        if errors:
            raise ValueError('invalid shared control read snapshots: ' + '; '.join(errors))
        for application in applications:
            controls = [c for c in records(data, 'control_knowledge') if isinstance(c, dict) and c.get('id') == application.get('control_id')]
            if len(controls) != 1 or controls[0].get('status') != 'reviewed' or not controls[0].get('fingerprints'):
                raise ValueError('reviewed control identity and fingerprints required')
            for fingerprint in controls[0]['fingerprints']:
                key = (controls[0]['repo_id'], AUDIT.source_path(fingerprint['path']))
                sha = fingerprint['sha256']
                if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdefABCDEF' for c in sha):
                    raise ValueError('invalid shared control fingerprint')
                sha = sha.lower()
                if snapshots.get(key) != sha or sources.get(key, sha) != sha:
                    raise ValueError('shared control source binding mismatch; use stale/unresolved and reread')
                sources[key] = sha
    if not sources or not any(repo == finding.get('repo_id') for repo, _ in sources):
        raise ValueError('target repository source snapshot required')
    validation = finding.get('validation')
    if not isinstance(validation, dict) or not text(validation.get('goal')) or validation.get('scope') not in ('isolated', 'integration', 'end_to_end'):
        raise ValueError('declare execution goal and non-none scope before running')
    result = {key: finding.get(key) for key in ('id', 'instance_key', 'repo_id')}
    if not all(text(x) for x in result.values()):
        raise ValueError('execution target identity required')
    result.update(goal=validation['goal'], scope=validation['scope'], sources=[
        {'repo_id': repo, 'path': path, 'sha256': sha} for (repo, path), sha in sorted(sources.items())])
    return result


def repository_binding(data, targets):
    needed = {s['repo_id'] for t in targets for s in t['sources']}
    result = []
    for repo in records(data, 'repositories'):
        if isinstance(repo, dict) and repo.get('repo_id') in needed:
            row = {k: repo.get(k) for k in ('repo_id', 'revision', 'path')}
            if not all(text(x) for x in row.values()):
                raise ValueError('repository identity/revision/path required')
            result.append(row)
    if len(result) != len(needed) or {r['repo_id'] for r in result} != needed:
        raise ValueError('missing or duplicate execution repository')
    return sorted(result, key=lambda r: r['repo_id'])


def execute(argv, cwd, timeout):
    """File-backed output avoids inherited-pipe waits; timeout cleanup is best effort."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(argv, cwd=cwd, stdout=stdout, stderr=stderr,
                                       start_new_session=(os.name != 'nt'))
        except OSError as exc:
            return dict(command=argv, exit_code=None, timed_out=False, stdout='', stderr=str(exc), cleanup_error=None)
        timed_out, cleanup_error = False, None
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                if os.name == 'nt':
                    killed = subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                            capture_output=True, timeout=5)
                    if killed.returncode:
                        cleanup_error = killed.stderr.decode('utf-8', errors='replace') or 'process tree cleanup failed'
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except (OSError, subprocess.TimeoutExpired) as exc:
                cleanup_error = str(exc)
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as exc:
                cleanup_error = str(exc)
        stdout.seek(0)
        stderr.seek(0)
        return dict(command=argv, exit_code=None if timed_out else process.returncode, timed_out=timed_out,
                    stdout=stdout.read().decode('utf-8', errors='replace'),
                    stderr=stderr.read().decode('utf-8', errors='replace'), cleanup_error=cleanup_error)


def capture(data, finding_ids, repo_roots, argv, cwd, root, environment, timeout=120):
    """Runs only the explicit command. Callers retain responsibility for authorization and assertions."""
    if not text(data.get('run_id')) or not text(environment):
        raise ValueError('run_id and environment description required')
    if not isinstance(finding_ids, list) or not finding_ids or not all(text(x) for x in finding_ids) or len(set(finding_ids)) != len(finding_ids):
        raise ValueError('unique explicit finding IDs required')
    if not isinstance(argv, list) or not argv or not all(text(x) for x in argv):
        raise ValueError('nonempty command argument array required')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('positive command timeout required')
    findings = [f for f in records(data, 'findings') if isinstance(f, dict) and f.get('id') in finding_ids]
    if len(findings) != len(finding_ids) or {f['id'] for f in findings} != set(finding_ids):
        raise ValueError('unknown or duplicate finding ID')
    targets = [target_binding(data, f, root) for f in findings]
    repos = repository_binding(data, targets)
    if not isinstance(repo_roots, dict):
        raise ValueError('repository roots must map repo_id to an actual local directory')
    paths = {}
    for target in targets:
        for source in target['sources']:
            directory = repo_roots.get(source['repo_id'])
            if not isinstance(directory, (str, Path)):
                raise ValueError('missing repository root')
            directory = Path(directory).resolve()
            if not directory.is_dir() or Path(root).resolve().is_relative_to(directory):
                raise ValueError('valid repository root required; keep evidence outside target repositories')
            path = AUDIT.local(directory, source['path'])
            if AUDIT.digest(path.read_bytes()) != source['sha256']:
                raise ValueError('source changed since review; reread before executing')
            paths[(source['repo_id'], source['path'])] = (path, source['sha256'])
    cwd = Path(cwd).resolve()
    if not cwd.is_dir():
        raise ValueError('execution working directory must exist')
    started = datetime.now(timezone.utc).isoformat()
    execution = execute(argv, cwd, timeout=timeout)
    finished = datetime.now(timezone.utc).isoformat()
    changes = []
    for (repo, relative), (path, before) in paths.items():
        try:
            after = AUDIT.digest(path.read_bytes())
        except OSError:
            after = None
        if after != before:
            changes.append({'repo_id': repo, 'path': relative, 'before': before, 'after': after})
    log = AUDIT.save(root, {'kind': 'execution_log', 'run_id': data['run_id'], **execution})
    command = json.dumps(argv, ensure_ascii=False)
    receipt = {'kind': 'execution', 'version': 1, 'run_id': data['run_id'], 'targets': targets,
               'repositories': repos, 'command': command, 'argv': argv, 'cwd': str(cwd),
               'environment': environment, 'executed_at': started, 'finished_at': finished,
               'exit_code': execution['exit_code'], 'timed_out': execution['timed_out'],
               'cleanup_error': execution['cleanup_error'],
               'source_unchanged': not changes, 'source_changes': changes, 'log': log}
    artifact = AUDIT.save(root, receipt)
    return receipt, artifact


def load_artifact(root, artifact):
    if not isinstance(artifact, dict):
        raise ValueError('execution artifact required')
    raw = AUDIT.local(root, artifact.get('path')).read_bytes()
    if AUDIT.digest(raw) != artifact.get('sha256'):
        raise ValueError('execution artifact digest mismatch')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('execution artifact must contain an object')
    return value


def validate_execution_bindings(data, root):
    errors = []
    for finding in records(data, 'findings'):
        if not isinstance(finding, dict) or not isinstance(finding.get('validation'), dict):
            continue
        validation = finding['validation']
        artifact = validation.get('execution_receipt')
        if validation.get('status') != 'PASSED' and artifact is None:
            continue
        try:
            receipt = load_artifact(root, artifact)
            if receipt.get('kind') != 'execution' or type(receipt.get('version')) is not int or receipt['version'] != 1 or receipt.get('run_id') != data.get('run_id'):
                raise ValueError('execution receipt kind/version/run_id mismatch')
            for key in ('cwd', 'environment', 'executed_at', 'finished_at'):
                if not text(receipt.get(key)):
                    raise ValueError('execution metadata required: ' + key)
            try:
                started, finished = (datetime.fromisoformat(receipt[k]) for k in ('executed_at', 'finished_at'))
                if started.tzinfo is None or finished.tzinfo is None or finished < started:
                    raise ValueError('execution timestamps must be ordered and timezone-aware')
            except ValueError as exc:
                raise ValueError('invalid execution timestamps') from exc
            if (type(receipt.get('timed_out')) is not bool or type(receipt.get('source_unchanged')) is not bool
                    or not isinstance(receipt.get('source_changes'), list)
                    or receipt['source_unchanged'] != (receipt['source_changes'] == [])
                    or (receipt.get('exit_code') is not None and type(receipt['exit_code']) is not int)
                    or (receipt.get('cleanup_error') is not None and not text(receipt['cleanup_error']))):
                raise ValueError('invalid execution result metadata')
            targets = receipt.get('targets')
            if not isinstance(targets, list) or not targets or any(not isinstance(t, dict) or not text(t.get('id')) for t in targets):
                raise ValueError('execution target bindings required')
            if len({t['id'] for t in targets}) != len(targets):
                raise ValueError('duplicate execution targets')
            by_id = {f['id']: f for f in records(data, 'findings') if isinstance(f, dict) and text(f.get('id'))}
            for target in targets:
                if target['id'] not in by_id or target != target_binding(data, by_id[target['id']], root):
                    raise ValueError('execution instance/goal/scope/source binding mismatch')
            if finding.get('id') not in {t['id'] for t in targets}:
                raise ValueError('execution receipt did not cover this instance')
            if receipt.get('repositories') != repository_binding(data, targets):
                raise ValueError('execution repository revision/path mismatch')
            argv = receipt.get('argv')
            if not isinstance(argv, list) or not argv or not all(text(x) for x in argv) or receipt.get('command') != json.dumps(argv, ensure_ascii=False):
                raise ValueError('execution command arguments mismatch')
            for key in ('command', 'environment', 'executed_at', 'exit_code'):
                if validation.get(key) != receipt.get(key):
                    raise ValueError('execution metadata mismatch: ' + key)
            log = load_artifact(root, receipt.get('log'))
            if log.get('kind') != 'execution_log' or log.get('run_id') != data.get('run_id') or log.get('command') != argv:
                raise ValueError('execution log identity/command mismatch')
            if not isinstance(log.get('stdout'), str) or not isinstance(log.get('stderr'), str):
                raise ValueError('original execution output required')
            if any(log.get(k) != receipt.get(k) for k in ('exit_code', 'timed_out', 'cleanup_error')):
                raise ValueError('execution log result mismatch')
            if receipt['log'] not in validation.get('artifacts', []):
                raise ValueError('bound execution log missing from validation.artifacts')
            if validation.get('status') == 'PASSED' and (type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0
                    or receipt.get('timed_out') is not False or receipt.get('source_unchanged') is not True or receipt.get('source_changes') != []
                    or receipt.get('cleanup_error') is not None):
                raise ValueError('PASSED requires successful execution with unchanged reviewed sources')
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append('execution binding ' + str(finding.get('id')) + ': ' + str(exc))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--repo-roots', required=True, type=Path, help='JSON map of repo_id to actual local source root')
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--finding', action='append', required=True)
    parser.add_argument('--cwd', required=True, type=Path)
    parser.add_argument('--environment', required=True)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--command-file', required=True, type=Path, help='JSON argument array; no implicit shell')
    args = parser.parse_args()
    try:
        data = json.loads(args.report.read_text(encoding='utf-8-sig'))
        roots = json.loads(args.repo_roots.read_text(encoding='utf-8-sig'))
        argv = json.loads(args.command_file.read_text(encoding='utf-8-sig'))
        receipt, artifact = capture(data, args.finding, roots, argv, args.cwd, args.evidence_root, args.environment, args.timeout)
        print(json.dumps({'execution_receipt': artifact, 'artifacts': [receipt['log']],
                          **{k: receipt[k] for k in ('command', 'environment', 'executed_at', 'exit_code')},
                          'timed_out': receipt['timed_out'], 'source_unchanged': receipt['source_unchanged'],
                          'cleanup_error': receipt['cleanup_error'],
                          'note': 'No vulnerability status inferred. Review actual target execution, tests and controls.'}, ensure_ascii=False))
        return 0 if receipt['exit_code'] == 0 and not receipt['timed_out'] and receipt['source_unchanged'] else 1
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
