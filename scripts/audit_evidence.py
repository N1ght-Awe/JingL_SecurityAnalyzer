"""Read-only search/read receipts and JingL supervision checks (not a semantic oracle)."""
import argparse
import hashlib
import json
import shutil
import subprocess
import uuid
from pathlib import Path, PureWindowsPath

OBLIGATIONS = ('Source', 'Propagation', 'Sink', 'Sanitizer', 'Guard',
               'Transport', 'Preconditions', 'Impact', 'counterevidence')
FINAL = ('源码确认', '确认', '误报')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def local(root, path):
    if not isinstance(path, str) or not path or PureWindowsPath(path).drive or PureWindowsPath(path).root:
        raise ValueError('expected relative path')
    target = (Path(root) / path).resolve()
    if not target.is_relative_to(Path(root).resolve()):
        raise ValueError('path outside root')
    return target


def save(root, value):
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8')
    name = 'receipts/' + uuid.uuid4().hex + '.json'
    target = local(root, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return {'path': name, 'sha256': digest(raw)}


def read_source(repo, path, start, end, evidence_root, run_id, repo_id):
    if Path(evidence_root).resolve().is_relative_to(Path(repo).resolve()):
        raise ValueError('keep evidence_root outside the scanned repository')
    source = local(repo, path)
    path = source.relative_to(Path(repo).resolve()).as_posix()
    raw = source.read_bytes()
    lines = raw.decode('utf-8-sig').splitlines(keepends=True)
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
        raise ValueError('invalid line range; no receipt emitted')
    if end - start >= 200:
        raise ValueError('read at most 200 lines per receipt; split the requested range')
    if len(''.join(lines[start-1:end]).encode('utf-8')) > 16000:
        raise ValueError('selected content exceeds 16000 bytes; narrow the range or inspect long lines separately')
    snapshot = 'snapshots/' + digest(raw)
    target = local(evidence_root, snapshot)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    record = {'kind': 'read', 'run_id': run_id, 'repo_id': repo_id, 'path': path,
              'start': start, 'end': end, 'source_sha256': digest(raw),
              'snapshot': snapshot, 'content': ''.join(lines[start-1:end])}
    return record, save(evidence_root, record)


def execute(argv, cwd, timeout=30):
    """No shell, no rewrite, no automatic installation; keep original stdout/stderr."""
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout)
        return {'command': argv, 'exit_code': result.returncode, 'timed_out': False,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr': result.stderr.decode('utf-8', errors='replace')}
    except subprocess.TimeoutExpired as exc:
        return {'command': argv, 'exit_code': None, 'timed_out': True,
                'stdout': (exc.stdout or b'').decode('utf-8', errors='replace'),
                'stderr': (exc.stderr or b'').decode('utf-8', errors='replace')}
    except OSError as exc:
        return {'command': argv, 'exit_code': None, 'timed_out': False,
                'stdout': '', 'stderr': str(exc)}


def search(repo, scope, text, pattern, lang, evidence_root, run_id, repo_id):
    if Path(evidence_root).resolve().is_relative_to(Path(repo).resolve()):
        raise ValueError('keep evidence_root outside the scanned repository')
    target = local(repo, scope)
    if not target.exists():
        raise ValueError('search scope does not exist')
    rg = shutil.which('rg')
    ast = shutil.which('ast-grep')  # Do not assume the unrelated Unix sg command is ast-grep.
    runs = {}
    if rg:
        runs['grep'] = execute([rg, '--json', '--hidden', '-g', '!.git', '-F', '-e', text, '--', str(target)], repo)
    if ast and pattern and lang:
        runs['ast'] = execute([ast, 'run', '--pattern', pattern, '--lang', lang, '--json=compact', str(target)], repo)
    record = {'kind': 'search', 'run_id': run_id, 'repo_id': repo_id, 'scope': scope,
              'query': text, 'pattern': pattern, 'language': lang, 'runs': runs,
              'ast_available': bool(ast), 'grep_available': bool(rg),
              'limitations': ['AST matches are syntactic, not resolved calls or dataflow.',
                              'Ignore files and search scope may exclude relevant assets; reconcile inventory.']}
    return record, save(evidence_root, record)


def load_receipt(root, artifact, run_id):
    if not isinstance(artifact, dict):
        raise ValueError('receipt artifact must be an object')
    raw = local(root, artifact.get('path')).read_bytes()
    if digest(raw) != artifact.get('sha256'):
        raise ValueError('receipt digest mismatch')
    item = json.loads(raw)
    if not isinstance(item, dict) or item.get('run_id') != run_id:
        raise ValueError('receipt run_id mismatch')
    if item.get('kind') == 'read':
        raw = local(root, item.get('snapshot')).read_bytes()
        if digest(raw) != item.get('source_sha256'):
            raise ValueError('source snapshot digest mismatch')
        lines = raw.decode('utf-8-sig').splitlines(keepends=True)
        a, b = item.get('start'), item.get('end')
        if type(a) is not int or type(b) is not int or not 1 <= a <= b <= len(lines):
            raise ValueError('invalid receipt range')
        if item.get('content') != ''.join(lines[a-1:b]):
            raise ValueError('receipt content does not match snapshot range')
    elif item.get('kind') == 'search':
        runs = item.get('runs')
        if not isinstance(runs, dict):
            raise ValueError('search runs must be an object')
        for run in runs.values():
            if (not isinstance(run, dict) or not isinstance(run.get('command'), list)
                    or not run['command'] or not all(isinstance(a, str) for a in run['command'])
                    or not isinstance(run.get('stdout'), str) or not isinstance(run.get('stderr'), str)
                    or type(run.get('timed_out')) is not bool
                    or not (run.get('exit_code') is None or type(run.get('exit_code')) is int)):
                raise ValueError('search execution record incomplete')
    else:
        raise ValueError('unknown receipt kind')
    return item


def source_path(path):
    """Normalize separators only; never resolve source identities against a live repo."""
    if (not isinstance(path, str) or not path or '\x00' in path or ':' in path
            or PureWindowsPath(path).drive or PureWindowsPath(path).root):
        raise ValueError('source path must be repository-relative')
    parts = path.replace('\\', '/').split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('source path must be canonical and repository-relative')
    return '/'.join(parts)


def collect_read_snapshots(data, root):
    """Return ({(repo_id, path): sha256}, errors) from verified current-run receipts.

    Conflicting versions are excluded from the index, not resolved by receipt order.
    This binds recorded source bytes; it does not prove complete or correct review.
    """
    snapshots, errors, conflicts = {}, [], set()
    if not isinstance(data, dict):
        return {}, ['read snapshots: report must be an object']
    repositories = data.get('repositories')
    repo_ids = {r['repo_id'] for r in repositories
                if isinstance(r, dict) and isinstance(r.get('repo_id'), str) and r['repo_id'].strip()
                } if isinstance(repositories, list) else set()
    records = data.get('supervision')
    if not isinstance(records, list):
        return {}, ['read snapshots: supervision must be an array']
    if not isinstance(data.get('run_id'), str) or not data['run_id'].strip():
        return {}, ['read snapshots: current run_id required']
    for review in records:
        if not isinstance(review, dict):
            errors.append('read snapshots: supervision record must be an object')
            continue
        artifacts = review.get('receipts', {})
        if not isinstance(artifacts, dict):
            errors.append('read snapshots: receipt map must be an object')
            continue
        for receipt_id, artifact in artifacts.items():
            label = f'read snapshots: {review.get("finding_id")}/{receipt_id}: '
            try:
                item = load_receipt(root, artifact, data['run_id'])
                repo_id = item.get('repo_id')
                if not isinstance(repo_id, str) or repo_id not in repo_ids:
                    raise ValueError('unknown receipt repo_id')
                if item['kind'] != 'read':
                    continue
                key = (repo_id, source_path(item.get('path')))
                sha256 = item['source_sha256']
                previous = snapshots.setdefault(key, sha256)
                if previous != sha256:
                    conflicts.add(key)
                    errors.append(label + 'mixed source snapshots; reread affected evidence and retain unresolved until reconciled')
            except (OSError, ValueError, TypeError) as exc:
                errors.append(label + str(exc))
    for key in conflicts:
        snapshots.pop(key, None)
    return snapshots, errors


def validate_control_bindings(data, root):
    """Bind applied control fingerprints to current recorded source, not revision labels."""
    snapshots, errors = collect_read_snapshots(data, root)
    if not isinstance(data, dict):
        return errors
    knowledge = data.get('control_knowledge')
    controls = {item['id']: item for item in knowledge
                if isinstance(item, dict) and isinstance(item.get('id'), str)
                } if isinstance(knowledge, list) else {}
    applications = data.get('control_applications')
    for application in applications if isinstance(applications, list) else []:
        if not isinstance(application, dict) or application.get('outcome') != 'applicable':
            continue
        label = f'control binding: {application.get("id")}: '
        control_id = application.get('control_id')
        control = controls.get(control_id) if isinstance(control_id, str) else None
        if control is None or control.get('status') != 'reviewed':
            errors.append(label + 'stale/unknown control cannot be applicable; retain unresolved pending review')
            continue
        fingerprints = control.get('fingerprints')
        if not isinstance(fingerprints, list) or not fingerprints:
            errors.append(label + 'all control fingerprints required; retain unresolved')
            continue
        repo_id = control.get('repo_id')
        for fingerprint in fingerprints:
            try:
                if not isinstance(fingerprint, dict) or not isinstance(repo_id, str):
                    raise ValueError('invalid control fingerprint/repo_id; retain unresolved')
                path = source_path(fingerprint.get('path'))
                expected = fingerprint.get('sha256')
                if not isinstance(expected, str) or len(expected) != 64 or any(c not in '0123456789abcdefABCDEF' for c in expected):
                    raise ValueError('invalid control fingerprint SHA-256; retain unresolved')
                actual = snapshots.get((repo_id, path))
                if actual is None:
                    raise ValueError(f'{repo_id}:{path}: current read snapshot missing/conflicting; retain unresolved')
                if expected.lower() != actual:
                    raise ValueError(f'{repo_id}:{path}: control fingerprint differs from current read snapshot; mark knowledge stale and application unresolved pending review')
            except (ValueError, TypeError) as exc:
                errors.append(label + str(exc))
    return errors


def validate_supervision(data, root):
    errors = []

    def require(ok, message):
        if not ok:
            errors.append('supervision: ' + message)

    def text(value):
        return isinstance(value, str) and bool(value.strip())

    records = data.get('supervision')
    if not isinstance(records, list):
        return ['supervision: expected array']
    def array(key):
        return data[key] if isinstance(data.get(key), list) else []

    findings = {f['id']: f for f in array('findings')
                if isinstance(f, dict) and text(f.get('id'))}
    repo_ids = {r['repo_id'] for r in array('repositories')
                if isinstance(r, dict) and text(r.get('repo_id'))}
    seen = set()
    snapshots = {}
    for review in records:
        if not isinstance(review, dict):
            require(False, 'review must be an object')
            continue
        fid = review.get('finding_id')
        if not text(fid) or fid not in findings or fid in seen:
            require(False, 'unknown/duplicate finding_id')
            continue
        seen.add(fid)
        f = findings[fid]
        label = fid + ': '
        decision = review.get('decision')
        require(decision in ('pass', 'blocked', 'pending'), label + 'invalid decision')
        require(text(review.get('rationale')), label + 'review rationale required')
        require(type(review.get('repair_rounds')) is int and 0 <= review['repair_rounds'] <= 2,
                label + 'repair_rounds must be 0..2')
        gaps = review.get('gaps')
        require(isinstance(gaps, list) and all(text(x) for x in gaps), label + 'gaps array required')
        if decision != 'pass':
            require(bool(gaps), label + 'unresolved supervision needs gaps')
        else:
            require(gaps == [], label + 'pass cannot retain gaps')
        if f.get('status') in FINAL:
            require(decision == 'pass', label + 'definitive conclusion requires supervision pass')
        if decision != 'pass':
            continue
        receipts = {}
        artifacts = review.get('receipts')
        require(isinstance(artifacts, dict) and bool(artifacts), label + 'receipt map required')
        for key, artifact in artifacts.items() if isinstance(artifacts, dict) else []:
            try:
                item = load_receipt(root, artifact, data.get('run_id'))
                require(text(item.get('repo_id')) and item['repo_id'] in repo_ids, label + 'unknown receipt repo')
                if item.get('kind') == 'read':
                    require(text(item.get('path')), label + 'source path required')
                    source_key = (str(item.get('repo_id')), str(item.get('path')))
                    previous = snapshots.setdefault(source_key, item['source_sha256'])
                    require(previous == item['source_sha256'], label + 'mixed source snapshots; reread affected evidence')
                receipts[key] = item
            except (OSError, ValueError, TypeError) as exc:
                require(False, label + str(exc))

        def refs_cover(requirements):
            if not isinstance(requirements, list) or not requirements:
                return False
            for need in requirements:
                if not isinstance(need, dict) or not text(need.get('receipt_id')):
                    return False
                r = receipts.get(need['receipt_id'], {})
                a, b = need.get('start'), need.get('end')
                if (not text(need.get('path')) or r.get('kind') != 'read' or r.get('repo_id') != need.get('repo_id')
                        or r.get('path') != need.get('path') or type(a) is not int or type(b) is not int
                        or not r['start'] <= a <= b <= r['end']):
                    return False
            return True

        if data.get('schema_version') == '2.3.0':
            try:
                artifact = review.get('source_review')
                if not isinstance(artifact, dict):
                    raise ValueError('source-first review artifact required')
                raw = local(root, artifact.get('path')).read_bytes()
                if digest(raw) != artifact.get('sha256'):
                    raise ValueError('source-first review digest mismatch')
                baseline = json.loads(raw)
                if (not isinstance(baseline, dict) or baseline.get('kind') != 'source_review'
                        or baseline.get('run_id') != data.get('run_id') or baseline.get('finding_id') != fid):
                    raise ValueError('source-first review identity mismatch')
                require(baseline.get('mode') in ('same_context_second_pass', 'fresh_context'), label + 'declare actual reviewer context')
                for key in ('scope', 'observations'):
                    require(text(baseline.get(key)), label + 'source-first ' + key + ' required')
                require(refs_cover(baseline.get('reads')), label + 'source-first scope not read')
                controls = baseline.get('controls')
                require(isinstance(controls, list), label + 'source-first controls array required (empty needs search rationale)')
                for control in controls if isinstance(controls, list) else []:
                    if not isinstance(control, dict):
                        require(False, label + 'invalid source-first control')
                        continue
                    require(text(control.get('name')) and text(control.get('assessment')), label + 'control assessment required')
                    require(refs_cover(control.get('reads')), label + 'discovered control implementation not read')
                initial_gaps = baseline.get('gaps')
                require(isinstance(initial_gaps, list) and all(text(x) for x in initial_gaps), label + 'initial review gaps required')
                require(text(review.get('reconciliation')), label + 'reconcile initial observations/controls/gaps with final evidence')
            except (OSError, ValueError, TypeError) as exc:
                require(False, label + str(exc))

        checks = review.get('checks')
        checks = checks if isinstance(checks, dict) else {}
        for name in OBLIGATIONS:
            item = checks.get(name)
            if not isinstance(item, dict):
                require(False, label + name + ' missing obligation')
                continue
            require(item.get('state') in ('resolved', 'not_applicable'), label + name + ' unresolved')
            require(text(item.get('reason')), label + name + ' reason required')
            require(refs_cover(item.get('reads')), label + name + ' required source ranges not read')
            if name == 'counterevidence' or (f.get('status') in ('源码确认', '确认') and name in ('Source', 'Propagation', 'Sink', 'Impact')):
                require(item.get('state') == 'resolved', label + name + ' cannot be not_applicable')
        discovery = review.get('discovery_receipt_ids')
        require(isinstance(discovery, list) and bool(discovery), label + 'independent discovery receipts required')
        for key in discovery if isinstance(discovery, list) else []:
            r = receipts.get(key, {}) if text(key) else {}
            runs = r.get('runs', {})
            successful = isinstance(runs, dict) and any(
                isinstance(v, dict) and type(v.get('exit_code')) is int and v['exit_code'] in (0, 1)
                and v.get('timed_out') is False for v in runs.values())
            require(r.get('kind') == 'search' and successful, label + 'discovery failed or missing')
        require(text(review.get('discovery_assessment')), label + 'explain search exclusions/failures and omitted-control review')
        edges = review.get('edges')
        require(isinstance(edges, list) and bool(edges), label + 'explicit call/dataflow edges required')
        for edge in edges if isinstance(edges, list) else []:
            if not isinstance(edge, dict):
                require(False, label + 'invalid edge')
                continue
            require(text(edge.get('from')) and text(edge.get('to')) and text(edge.get('reason')), label + 'edge explanation required')
            require(edge.get('resolution') in ('resolved', 'excluded'), label + 'unresolved edge')
            require(refs_cover(edge.get('reads')), label + 'edge source ranges not read')
    require(seen == set(findings), 'each finding needs one supervision record, including pending findings')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--repo-id', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--evidence-root', required=True, type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    read = sub.add_parser('read')
    read.add_argument('path')
    read.add_argument('start', type=int)
    read.add_argument('end', type=int)
    find = sub.add_parser('search')
    find.add_argument('--scope', default='.')
    find.add_argument('--text', required=True)
    find.add_argument('--pattern')
    find.add_argument('--lang')
    args = parser.parse_args()
    try:
        common = (args.evidence_root, args.run_id, args.repo_id)
        if args.action == 'read':
            record, artifact = read_source(args.repo, args.path, args.start, args.end, *common)
            print(f"{record['path']}:{record['start']}-{record['end']}")
            print(record['content'])
        else:
            record, artifact = search(args.repo, args.scope, args.text, args.pattern, args.lang, *common)
            # A bounded preview is never evidence of complete search-result inspection.
            print(json.dumps(record, ensure_ascii=False)[:12000])
            print('Search preview only. Inspect the saved receipt in bounded portions before review.')
        print(json.dumps({'artifact': artifact}, ensure_ascii=False))
        return 0 if args.action == 'read' or any(
            r['exit_code'] in (0, 1) and not r['timed_out'] for r in record['runs'].values()) else 1
    except (OSError, ValueError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
