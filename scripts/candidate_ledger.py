"""Persist discoveries before triage and reconcile every call instance at delivery."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('ledger_evidence', Path(__file__).with_name('audit_evidence.py'))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)
NAME = 'candidate-ledger.jsonl'
FIELDS = ('id', 'repo_id', 'type', 'instance_key', 'entry', 'operation', 'location')


def text(value):
    return isinstance(value, str) and bool(value.strip())


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True) + '\n').encode('utf-8')


@contextmanager
def locked(root):
    """Fail fast on concurrent writers; never silently overwrite a discovery."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = AUDIT.local(root, NAME + '.lock')
    with path.open('x', encoding='utf-8'):
        pass
    try:
        yield
    finally:
        path.unlink()


def load(root, run_id, verify_evidence=True):
    raw = AUDIT.local(root, NAME).read_bytes()
    rows = [json.loads(line) for line in raw.splitlines()]
    if not rows or rows[0] != {'kind': 'discovery_ledger', 'run_id': run_id, 'version': 1}:
        raise ValueError('ledger header/run_id mismatch')
    seen, instances = set(), set()
    for item in rows[1:]:
        if not isinstance(item, dict) or not all(text(item.get(k)) for k in FIELDS):
            raise ValueError('candidate identity and original location required')
        key = (item['repo_id'], item['type'], item['instance_key'])
        if item['id'] in seen or key in instances:
            raise ValueError('duplicate candidate id or call instance')
        seen.add(item['id'])
        instances.add(key)
        evidence = item.get('evidence')
        if not isinstance(evidence, list) or not evidence:
            raise ValueError('candidate needs original search/read evidence')
        for artifact in evidence if verify_evidence else []:
            receipt = AUDIT.load_receipt(root, artifact, run_id)
            if receipt.get('repo_id') != item['repo_id']:
                raise ValueError('candidate evidence repo mismatch')
    return raw, rows[1:]


def snapshot(root, run_id):
    raw, _ = load(root, run_id, verify_evidence=False)
    return {'path': NAME, 'sha256': hashlib.sha256(raw).hexdigest()}


def initialize(root, run_id):
    if not text(run_id):
        raise ValueError('run_id required')
    with locked(root):
        with AUDIT.local(root, NAME).open('xb') as stream:
            stream.write(encoded({'kind': 'discovery_ledger', 'run_id': run_id, 'version': 1}))
    return snapshot(root, run_id)


def append(root, run_id, item):
    if not isinstance(item, dict) or not all(text(item.get(k)) for k in FIELDS):
        raise ValueError('candidate identity and original location required')
    evidence = item.get('evidence')
    if not isinstance(evidence, list) or not evidence:
        raise ValueError('candidate needs original search/read evidence')
    for artifact in evidence:
        if AUDIT.load_receipt(root, artifact, run_id).get('repo_id') != item['repo_id']:
            raise ValueError('candidate evidence repo mismatch')
    with locked(root):
        _, rows = load(root, run_id, verify_evidence=False)
        for old in rows:
            if old['id'] == item['id'] or all(old[k] == item[k] for k in ('repo_id', 'type', 'instance_key')):
                if old == item:
                    return snapshot(root, run_id)  # Safe retry, not a second candidate.
                raise ValueError('candidate already registered; preserve the original discovery')
        with AUDIT.local(root, NAME).open('ab') as stream:
            stream.write(encoded(item))
    return snapshot(root, run_id)


def save_review(root, run_id, item):
    """Archive observations before comparing the analyst's conclusion."""
    if not isinstance(item, dict) or not text(item.get('finding_id')):
        raise ValueError('finding_id required')
    return AUDIT.save(root, {**item, 'kind': 'source_review', 'run_id': run_id})


def validate_ledger(data, root):
    try:
        raw, rows = load(root, data.get('run_id'))
        expected = {'path': NAME, 'sha256': hashlib.sha256(raw).hexdigest()}
        if data.get('candidate_ledger') != expected:
            raise ValueError('candidate_ledger must reference the full current discovery ledger')
        findings = data.get('findings')
        if not isinstance(findings, list) or any(not isinstance(f, dict) or not text(f.get('id')) for f in findings):
            raise ValueError('findings must preserve registered candidates')
        by_id = {f['id']: f for f in findings}
        if set(by_id) != {row['id'] for row in rows}:
            raise ValueError('every registered candidate needs its own disposition; no omitted or unregistered instances')
        for row in rows:
            f = by_id[row['id']]
            for key in ('repo_id', 'instance_key', 'entry', 'operation'):
                if f.get(key) != row[key]:
                    raise ValueError(f"{row['id']}: discovery identity changed: {key}")
            if f.get('type') != row['type'] and not text(f.get('classification_reason')):
                raise ValueError(f"{row['id']}: changed type requires classification_reason; original type remains in ledger")
        return []
    except (OSError, ValueError, TypeError) as exc:
        return ['candidate ledger: ' + str(exc)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--run-id', required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('init')
    sub.add_parser('snapshot')
    for action in ('add', 'review'):
        sub.add_parser(action).add_argument('input', type=Path)
    args = parser.parse_args()
    try:
        if args.action in ('init', 'snapshot'):
            result = (initialize if args.action == 'init' else snapshot)(args.evidence_root, args.run_id)
        else:
            item = json.loads(args.input.read_text(encoding='utf-8-sig'))
            result = (append if args.action == 'add' else save_review)(args.evidence_root, args.run_id, item)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
