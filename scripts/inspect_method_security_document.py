"""Replay a fresh independent author review without replacing historical results.

This command checks the exact committed sixteen-document corpus. The reviewed
judgments are Inspector-owned data, not the subject's own validation results.
It neither classifies arbitrary prose nor executes a protocol implementation.
"""

import argparse
import base64
import copy
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from inspect_method_document import EvidenceError, load_catalog as load_previous


ROOT = Path(__file__).resolve().parents[1]
REVISION = '6d611b19764cfae50936ab4c63dbe4e1f9f78487'
PREVIOUS = '06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b'
REPOSITORY = 'SAGE-X-project/sage-spec'
CATALOG = 'docs/sage-method-security-recheck.json'
CATALOG_SHA256 = 'b587f5b4d765ce953608e058f542075479b8bd91d5778f94252c66e799cdbe57'
CAPTURE_FORMAT = 'did-inspector-method-security-capture/1'
REPORT_FORMAT = 'did-inspector-method-security-report/1'
VERDICTS = ('PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE', 'NOT_RUN')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_catalog(root=ROOT):
    root = Path(root)
    previous = load_previous(root)
    data = (root / CATALOG).read_bytes()
    if sha(data) != CATALOG_SHA256:
        raise EvidenceError('unreviewed fresh author catalog')
    catalog = json.loads(data)
    if (set(catalog) != {
            'format', 'repository', 'revision', 'previous_revision',
            'previous_catalog_sha256', 'files', 'judgments', 'review_report',
            'review_policy', 'protocol_runtime_executed', 'historical_reports_modified'}
            or catalog['format'] != 'did-inspector-method-security-recheck/1'
            or catalog['repository'] != REPOSITORY or catalog['revision'] != REVISION
            or catalog['previous_revision'] != PREVIOUS
            or catalog['protocol_runtime_executed'] is not False
            or catalog['historical_reports_modified'] is not False
            or catalog['previous_catalog_sha256'] != sha(
                (root / 'docs/sage-method-document-review.json').read_bytes())):
        raise EvidenceError('fresh review identity or scope drift')
    files = catalog['files']
    if ([f['path'] for f in files] != [f['path'] for f in previous['files']]
            or len(files) != 16 or len({f['path'] for f in files}) != 16):
        raise EvidenceError('fresh corpus inventory drift')
    if ([r['id'] for r in catalog['judgments']] != [r['id'] for r in previous['rows']]
            or len(catalog['judgments']) != 51):
        raise EvidenceError('fresh statement inventory drift')
    rows = []
    for current, old in zip(catalog['judgments'], previous['rows']):
        if (set(current) != {'id', 'scope', 'verdict', 'review_basis', 'text_sha256'}
                or current['text_sha256'] != old['text_sha256']
                or current['verdict'] not in set(VERDICTS) - {'ERROR'}
                or not current['scope'] or not current['review_basis']):
            raise EvidenceError('unreviewed author judgment')
        rows.append({**current, 'level': old['level'],
                     'pending_review': copy.deepcopy(old.get('pending_review'))})
    review = catalog['review_report']
    if (set(review) != {'path', 'sha256'}
            or review['path'] != 'docs/sage-method-security-author-review.md'
            or sha((root / review['path']).read_bytes()) != review['sha256']):
        raise EvidenceError('independent review source drift')
    return {**catalog, 'rows': rows}


def capture(repository, catalog):
    def git(*args):
        try:
            return subprocess.check_output(
                ['git', '--no-replace-objects', '-C', str(repository), *args],
                stderr=subprocess.PIPE, timeout=15)
        except (OSError, subprocess.SubprocessError) as error:
            raise EvidenceError('pinned Git document source unavailable') from error
    if git('rev-parse', '--verify', REVISION + '^{commit}').decode().strip() != REVISION:
        raise EvidenceError('unreviewed document revision')
    files = []
    for source in catalog['files']:
        ref = REVISION + ':' + source['path']
        if git('cat-file', '-s', ref).decode().strip() != str(source['bytes']):
            raise EvidenceError('pinned Git blob size mismatch')
        content = git('cat-file', 'blob', ref)
        files.append({'path': source['path'],
                      'content_base64': base64.b64encode(content).decode('ascii')})
    return {'format': CAPTURE_FORMAT, 'repository': REPOSITORY,
            'revision': REVISION, 'files': files}


def verify_capture(raw, catalog):
    if (not isinstance(raw, dict)
            or set(raw) != {'format', 'repository', 'revision', 'files'}
            or raw['format'] != CAPTURE_FORMAT or raw['repository'] != REPOSITORY
            or raw['revision'] != REVISION or not isinstance(raw['files'], list)
            or len(raw['files']) != 16):
        raise EvidenceError('fresh capture identity or inventory mismatch')
    expected = {f['path']: f for f in catalog['files']}
    actual = {}
    for entry in raw['files']:
        if (not isinstance(entry, dict) or set(entry) != {'path', 'content_base64'}
                or not isinstance(entry['path'], str) or entry['path'] not in expected
                or entry['path'] in actual or not isinstance(entry['content_base64'], str)):
            raise EvidenceError('invalid or duplicate captured file')
        source = expected[entry['path']]
        encoded = entry['content_base64']
        if len(encoded) != ((source['bytes'] + 2) // 3) * 4:
            raise EvidenceError('captured file exceeds its reviewed encoding bound')
        try:
            content = base64.b64decode(encoded, validate=True)
            content.decode('utf-8')
        except (ValueError, UnicodeError) as error:
            raise EvidenceError('invalid captured document bytes') from error
        if (base64.b64encode(content).decode('ascii') != encoded
                or len(content) != source['bytes'] or sha(content) != source['sha256']):
            raise EvidenceError('unreviewed captured document: ' + entry['path'])
        actual[entry['path']] = content
    if set(actual) != set(expected):
        raise EvidenceError('incomplete reviewed corpus')
    return actual


def inspect(catalog, raw, observer):
    if not isinstance(observer, str) or not re.fullmatch(r'[0-9a-f]{40}', observer):
        raise EvidenceError('observer revision must name an exact commit')
    issue = None
    try:
        verify_capture(raw, catalog)
    except (EvidenceError, KeyError, TypeError) as error:
        issue = str(error)
    rows = []
    for source in catalog['rows']:
        verdict = source['verdict']
        if issue and verdict != 'NOT_RUN':
            verdict = 'ERROR'
        row = {'id': source['id'], 'level': source['level'],
               'text_sha256': source['text_sha256'], 'verdict': verdict,
               'scope': source['scope'],
               'detail': issue if issue and verdict == 'ERROR' else source['review_basis'],
               'evidence': [] if issue or verdict == 'NOT_RUN' else copy.deepcopy(catalog['files'])}
        if source['pending_review'] is not None:
            row['pending_review'] = copy.deepcopy(source['pending_review'])
        rows.append(row)
    totals = {v: sum(r['verdict'] == v for r in rows) for v in VERDICTS}
    return {'format': REPORT_FORMAT, 'actor': 'SAGE method specification author',
            'repository': REPOSITORY, 'revision': REVISION,
            'inspector_revision': observer, 'review_policy': catalog['review_policy'],
            'independent_review': catalog['review_report'], 'totals': totals,
            'statements': rows, 'runtime_results_merged': False,
            'historical_reports_modified': False, 'protocol_runtime_executed': False,
            'documentary_gate': 'ERROR' if totals['ERROR'] else 'FAIL' if totals['FAIL'] else 'PASS',
            'previous_review': {'revision': PREVIOUS,
                                'catalog_sha256': catalog['previous_catalog_sha256'],
                                'relationship': 'separate historical subject; not merged'}}


def protected_sources(repository):
    roots = {Path(repository).resolve(), ROOT.resolve()}
    for source in list(roots):
        if not source.exists():
            continue
        try:
            result = subprocess.check_output([
                'git', '--no-replace-objects', '-C', str(source), 'rev-parse',
                '--path-format=absolute', '--show-toplevel', '--absolute-git-dir',
                '--git-common-dir'], stderr=subprocess.PIPE, text=True, timeout=15)
            paths = result.splitlines()
            if len(paths) != 3 or any(not Path(p).is_absolute() for p in paths):
                raise EvidenceError('unresolved Git source boundaries')
            roots.update(Path(p).resolve() for p in paths)
        except (OSError, subprocess.SubprocessError) as error:
            if source != ROOT.resolve():
                raise EvidenceError('cannot establish source checkout boundaries') from error
            # An installed data bundle still protects its own directory.
    return roots


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--raw-out', required=True, type=Path)
    parser.add_argument('--inspector-revision', required=True)
    args = parser.parse_args(argv)
    original_outputs = [args.out, args.raw_out]
    outputs = [p.resolve() for p in original_outputs]
    try:
        protected = protected_sources(args.repository)
    except EvidenceError as error:
        parser.error(str(error))
    if (outputs[0] == outputs[1]
            or any(p.exists() or p.is_symlink() for p in original_outputs)
            or any(p.exists() for p in outputs)
            or any(p == r or r in p.parents for p in outputs for r in protected)):
        parser.error('outputs must be distinct new files outside both source checkouts')
    try:
        catalog = load_catalog()
        issue = None
        try:
            raw = capture(args.repository, catalog)
        except EvidenceError as error:
            issue = str(error)
            raw = {'format': CAPTURE_FORMAT, 'repository': REPOSITORY,
                   'revision': REVISION, 'files': [], 'evidence_error': issue}
        report = inspect(catalog, raw, args.inspector_revision)
        with ExitStack() as stack:
            handles = []
            for path in outputs:
                path.parent.mkdir(parents=True, exist_ok=True)
                handles.append(stack.enter_context(path.open('x', encoding='utf-8')))
            for handle, data in zip(handles, [report, raw]):
                handle.write(json.dumps(data, indent=2) + '\n')
        print(json.dumps(report['totals'], sort_keys=True))
        return 2 if report['totals']['ERROR'] else 1 if report['totals']['FAIL'] else 0
    except (EvidenceError, OSError, KeyError, TypeError, ValueError) as error:
        print('evidence error: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
