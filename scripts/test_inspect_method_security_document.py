"""Fixed-corpus review and evidence-refusal tests; no attack service or client."""

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import inspect_method_document as previous
import inspect_method_security_document as fresh


class FreshMethodSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = fresh.load_catalog()
        cls.repository = Path(os.environ.get(
            'SAGE_METHOD_SECURITY_SPEC_ROOT', str(fresh.ROOT / '.method-security-spec')))
        if not cls.repository.is_dir():
            raise RuntimeError('fixed source checkout required; no skipped source checks')
        cls.raw = fresh.capture(cls.repository, cls.catalog)
        fresh.verify_capture(cls.raw, cls.catalog)
        cls.old_catalog_sha = hashlib.sha256(
            (fresh.ROOT / 'docs/sage-method-document-review.json').read_bytes()).hexdigest()

    def test_exact_corpus_reports_reviewed_author_findings(self):
        result = fresh.inspect(self.catalog, self.raw, '0' * 40)
        self.assertEqual(result['totals'], {
            'PASS': 26, 'FAIL': 4, 'ERROR': 0, 'NOT_APPLICABLE': 19, 'NOT_RUN': 2})
        self.assertEqual(result['documentary_gate'], 'FAIL')
        self.assertFalse(result['runtime_results_merged'])
        self.assertFalse(result['historical_reports_modified'])
        self.assertFalse(result['protocol_runtime_executed'])
        self.assertEqual(result['revision'], fresh.REVISION)

    def test_missing_changed_or_unexpected_source_has_no_replayed_judgments(self):
        alternatives = []
        raw = copy.deepcopy(self.raw)
        raw['files'].pop()
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        raw['revision'] = fresh.PREVIOUS
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        raw['files'][1] = copy.deepcopy(raw['files'][0])
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        raw['files'][0]['unknown'] = 'unused'
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        raw['files'][0]['content_base64'] = '!' * len(raw['files'][0]['content_base64'])
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        raw['files'][0]['content_base64'] += 'AAAA'
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        content = base64.b64decode(raw['files'][0]['content_base64'])
        replacement = b'!' if content[:1] != b'!' else b'#'
        raw['files'][0]['content_base64'] = base64.b64encode(replacement + content[1:]).decode('ascii')
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        content = base64.b64decode(raw['files'][0]['content_base64'])
        raw['files'][0]['content_base64'] = base64.b64encode(b'\xff' + content[1:]).decode('ascii')
        alternatives.append(raw)
        raw = copy.deepcopy(self.raw)
        entry = next(f for f in raw['files'] if f['path'] == 'spec/06-did-sage.md')
        entry['content_base64'] = base64.b64encode(base64.b64decode(
            entry['content_base64']).replace(b'\n', b'\r\n')).decode('ascii')
        alternatives.append(raw)
        for raw in alternatives:
            with self.subTest(shape=list(raw)):
                result = fresh.inspect(self.catalog, raw, '0' * 40)
                self.assertEqual(result['totals'], {
                    'PASS': 0, 'FAIL': 0, 'ERROR': 49, 'NOT_APPLICABLE': 0, 'NOT_RUN': 2})
                self.assertTrue(all(not r['evidence'] for r in result['statements']))

    def test_error_metadata_cannot_bypass_capture_verification(self):
        raw = {'format': fresh.CAPTURE_FORMAT, 'repository': fresh.REPOSITORY,
               'revision': fresh.REVISION, 'files': [], 'evidence_error': ''}
        self.assertEqual(fresh.inspect(self.catalog, raw, '0' * 40)['totals']['ERROR'], 49)

    def test_pending_issuer_contracts_and_original_statement_identity_survive(self):
        old = previous.load_catalog()
        result = fresh.inspect(self.catalog, self.raw, '0' * 40)
        self.assertEqual([r['id'] for r in result['statements']], [r['id'] for r in old['rows']])
        self.assertEqual([r['text_sha256'] for r in result['statements']],
                         [r['text_sha256'] for r in old['rows']])
        for source, row in zip(old['rows'], result['statements']):
            if 'pending_review' in source:
                self.assertEqual(row['pending_review'], source['pending_review'])
                self.assertEqual(row['verdict'], 'NOT_RUN')

    def test_observer_identity_is_not_optional(self):
        for observer in ('', 'main', '0' * 39, 'A' * 40, None):
            with self.subTest(observer=observer), self.assertRaises(fresh.EvidenceError):
                fresh.inspect(self.catalog, self.raw, observer)

    def test_returned_evidence_cannot_mutate_reviewed_catalog(self):
        result = fresh.inspect(self.catalog, self.raw, '0' * 40)
        row = next(r for r in result['statements'] if r['evidence'])
        before = copy.deepcopy(self.catalog['files'])
        row['evidence'][0]['sha256'] = '0' * 64
        self.assertEqual(self.catalog['files'], before)

    def test_unreviewed_judgment_or_review_artifact_is_refused(self):
        names = {'docs/sage-method-document-review.json',
                 'docs/sage-remaining-clause-review.json', fresh.CATALOG,
                 'docs/sage-method-security-author-review.md'}
        for name in ('cid10.json', 'did11-cr20260305.json', 'res10-crd20261001.json'):
            names.add('statements/' + name)
            content = json.loads((fresh.ROOT / 'statements' / name).read_text())
            names.add('statements/' + content['source'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(fresh.ROOT / name, dest)
            fresh.load_catalog(root)
            path = root / fresh.CATALOG
            original = path.read_bytes()
            data = json.loads(original)
            next(r for r in data['judgments'] if r['verdict'] == 'FAIL')['verdict'] = 'PASS'
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(fresh.EvidenceError, 'unreviewed fresh author catalog'):
                fresh.load_catalog(root)
            path.write_bytes(original)
            path = root / 'docs/sage-method-security-author-review.md'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(fresh.EvidenceError, 'independent review source drift'):
                fresh.load_catalog(root)

    def test_safe_git_cli_and_historical_catalog_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.json'
            raw = Path(directory) / 'capture.json'
            run = subprocess.run([
                sys.executable, '-B', str(fresh.ROOT / 'scripts/inspect_method_security_document.py'),
                '--repository', str(self.repository), '--out', str(report),
                '--raw-out', str(raw), '--inspector-revision', '0' * 40],
                capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 1, run.stderr)
            result = json.loads(report.read_text())
            self.assertEqual(result['totals']['FAIL'], 4)
            self.assertEqual(result['totals']['ERROR'], 0)
            fresh.verify_capture(json.loads(raw.read_text()), self.catalog)
        self.assertEqual(hashlib.sha256(
            (fresh.ROOT / 'docs/sage-method-document-review.json').read_bytes()).hexdigest(),
            self.old_catalog_sha)

    def test_cli_refuses_existing_output_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / 'keep.json'
            existing.write_bytes(b'owned existing data')
            result = subprocess.run([
                sys.executable, '-B', str(fresh.ROOT / 'scripts/inspect_method_security_document.py'),
                '--repository', str(self.repository), '--out', str(existing),
                '--raw-out', str(Path(directory) / 'capture.json'),
                '--inspector-revision', '0' * 40], capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(existing.read_bytes(), b'owned existing data')

    def test_dangling_output_link_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'absent.json'
            link = root / 'link.json'
            link.symlink_to(target)
            args = ['--repository', str(self.repository), '--out', str(link),
                    '--raw-out', str(root / 'capture.json'),
                    '--inspector-revision', '0' * 40]
            with patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                fresh.main(args)
            self.assertEqual(error.exception.code, 2)
            self.assertTrue(link.is_symlink())
            self.assertFalse(target.exists())

    def test_exclusive_creation_preserves_a_concurrent_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, raw = root / 'report.json', root / 'capture.json'
            original_open = Path.open
            sentinel = 'owned temporary fixture'

            def open_with_collision(path, mode='r', *args, **kwargs):
                if path == raw.resolve() and mode == 'x':
                    with original_open(path, 'x', encoding='utf-8') as handle:
                        handle.write(sentinel)
                return original_open(path, mode, *args, **kwargs)

            args = ['--repository', str(self.repository), '--out', str(report),
                    '--raw-out', str(raw), '--inspector-revision', '0' * 40]
            with patch.object(Path, 'open', open_with_collision), patch(
                    'sys.stderr', new_callable=io.StringIO):
                self.assertEqual(fresh.main(args), 2)
            self.assertEqual(raw.read_text(), sentinel)
            self.assertEqual(report.read_bytes(), b'')

    def test_subdirectory_input_protects_actual_checkout_and_git_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / 'source'
            checkout.mkdir()
            subprocess.run(['git', '-c', 'init.templateDir=', 'init', '--quiet', str(checkout)],
                           check=True, capture_output=True)
            subdirectory = checkout / 'nested'
            subdirectory.mkdir()
            protected = fresh.protected_sources(subdirectory)
            self.assertIn(checkout.resolve(), protected)
            self.assertIn((checkout / '.git').resolve(), protected)
            for output in (checkout / 'new.json', checkout / '.git' / 'new.json'):
                args = ['--repository', str(subdirectory), '--out', str(output),
                        '--raw-out', str(root / 'capture.json'),
                        '--inspector-revision', '0' * 40]
                with patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                    fresh.main(args)
                self.assertEqual(error.exception.code, 2)
                self.assertFalse(output.exists())

    def test_command_entry_reports_source_errors_without_a_normative_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good_args = ['--repository', str(self.repository),
                         '--out', str(root / 'good.json'),
                         '--raw-out', str(root / 'good-raw.json'),
                         '--inspector-revision', '0' * 40]
            with patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(fresh.main(good_args), 1)
            bad_args = ['--repository', str(root / 'missing-repository'),
                        '--out', str(root / 'error.json'),
                        '--raw-out', str(root / 'error-raw.json'),
                        '--inspector-revision', '0' * 40]
            with patch('sys.stdout', new_callable=io.StringIO):
                self.assertEqual(fresh.main(bad_args), 2)
            self.assertEqual(json.loads((root / 'error.json').read_text())['totals'], {
                'PASS': 0, 'FAIL': 0, 'ERROR': 49, 'NOT_APPLICABLE': 0, 'NOT_RUN': 2})
            self.assertTrue(json.loads((root / 'error-raw.json').read_text())['evidence_error'])


if __name__ == '__main__':
    unittest.main()
