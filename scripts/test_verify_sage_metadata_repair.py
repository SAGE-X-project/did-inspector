"""Authored unit controls for the bounded checker; never runtime evidence."""
import base64
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_sage_metadata_repair as checker


class MetadataEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((checker.ROOT / 'docs/sage-metadata-repair.json').read_text())
        self.original = (checker.ROOT / 'scripts/testdata/sage-metadata-input.json').read_text().rstrip('\n')
        q = json.loads(self.original)['Request']
        reply = json.loads(base64.b64decode(q['reply']))
        self.actual = {'request': q, 'operation': 'github.com/sage-x-project/did-go/resolution/universal.Client.resolve',
                       'server_tls': True, 'server_calls': 1, 'server_role': 'controlled client response fixture; not SAGE server output',
                       'endpoint': 'https://127.0.0.1:1234/1.0/identifiers/', 'native': [], 'consumer': [{'operation': 'github.com/sage-x-project/did-go/consumer.Consumer.Consume', 'media_type': 'application/did', 'require': 'unknown', 'expected': 'unknown', 'strict': False, 'version': '1.1', 'json_ld': False, 'dropped_terms': None, 'input': base64.b64encode(json.dumps(reply['didDocument']).encode()).decode(), 'model': base64.b64encode(json.dumps(reply['didDocument']).encode()).decode(), 'entries': base64.b64encode(b'{}').decode()}],
                       'wire': [{'method': 'GET', 'url': 'https://127.0.0.1:1234/1.0/identifiers/' + q['request']['input'],
                                 'accept': 'application/did', 'body': None, 'content_type': ''}],
                       'result': {'content_kind': 'document', 'snapshot': copy.deepcopy(reply['didDocument']), 'raw': base64.b64encode(json.dumps(reply['didDocument']).encode()).decode(), 'has_content': True, 'returned_id': q['request']['input'],
                                  'metadata': reply['didResolutionMetadata'], 'content_metadata': reply['didDocumentMetadata']}}
        subject = {k: self.manifest['subject'][k] for k in ['name', 'version', 'revision']}
        observation = {'statement': checker.ID, 'verdict': 'PASS', 'input': self.original, 'observed': json.dumps(self.actual)}
        statements = [{'id': i, 'verdict': 'PASS' if i == checker.ID else 'NOT_RUN'} for i in sorted(checker.inventory(self.manifest))]
        self.evidence = {'runtime_results_merged': False,
                         'report': {'inspector': {'revision': 'unit-observer'}, 'subject': subject, 'profile': 'did-1.1',
                                    'specs': self.manifest['specs'], 'statements': statements, 'not_run': sorted(checker.inventory(self.manifest) - {checker.ID}), 'cases': [{'id': self.manifest['case'], 'statements': [checker.ID], 'verdict': 'PASS', 'observations': 1}],
                                    'totals': {'statements': 486, 'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'NOT_APPLICABLE': 0, 'NOT_SUPPORTED': 0, 'NOT_RUN': 485}},
                         'raw': {'subject': copy.deepcopy(subject), 'profile': 'did-1.1',
                                 'cases': [{'case': self.manifest['case'], 'statements': [checker.ID], 'observations': [observation]}]}}

    def verify(self):
        return checker.verify(self.evidence, 'unit-observer', self.manifest, self.original)

    def test_authored_positive_and_main(self):
        self.assertEqual(self.verify()['actual_TLS_calls'], 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / 'input.json').write_text(json.dumps(self.evidence))
            with patch.object(sys, 'argv', ['checker', '--evidence', str(path / 'input.json'), '--observer', 'unit-observer', '--out', str(path / 'result.json')]):
                checker.main()
                with self.assertRaises(FileExistsError): checker.main()
            self.assertEqual(json.loads((path / 'result.json').read_text())['selected_PASS'], [checker.ID])

    def test_report_and_identity_mutations(self):
        changes = [lambda x: x.update(runtime_results_merged=True),
                   lambda x: x['report']['inspector'].update(revision='other'),
                   lambda x: x['raw']['subject'].update(revision='other'),
                   lambda x: x['report'].update(specs=[]), lambda x: x['raw'].update(profile='other'),
                   lambda x: x['raw'].update(cases=[]),
                   lambda x: x['raw']['cases'][0].update(case='other'),
                   lambda x: x['raw']['cases'][0]['observations'][0].update(verdict='FAIL'),
                   lambda x: x['raw']['cases'][0]['observations'][0].update(input='{}'),
                   lambda x: x['report']['totals'].update(PASS=2), lambda x: x['report']['totals'].update(PASS=True), lambda x: x['report']['totals'].update(FAIL=False),
                   lambda x: x['report'].update(statements=[]),
                   lambda x: x['report']['statements'][1].update(verdict='PASS'), lambda x: x['report']['statements'][1].update(id='authored-unknown'), lambda x: x['report']['cases'][0].update(id='other'), lambda x: x['report'].update(not_run=[])]
        original = copy.deepcopy(self.evidence)
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.evidence = copy.deepcopy(original)
                change(self.evidence)
                with self.assertRaises(ValueError): self.verify()

    def test_actual_observation_mutations(self):
        changes = [lambda x: x['request'].update(post=True), lambda x: x.update(operation='other'),
                   lambda x: x.update(server_calls=2), lambda x: x.update(server_role='untrusted'),
                   lambda x: x.update(endpoint='https://192.0.2.1/1.0/identifiers/'),
                   lambda x: x['wire'][0].update(method='POST'), lambda x: x['consumer'][0].update(error='refused'),
                   lambda x: x['result'].update(has_content=False),
                   lambda x: x['result']['metadata'].update(extension={}),
                   lambda x: x['result']['content_metadata'].pop('deactivated'),
                   lambda x: x['result']['content_metadata'].update(deactivated=0),
                   lambda x: x['result']['content_metadata'].update(proof=[]), lambda x: x.update(server_calls=True), lambda x: x.update(native=False), lambda x: x['wire'][0].update(body=False), lambda x: x['consumer'][0].update(error=False), lambda x: x['consumer'][0].update(operation='other'), lambda x: x['consumer'][0].update(model=base64.b64encode(b'{}').decode()), lambda x: x.update(endpoint=x['endpoint'] + '?'), lambda x: x.update(endpoint=x['endpoint'] + '#')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                actual = copy.deepcopy(self.actual)
                change(actual)
                self.evidence['raw']['cases'][0]['observations'][0]['observed'] = json.dumps(actual)
                with self.assertRaises(ValueError): self.verify()

    def test_typed_equality(self):
        self.assertTrue(checker.equal([{'a': False}], [{'a': False}]))
        self.assertFalse(checker.equal(False, 0))
        self.assertFalse(checker.equal([False], [0]))
        self.assertFalse(checker.equal([1], []))
        self.assertFalse(checker.equal({'a': 1}, {'b': 1}))
        self.assertFalse(checker.equal('a', 'b'))
        self.assertEqual(hashlib.sha256(self.original.encode()).hexdigest(), self.manifest['input_sha256'])


if __name__ == '__main__':
    unittest.main()
