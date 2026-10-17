"""Authored checker controls only; these fixtures are not runtime evidence."""
import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_sage_fragment_repair as checker


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


class FragmentEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((checker.ROOT / 'docs/sage-fragment-repair.json').read_text())
        fixed, authored = checker.fixtures(self.manifest)
        subject = {k: self.manifest['subject'][k] for k in ['name', 'version', 'revision']}
        raw = []
        for name, f in fixed.items():
            observed = []
            for i in range(3):
                document = authored[name]['control_document' if i == 1 else 'document']
                model = json.loads(document)
                q = dict(f['request'])
                if i == 2: q['input'] = 'did:example:resources#absent'
                data = base64.b64encode(document).decode()
                result = {'has_content': True, 'returned_id': f['expected_content']['id'], 'content_kind': 'map', 'snapshot': copy.deepcopy(f['expected_content']), 'raw': encoded(f['expected_content']), 'metadata': {'contentType': 'application/ld+json'}, 'content_metadata': {}}
                if i == 2:
                    result = {'has_content': False, 'raw': encoded(None), 'metadata': {'error': {'type': 'https://www.w3.org/ns/did#NOT_FOUND', 'detail': 'absent public fragment'}}, 'content_metadata': {}}
                observed.append({'role': checker.ROLE, 'operation': 'github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference',
                    'request': {'document': {'data': data, 'media_type': 'application/did'}, 'request': q}, 'options': encoded({'accept': 'application/did'}),
                    'resolve_inputs': ['did:example:resources'], 'resolve_options': [encoded({'accept': 'application/did'})], 'driver_inputs': ['did:example:resources'],
                    'driver_options': [encoded({'VersionID': '', 'VersionTime': None, 'MediaType': 'application/did', 'NoCache': False})], 'driver_results': [encoded({'Data': data, 'ContentType': 'application/did', 'Metadata': {}})],
                    'consumption': [{'operation': 'github.com/sage-x-project/did-go/consumer.Consumer.Consume', 'input': data, 'media_type': 'application/did', 'require': 'unknown', 'expected': 'unknown', 'strict': False, 'version': '1.1', 'json_ld': False, 'dropped_terms': None, 'model': encoded(model), 'entries': encoded({})}],
                    'data_model': encoded(model), 'resolved_data_model': encoded(model), 'entries': encoded({}), 'resolved_entries': encoded({}), 'resolved_metadata': encoded({'contentType': 'application/did'}), 'result': result})
            text = json.dumps({k: f[k] for k in ['name', 'document', 'control_document', 'expected_content', 'request']}, separators=(',', ':'), ensure_ascii=False)
            raw.append({'case': checker.PREFIX + name, 'statements': [checker.ID], 'observations': [{'statement': checker.ID, 'verdict': 'PASS', 'input': text, 'observed': json.dumps(observed)}]})
        ids = checker.inventory(self.manifest)
        cases = [x['case'] for x in raw]
        self.evidence = {'scope': checker.SCOPE, 'runtime_results_merged': False,
            'raw': {'subject': copy.deepcopy(subject), 'profile': 'did-1.1', 'cases': raw},
            'report': {'subject': subject, 'profile': 'did-1.1', 'inspector': {'revision': 'unit-observer'}, 'specs': self.manifest['specs'],
                'totals': {'statements': 486, 'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'NOT_APPLICABLE': 0, 'NOT_SUPPORTED': 0, 'NOT_RUN': 485},
                'statements': [{'id': i, 'verdict': 'PASS' if i == checker.ID else 'NOT_RUN', 'cases': cases if i == checker.ID else []} for i in sorted(ids)],
                'cases': [{'id': c, 'statements': [checker.ID], 'verdict': 'PASS', 'observations': 1} for c in cases], 'not_run': sorted(ids - {checker.ID})}}

    def verify(self):
        return checker.verify(self.evidence, 'unit-observer', self.manifest)

    def test_authored_positive_and_cli(self):
        self.assertEqual(self.verify()['actual_native_calls'], 15)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'input.json').write_text(json.dumps(self.evidence))
            with patch.object(sys, 'argv', ['checker', '--evidence', str(p / 'input.json'), '--observer', 'unit-observer', '--out', str(p / 'out.json')]):
                checker.main()
                with self.assertRaises(FileExistsError): checker.main()
            self.assertEqual(json.loads((p / 'out.json').read_text())['cases'], 5)

    def test_report_mutations(self):
        mutations = [lambda x: x.update(runtime_results_merged=True), lambda x: x.update(scope='other'), lambda x: x['raw']['subject'].update(revision='other'),
            lambda x: x['report']['inspector'].update(revision='other'), lambda x: x['raw'].update(profile='other'), lambda x: x['report'].update(specs=[]),
            lambda x: x['report']['totals'].update(PASS=True), lambda x: x['report']['totals'].update(NOT_RUN=0),
            lambda x: x['raw']['cases'][0]['observations'][0].update(input='{}'), lambda x: x['raw']['cases'][0]['observations'][0].update(verdict='FAIL'),
            lambda x: x['raw']['cases'][0].update(case='other'), lambda x: x['raw'].update(cases=[]), lambda x: x['raw']['cases'][0].update(statements=[]),
            lambda x: x['raw']['cases'][0]['observations'][0].update(observed='[]'), lambda x: x['report'].update(statements=[]),
            lambda x: x['report']['statements'][0].update(verdict='PASS'), lambda x: x['report']['statements'][0].update(cases=['other']),
            lambda x: x['report']['cases'][0].update(observations=True), lambda x: x['report']['cases'][0].update(id='other'), lambda x: x['report'].update(not_run=[])]
        original = copy.deepcopy(self.evidence)
        for i, mutate in enumerate(mutations):
            with self.subTest(i=i):
                self.evidence = copy.deepcopy(original); mutate(self.evidence)
                with self.assertRaises(ValueError): self.verify()

    def test_observation_mutations(self):
        mutations = [(0, lambda x: x.update(role='other')), (0, lambda x: x.update(production=[{}])), (0, lambda x: x['request']['request'].update(input='other')),
            (0, lambda x: x.update(options=encoded({}))), (0, lambda x: x.update(resolve_inputs=[])), (0, lambda x: x.update(driver_inputs=[])),
            (0, lambda x: x.update(driver_options=[encoded({'NoCache': True})])), (0, lambda x: x.update(driver_results=[encoded({})])),
            (0, lambda x: x.update(consumption=[])), (0, lambda x: x['consumption'][0].update(error='bad')), (0, lambda x: x['consumption'][0].update(strict=True)),
            (0, lambda x: x['consumption'][0].update(model=encoded({}))), (0, lambda x: x.update(resolved_data_model=encoded({}))),
            (0, lambda x: x['result'].update(native={})), (0, lambda x: x['result'].update(has_content=False)), (0, lambda x: x['result'].update(snapshot={})),
            (0, lambda x: x['result'].update(raw=encoded({}))), (0, lambda x: x['result'].update(content_metadata={'unrelated': True})),
            (2, lambda x: x['result']['metadata']['error'].update(type='other')), (2, lambda x: x['result'].update(raw=encoded({}))), (2, lambda x: x['result'].update(snapshot={'id': 'did:example:resources#target'})), (2, lambda x: x['result'].update(content_kind='map')),
            (1, lambda x: x.update(capture_error='lost')), (1, lambda x: x['result']['snapshot']['values'].__setitem__(0, 0))]
        original = copy.deepcopy(self.evidence)
        for j, (i, mutate) in enumerate(mutations):
            with self.subTest(j=j):
                self.evidence = copy.deepcopy(original)
                o = self.evidence['raw']['cases'][0]['observations'][0]
                values = json.loads(o['observed']); mutate(values[i]); o['observed'] = json.dumps(values)
                with self.assertRaises(ValueError): self.verify()

    def test_frozen_sources_and_typed_values(self):
        for field in ['fixture_sha256', 'case_inputs']:
            manifest = copy.deepcopy(self.manifest); manifest[field] = '' if field.endswith('sha256') else {}
            with self.assertRaises(ValueError): checker.verify(self.evidence, 'unit-observer', manifest)
        manifest = copy.deepcopy(self.manifest); manifest['specs'][0]['sha256'] = 'other'
        with self.assertRaises(ValueError): checker.inventory(manifest)
        self.assertFalse(checker.equal([False], [0])); self.assertFalse(checker.equal({'a': 1}, {'b': 1})); self.assertFalse(checker.equal([1], [])); self.assertFalse(checker.equal('x', 'y'))
        with self.assertRaises(ValueError): checker.decoded(None)


if __name__ == '__main__':
    unittest.main()
