"""Authored unit scenarios only; generated receipts are not runtime evidence."""
import base64
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import verify_sage_expansion_repair as checker


def encoded(v):
    return base64.b64encode(json.dumps(v).encode()).decode()


class ExpansionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = Path(os.environ['EXPANSION_UNIT_ZIP']).read_bytes()

    def setUp(self):
        self.m = json.loads((checker.ROOT / 'profiles/sageresolution/expansion_repair.json').read_text())
        fs = checker.fixtures(self.m)
        prefix = self.m['module'] + '@' + self.m['version'] + '/'
        with zipfile.ZipFile(io.BytesIO(self.archive)) as z:
            files = {name: base64.b64encode(z.read(prefix + name)).decode() for name in self.m['source_files']}
        source = {'request': checker.request(self.m), 'module': self.m['module'], 'version': self.m['version'], 'sum': self.m['sum'], 'replaced': False, 'operation': 'debug.ReadBuildInfo + local go env + module cache/ZIP byte capture', 'compiler': 'go1.26.8', 'environment_compiler': 'go1.26.8', 'archive': base64.b64encode(self.archive).decode(), 'files': files, 'diagnostics': []}
        audit = json.loads((checker.ROOT / 'profiles/sageresolution/expansion_source_witness.json').read_text())
        audit['roles'].update(method_extensions='true', service_extensions='true')
        audit['steps'][1]['correct'] = True
        audit['steps'][1]['expressions'] = ['typed Method.Extra read: true', 'typed Service.Extra read: true']
        pairs = [('expand', 'expandJSONMap'), ('expandMethod', 'expandJSONMap'), ('expandJSONMap', 'absoluteString'), ('expandJSONMap', 'expandJSONValue'), ('expandJSONValue', 'expandJSONMap'), ('expandJSONValue', 'expandJSONValue')]
        edges = [[self.m['module'] + '/resolver.' + n for n in pair] for pair in pairs]
        for edge in edges:
            for n in edge: audit['frames'].setdefault(n, '0' * 64)
        runtime, items = [], []
        for f, document in fs:
            data = base64.b64encode(document).decode()
            options = {'accept': 'application/did'}
            enabled = f['request'].get('options', {}).get('expandRelativeUrls') is True
            if enabled: options['expandRelativeUrls'] = True
            wire = copy.deepcopy(f['expected'])
            if enabled: wire['@context'] = 'https://www.w3.org/ns/did/v1.1'
            runtime.append({'role': checker.common.ROLE, 'operation': 'github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve', 'request': {'document': {'data': data, 'media_type': 'application/did'}, 'request': f['request']}, 'options': encoded(options), 'resolve_inputs': ['did:example:123'], 'resolve_options': [encoded(options)], 'driver_inputs': ['did:example:123'], 'driver_options': [encoded({'VersionID': '', 'VersionTime': None, 'MediaType': 'application/did', 'NoCache': False})], 'driver_results': [encoded({'Data': data, 'ContentType': 'application/did', 'Metadata': {}})], 'consumption': [{'operation': 'github.com/sage-x-project/did-go/consumer.Consumer.Consume', 'input': data, 'media_type': 'application/did', 'require': 'unknown', 'expected': 'unknown', 'strict': False, 'version': '1.1', 'json_ld': False, 'dropped_terms': None, 'model': encoded(f['document']), 'entries': encoded({})}], 'data_model': encoded(f['expected']), 'resolved_data_model': encoded(f['expected']), 'entries': encoded({}), 'resolved_entries': encoded({}), 'resolved_metadata': encoded({'contentType': 'application/did'}), 'result': {'has_content': True, 'returned_id': 'did:example:123', 'content_kind': 'document', 'snapshot': f['expected'], 'raw': encoded(wire), 'metadata': {'contentType': 'application/did'}, 'content_metadata': {}}})
            for path in f['extension_paths']:
                a, b = f['document'], f['expected']
                for part in path:
                    a = a[int(part)] if isinstance(a, list) else a[part]
                    b = b[int(part)] if isinstance(b, list) else b[part]
                items.append({'path': path, 'original': a, 'expected': b, 'observed': b, 'qualifies': True})
        proof = {'source': source, 'audit': audit, 'edges': edges, 'runtime': runtime, 'items': items}
        subject = {k: self.m['subject'][k] for k in ['name', 'version', 'revision']}
        ids = checker.common.inventory(self.m)
        self.e = {'scope': checker.SCOPE, 'runtime_results_merged': False, 'raw': {'subject': copy.deepcopy(subject), 'profile': 'did-1.1', 'cases': [{'case': checker.CASE, 'statements': checker.IDS, 'observations': [{'statement': i, 'verdict': 'PASS', 'input': json.dumps(checker.request(self.m)), 'observed': json.dumps(proof)} for i in checker.IDS]}]}, 'report': {'subject': subject, 'profile': 'did-1.1', 'inspector': {'revision': 'authored-unit'}, 'specs': self.m['specs'], 'totals': {'statements': 486, 'PASS': 2, 'FAIL': 0, 'ERROR': 0, 'NOT_SUPPORTED': 0, 'NOT_APPLICABLE': 0, 'NOT_RUN': 484}, 'statements': [{'id': i, 'verdict': 'PASS' if i in checker.IDS else 'NOT_RUN', 'cases': [checker.CASE] if i in checker.IDS else []} for i in sorted(ids)], 'cases': [{'id': checker.CASE, 'statements': checker.IDS, 'verdict': 'PASS', 'observations': 2}], 'not_run': sorted(ids - set(checker.IDS))}}

    def verify(self): return checker.verify(self.e, 'authored-unit', self.m)

    def test_authored_positive_and_cli(self):
        self.assertEqual(self.verify()['actual_native_calls'], 5)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p/'in.json').write_text(json.dumps(self.e))
            with patch.object(sys, 'argv', ['check', '--evidence', str(p/'in.json'), '--observer', 'authored-unit', '--out', str(p/'out.json')]):
                checker.main()
                with self.assertRaises(FileExistsError): checker.main()
            self.assertEqual(json.loads((p/'out.json').read_text())['NOT_RUN'], 484)

    def test_report_controls(self):
        for mutation in [lambda x:x.update(scope='other'), lambda x:x.update(runtime_results_merged=True), lambda x:x['report']['totals'].update(PASS=True), lambda x:x['raw']['subject'].update(revision='other'), lambda x:x['raw']['cases'][0].update(statements=[]), lambda x:x['raw']['cases'][0]['observations'][0].update(input='{}'), lambda x:x['report'].update(statements=[]), lambda x:x['report']['statements'][0].update(cases=['other']), lambda x:x['report']['cases'][0].update(observations=True), lambda x:x['report'].update(not_run=[])]:
            old=copy.deepcopy(self.e);mutation(self.e)
            with self.assertRaises(ValueError):self.verify()
            self.e=old

    def test_proof_controls(self):
        mutations=[lambda x:x.update(analysis_error='missing'),lambda x:x.update(runtime=[]),lambda x:x['source'].update(replaced=True),lambda x:x['source'].update(environment_compiler='other'),lambda x:x['source'].update(archive=base64.b64encode(b'not zip').decode()),lambda x:x['source'].update(sum='other'),lambda x:x['source'].update(files={}),lambda x:x['source']['files'].update({'resolver/expand.go':base64.b64encode(b'changed').decode()}),lambda x:x['audit'].update(roles={}),lambda x:x['audit'].update(unknown=['other']),lambda x:x['audit']['steps'][1].update(correct=False),lambda x:x['audit']['steps'][0].update(expressions=['other']),lambda x:x.update(edges=[]),lambda x:x['audit'].update(frames={}),lambda x:x['items'][0].update(qualifies=1),lambda x:x['items'][0].update(observed='#unchanged')]
        for mutation in mutations:
            old=copy.deepcopy(self.e);o=self.e['raw']['cases'][0]['observations'][0];proof=json.loads(o['observed']);mutation(proof)
            for observation in self.e['raw']['cases'][0]['observations']: observation['observed']=json.dumps(proof)
            with self.assertRaises((ValueError,zipfile.BadZipFile)):self.verify()
            self.e=old
        o=self.e['raw']['cases'][0]['observations'][1];proof=json.loads(o['observed']);proof['unit_only_difference']=True;o['observed']=json.dumps(proof)
        with self.assertRaises(ValueError):self.verify()

    def test_runtime_controls(self):
        mutations=[lambda x:x.update(role='other'),lambda x:x.update(production=[{}]),lambda x:x['request']['request'].update(input='other'),lambda x:x.update(options=encoded({})),lambda x:x.update(driver_options=[encoded({})]),lambda x:x.update(driver_results=[encoded({})]),lambda x:x.update(consumption=[]),lambda x:x['consumption'][0].update(strict=True),lambda x:x['consumption'][0].update(model=encoded({})),lambda x:x.update(data_model=encoded({})),lambda x:x.update(resolved_data_model=encoded({})),lambda x:x.update(entries=encoded({'x':1})),lambda x:x.update(resolved_metadata=encoded({})),lambda x:x['result'].update(native={}),lambda x:x['result'].update(has_content=1),lambda x:x['result'].update(snapshot={}),lambda x:x['result'].update(raw=encoded({}))]
        for mutation in mutations:
            old=copy.deepcopy(self.e);o=self.e['raw']['cases'][0]['observations'][0];proof=json.loads(o['observed']);mutation(proof['runtime'][2])
            for observation in self.e['raw']['cases'][0]['observations']: observation['observed']=json.dumps(proof)
            with self.assertRaises(ValueError):self.verify()
            self.e=old

    def test_frozen_inputs(self):
        self.m['fixture_sha256']='other'
        with self.assertRaises(ValueError):self.verify()
        with self.assertRaises(ValueError):checker.verify(self.e,'',self.m)


if __name__=='__main__':unittest.main()
