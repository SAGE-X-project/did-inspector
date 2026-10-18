"""Authored unit scenarios only; generated receipts are not runtime evidence."""
import base64
import copy
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import verify_sage_resource_repair as checker


def encoded(v):
    return base64.b64encode(json.dumps(v).encode()).decode()


class ResourceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = (checker.ROOT / 'checks/sourcearith/testdata/did-go-resource.zip').read_bytes()

    def setUp(self):
        self.m = json.loads((checker.ROOT / 'profiles/sageresolution/resource_repair.json').read_text())
        fs = checker.fixtures(self.m)
        prefix = self.m['module'] + '@' + self.m['version'] + '/'
        with zipfile.ZipFile(io.BytesIO(self.archive)) as z:
            files = {name: base64.b64encode(z.read(prefix + name)).decode() for name in self.m['source_files']}
        source = {'request': checker.request(self.m), 'module': self.m['module'], 'version': self.m['version'], 'sum': self.m['sum'], 'replaced': False, 'operation': 'debug.ReadBuildInfo + local go env + module cache/ZIP byte capture', 'compiler': 'go1.26.8', 'environment_compiler': 'go1.26.8', 'archive': base64.b64encode(self.archive).decode(), 'files': files, 'diagnostics': []}
        audit = json.loads((checker.ROOT / 'profiles/sageresolution/url_roles_witness.json').read_text())
        audit['steps'][0].update(correct=True, expressions=['u.WithoutFragment()'])
        edges = [[audit['roots'][1], self.m['module'] + '/did.(' + self.m['module'] + '/did.DIDURL).WithoutFragment']]
        runtime = []
        for f, document in fs:
            data = base64.b64encode(document).decode()
            options = {'accept': 'application/did'}
            nested = dict(options)
            if f['parts']['has_query']: nested['relativeRef'] = 'next'
            result = {'has_content': not bool(f['diagnostic_error']), 'content_metadata': {}, 'raw': encoded(f['expected_content'])}
            if f['diagnostic_error']:
                result['metadata'] = {'error': {'type': f['diagnostic_error']}}
            else:
                result.update(metadata={'contentType': 'application/ld+json'}, content_kind=f['expected_kind'], snapshot=f['expected_content'], returned_id=f['expected_content']['id'])
            handlers = [{'Operation': 'github.com/sage-x-project/did-go/dereferencer.ResourceHandler', 'Role': 'literal passive resource handler; records actual values and returns unhandled', 'URL': f['adjusted'], 'Options': encoded(options), 'Model': encoded(f['document']), 'Entries': encoded({}), 'Metadata': encoded({'contentType': 'application/did'})}] if f['handler_calls'] else []
            runtime.append({'role': checker.common.ROLE, 'operation': 'github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference', 'request': {'document': {'data': data, 'media_type': 'application/did'}, 'request': f['request'], 'observe_resource_handler': True}, 'options': encoded(options), 'resolve_inputs': ['did:example:resources'], 'resolve_options': [encoded(nested)], 'driver_inputs': ['did:example:resources'], 'driver_options': [encoded({'VersionID': '', 'VersionTime': None, 'MediaType': 'application/did', 'NoCache': False})], 'driver_results': [encoded({'Data': data, 'ContentType': 'application/did', 'Metadata': {}})], 'consumption': [{'operation': 'github.com/sage-x-project/did-go/consumer.Consumer.Consume', 'input': data, 'media_type': 'application/did', 'require': 'unknown', 'expected': 'unknown', 'strict': False, 'version': '1.1', 'json_ld': False, 'dropped_terms': None, 'model': encoded(f['document']), 'entries': encoded({})}], 'data_model': encoded(f['document']), 'resolved_data_model': encoded(f['document']), 'entries': encoded({}), 'resolved_entries': encoded({}), 'resolved_metadata': encoded({'contentType': 'application/did'}), 'resource_handler': handlers, 'result': result})
        proof = {'source': source, 'audit': audit, 'edges': edges, 'runtime': runtime}
        subject = {k: self.m['subject'][k] for k in ['name', 'version', 'revision']}
        ids = checker.common.inventory(self.m)
        self.e = {'scope': checker.SCOPE, 'runtime_results_merged': False, 'raw': {'subject': copy.deepcopy(subject), 'profile': 'did-1.1', 'cases': [{'case': checker.CASE, 'statements': checker.IDS, 'observations': [{'statement': i, 'verdict': 'PASS', 'input': json.dumps(checker.request(self.m)), 'observed': json.dumps(proof)} for i in checker.IDS]}]}, 'report': {'subject': subject, 'profile': 'did-1.1', 'inspector': {'revision': 'authored-unit'}, 'specs': self.m['specs'], 'totals': {'statements': 486, 'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'NOT_SUPPORTED': 0, 'NOT_APPLICABLE': 0, 'NOT_RUN': 485}, 'statements': [{'id': i, 'verdict': 'PASS' if i in checker.IDS else 'NOT_RUN', 'cases': [checker.CASE] if i in checker.IDS else []} for i in sorted(ids)], 'cases': [{'id': checker.CASE, 'statements': checker.IDS, 'verdict': 'PASS', 'observations': 1}], 'not_run': sorted(ids - set(checker.IDS))}}

    def verify(self): return checker.verify(self.e, 'authored-unit', self.m)

    def test_authored_positive_and_cli(self):
        self.assertEqual(self.verify()['actual_native_calls'], 7)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p/'in.json').write_text(json.dumps(self.e))
            with patch.object(sys, 'argv', ['check', '--evidence', str(p/'in.json'), '--observer', 'authored-unit', '--out', str(p/'out.json')]):
                checker.main()
                with self.assertRaises(FileExistsError): checker.main()
            self.assertEqual(json.loads((p/'out.json').read_text())['NOT_RUN'], 485)

    def test_report_controls(self):
        for mutation in [lambda x:x.update(scope='other'), lambda x:x.update(runtime_results_merged=True), lambda x:x['report']['totals'].update(PASS=True), lambda x:x['raw']['subject'].update(revision='other'), lambda x:x['raw']['cases'][0].update(statements=[]), lambda x:x['raw']['cases'][0]['observations'][0].update(input='{}'), lambda x:x['report'].update(statements=[]), lambda x:x['report']['statements'][0].update(cases=['other']), lambda x:x['report']['cases'][0].update(observations=True), lambda x:x['report'].update(not_run=[])]:
            old=copy.deepcopy(self.e);mutation(self.e)
            with self.assertRaises(ValueError):self.verify()
            self.e=old

    def test_proof_controls(self):
        mutations = [lambda x:x.update(analysis_error='missing'), lambda x:x.update(runtime=[]), lambda x:x['source'].update(replaced=True), lambda x:x['source'].update(environment_compiler='other'), lambda x:x['source'].update(archive=base64.b64encode(b'not zip').decode()), lambda x:x['source'].update(sum='other'), lambda x:x['source'].update(files={}), lambda x:x['source']['files'].update({'dereferencer/dereferencer.go':base64.b64encode(b'changed').decode()}), lambda x:x['audit'].update(roles={}), lambda x:x['audit'].update(unknown=['other']), lambda x:x['audit']['steps'][0].update(correct=False), lambda x:x['audit']['steps'][0].update(expressions=['u']), lambda x:x['audit']['steps'][1].update(correct=False), lambda x:x.update(edges=[]), lambda x:x['audit'].update(frames={}), lambda x:x['audit']['frames'].update(extra='invalid')]
        for mutation in mutations:
            self.refuse(mutation)

    def refuse(self, mutation):
        old=copy.deepcopy(self.e);o=self.e['raw']['cases'][0]['observations'][0];proof=json.loads(o['observed']);mutation(proof);o['observed']=json.dumps(proof)
        with self.assertRaises((ValueError,zipfile.BadZipFile)):self.verify()
        self.e=old

    def test_runtime_controls(self):
        mutations=[lambda x:x.update(role='other'),lambda x:x.update(production=[{}]),lambda x:x['request']['request'].update(input='other'),lambda x:x.update(options=encoded({})),lambda x:x.update(resolve_options=[encoded({})]),lambda x:x.update(driver_options=[encoded({})]),lambda x:x.update(driver_results=[encoded({})]),lambda x:x.update(consumption=[]),lambda x:x['consumption'][0].update(strict=True),lambda x:x['consumption'][0].update(model=encoded({})),lambda x:x.update(data_model=encoded({})),lambda x:x.update(resolved_data_model=encoded({})),lambda x:x.update(entries=encoded({'x':1})),lambda x:x.update(resolved_metadata=encoded({})),lambda x:x['result'].update(native={}),lambda x:x['result'].update(has_content=True),lambda x:x['result'].update(raw=encoded({})),lambda x:x['result'].update(snapshot={}),lambda x:x['result'].update(content_kind='map'),lambda x:x['result'].update(returned_id='other'),lambda x:x.update(resource_handler=[]),lambda x:x['resource_handler'][0].update(Role='other'),lambda x:x['resource_handler'][0].update(Options=encoded({})),lambda x:x['resource_handler'][0]['URL'].update(fragment='changed'),lambda x:x['resource_handler'][0]['URL'].update(has_fragment=True),lambda x:x['resource_handler'][0]['URL'].update(query='changed')]
        for mutation in mutations:
            self.refuse(lambda x:mutation(x['runtime'][2]))
        self.refuse(lambda x:x['runtime'][6]['result'].update(raw=encoded({})))
        self.refuse(lambda x:x['runtime'][6]['result'].update(snapshot={}))
        self.refuse(lambda x:x['runtime'][6]['result'].update(returned_id='other'))

    def test_frozen_inputs(self):
        self.m['fixture_sha256']='other'
        with self.assertRaises(ValueError):self.verify()
        with self.assertRaises(ValueError):checker.verify(self.e,'',self.m)


if __name__=='__main__':unittest.main()
