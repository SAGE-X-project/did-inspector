import copy
import json
import os
from pathlib import Path
import unittest
import check_sage_resources as checker

class ResourceLiteralTests(unittest.TestCase):
    def test_public_fixture_classes(self):
        fs=checker.fixtures();self.assertEqual(len(fs),9)
        self.assertEqual({f['expected_kind'] for f in fs.values()},{'document','verification-method','service','map','uri-list'})
        self.assertEqual(fs['parameter-relative-reference']['expected_content'],['https://agent.example/send'])

@unittest.skipUnless(os.environ.get('SAGE_BATCH_REPORT_DIR'),'actual adapter report evidence')
class ActualResourceEvidenceTests(unittest.TestCase):
    def setUp(self):
        r=Path(os.environ['SAGE_BATCH_REPORT_DIR']);self.raw=json.loads((r/'resolution-did-1.1-raw.json').read_text());self.report=json.loads((r/'resolution-did-1.1.json').read_text())
    def test_all_actual_evidence(self):self.assertEqual(len(checker.verify_resources(self.raw,self.report)),2)
    def mutate(self,name,change,reject=True):
        raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case'].endswith('/resource-choice-'+name));v=json.loads(c['observations'][0]['observed']);change(v);c['observations'][0]['observed']=json.dumps(v)
        if reject:
            with self.assertRaises((AssertionError,KeyError,TypeError,ValueError)):checker.verify_resources(raw,self.report)
        else:self.assertEqual(len(checker.verify_resources(raw,self.report)),2)
    def test_wrong_kind_input_media_resource_or_driver(self):
        for name,change in [('document',lambda v:v[0]['result'].update(raw='e30=')),('parameter-service',lambda v:v[0]['result'].update(raw=None)),('service',lambda v:v[0]['result'].update(content_kind='document')),('nested-full',lambda v:v[0]['result'].update(raw='e30=')),('method',lambda v:v[0]['result']['metadata'].update(contentType='text/plain')),('parameter-service',lambda v:v[0]['request']['request'].update(input='did:example:other')),('parameter-service-type',lambda v:v[0].update(driver_inputs=['did:example:other'])),('parameter-relative-reference',lambda v:v[0].update(driver_results=[])),('nested-relative',lambda v:v[0].update(resolve_inputs=[]))]:
            with self.subTest(name=name):self.mutate(name,change)
    def test_diagnostic_control_and_forwarding_are_separate(self):
        self.mutate('service',lambda v:v[1].update(result={}),False)
        self.mutate('parameter-service',lambda v:v[0].update(resolve_options=['e30=']),False)
    def test_case_omission_duplicate_or_statement_reassignment(self):
        for action in ['missing','duplicate','wrong-statement']:
            raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case'].endswith('/resource-choice-service'))
            if action=='missing':raw['cases'].remove(c)
            elif action=='duplicate':raw['cases'].append(copy.deepcopy(c))
            else:c['observations'][0]['statement']=checker.PARAMETERS
            with self.assertRaises(AssertionError):checker.verify_resources(raw,self.report)
