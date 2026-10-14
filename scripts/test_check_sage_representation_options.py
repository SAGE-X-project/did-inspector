import copy
import json
import os
from pathlib import Path
import unittest
import check_sage_representation_options as checker

@unittest.skipUnless(os.environ.get('SAGE_BATCH_REPORT_DIR'),'actual adapter report evidence')
class ActualOptionEvidenceTests(unittest.TestCase):
    def setUp(self):
        r=Path(os.environ['SAGE_BATCH_REPORT_DIR']);self.raw=json.loads((r/'resolution-did-1.1-raw.json').read_text());self.report=json.loads((r/'resolution-did-1.1.json').read_text())
    def test_all_actual_evidence(self):self.assertEqual(len(checker.verify_options(self.raw,self.report)),3)
    def mutate(self,name,change,reject=True):
        raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case'].endswith('/representation-options-'+name));v=json.loads(c['observations'][0]['observed']);change(v);c['observations'][0]['observed']=json.dumps(v)
        if reject:
            with self.assertRaises((AssertionError,KeyError,TypeError,ValueError)):checker.verify_options(raw,self.report)
        else:self.assertEqual(len(checker.verify_options(raw,self.report)),3)
    def test_option_capture_or_output_substitution(self):
        for name,change in [('producer-true',lambda v:v['calls'][0].update(json_ld=False)),('producer-false',lambda v:v['calls'][0].update(output='e30=')),('consumer-true',lambda v:v.update(strict=False)),('consumer-false',lambda v:v.update(require='unknown')),('consumer-true',lambda v:v.update(input='e30=')),('resolver-proof',lambda v:v[0]['result']['metadata'].update(proof=[])),('resolver-proof',lambda v:v[0]['consumer'][0].update(input='e30=')),('resolver-proof',lambda v:v[0]['wire'][0].update(method='POST'))]:
            with self.subTest(name=name):self.mutate(name,change)
    def test_unrelated_diagnostics_and_absent_control(self):
        self.mutate('resolver-proof',lambda v:v[0]['result'].update(content_metadata={'deactivated':False}),False)
        self.mutate('resolver-proof',lambda v:v[1]['result']['metadata'].update(proof=[{'type':'ResolverAddedDiagnostic'}]),False)
    def test_missing_duplicate_or_misbound_case(self):
        for action in ['missing','duplicate','rename']:
            raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case'].endswith('/representation-options-producer-false'))
            if action=='missing':raw['cases'].remove(c)
            elif action=='duplicate':raw['cases'].append(copy.deepcopy(c))
            else:c['case']=c['case'].replace('producer-false','producer-true')
            with self.assertRaises(AssertionError):checker.verify_options(raw,self.report)
