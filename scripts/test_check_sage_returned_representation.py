import base64,copy,json,os,unittest
from pathlib import Path
import check_sage_returned_representation as checker
from sage_returned_representation_scope import REPRESENTATION_CASE,REPRESENTATION_ID,verify_representation_pending
@unittest.skipUnless(os.environ.get('SAGE_BATCH_REPORT_DIR'),'actual CI reports required')
class ReturnedRepresentationTests(unittest.TestCase):
 def setUp(self):
  root=Path(os.environ['SAGE_BATCH_REPORT_DIR']);self.raw=json.loads((root/'resolution-did-1.1-raw.json').read_text());self.report=json.loads((root/'resolution-did-1.1.json').read_text())
 def test_actual_complete_minimal_class(self):self.assertEqual(checker.verify_returned_representation(self.raw,self.report),{REPRESENTATION_ID})
 def mutate(self,change):
  raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case']==REPRESENTATION_CASE);e=json.loads(c['observations'][0]['observed']);change(e);c['observations'][0]['observed']=json.dumps(e)
  with self.assertRaises((AssertionError,ValueError,KeyError,TypeError)):checker.verify_returned_representation(raw,self.report)
 def test_versions_and_same_call_binding(self):
  for change in [lambda e:e['runtime'][0]['consumption'][0].update(version='1.0'),lambda e:e['runtime'][0]['production'][0].update(version='1.1'),lambda e:e['runtime'][0]['production'][0].update(output='e30='),lambda e:e['runtime'][0].update(production=[]),lambda e:e['runtime'][0]['request'].update(observe_production=False),lambda e:e.update(runtime=e['runtime'][:1])]:self.mutate(change)
 def test_complete_output_not_just_serializer_success(self):
  for payload in [b'[]',b'{}',b'{"id":3}',b'{"id":"did:example:123","extra":true}',b'{"id":"did:example:123","id":"did:example:123"}',b'{"id":"did:example:123"} null']:
   value=base64.b64encode(payload).decode()
   def change(e):e['runtime'][0]['production'][0]['output']=value;e['runtime'][0]['result']['raw']=value
   self.mutate(change)
 def test_source_identity_and_byte_receipt(self):
  for change in [lambda e:e['source'].update(replaced=True),lambda e:e['source'].update(compiler='different'),lambda e:e['source']['files'].update({'resolver/resolver.go':'e30='})]:self.mutate(change)
 def test_missing_new_case_preserves_pending_guard(self):
  raw=copy.deepcopy(self.raw);raw['cases']=[c for c in raw['cases'] if c['case']!=REPRESENTATION_CASE];live={x['id']:copy.deepcopy(x) for x in self.report['statements']}
  with self.assertRaises(AssertionError):verify_representation_pending(raw,live)
  live[REPRESENTATION_ID]['verdict']='NOT_RUN';verify_representation_pending(raw,live)

 def test_boolean_driver_option_does_not_accept_numeric_zero(self):
  def change(e):
   v=e['runtime'][0];options=json.loads(base64.b64decode(v['driver_options'][0]));options['NoCache']=0;v['driver_options'][0]=base64.b64encode(json.dumps(options).encode()).decode()
  self.mutate(change)
