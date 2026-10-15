import base64,copy,json,os,unittest
from pathlib import Path
import check_sage_internal_boundaries as check
from sage_internal_boundary_scope import CASES,CAPACITY_IDS,CONTEXT_ID,MEDIA_ID
@unittest.skipUnless(os.environ.get('SAGE_BATCH_REPORT_DIR'),'actual reports required')
class InternalBoundaryTests(unittest.TestCase):
 def setUp(self):
  root=Path(os.environ['SAGE_BATCH_REPORT_DIR']);self.raw=json.loads((root/'resolution-did-1.1-raw.json').read_text());self.report=json.loads((root/'resolution-did-1.1.json').read_text())
 def test_all_actual_grouped_boundaries(self):self.assertEqual(check.verify_internal_boundaries(self.raw,self.report),set(CASES))
 def mutate(self,ident,change):
  raw=copy.deepcopy(self.raw);c=next(c for c in raw['cases'] if c['case']==CASES[ident]);e=json.loads(c['observations'][0]['observed']);change(e)
  for o in c['observations']:o['observed']=json.dumps(e)
  with self.assertRaises((AssertionError,ValueError,KeyError,TypeError)):check.verify_internal_boundaries(raw,self.report)
 def test_capacity_not_rfc4648_or_roundtrip_only(self):
  self.assertEqual(check.component_encoding(bytes([255])),'uD_')
  self.assertNotEqual(check.component_encoding(bytes([255])),'u'+base64.urlsafe_b64encode(bytes([255])).decode().rstrip('='))
  for change in [lambda e:e['calls'][0].update(operation='RFC4648 helper'),lambda e:e['calls'][1].update(header=122),lambda e:e['audit']['steps'][0].update(correct=False),lambda e:e['source'].update(replaced=True)]:self.mutate(CAPACITY_IDS[0],change)
 def test_injection_must_be_same_actual_no_context_call(self):
  for change in [lambda e:e['calls'][0].update(entries=base64.b64encode(b'{"@context":"other"}').decode()),lambda e:e['calls'][0].update(output=base64.b64encode(b'{"@context":false}').decode()),lambda e:e['calls'][0].update(version='1.0')]:self.mutate(CONTEXT_ID,change)
 def test_fragment_actual_input_media_and_candidate(self):
  for change in [lambda e:e['runtime'][0]['request']['document'].update(media_type='application/did'),lambda e:e['runtime'][0]['consumption'][0].update(version='1.1'),lambda e:e['runtime'][0]['result'].update(raw='e30='),lambda e:e['audit']['steps'][1].update(correct=False)]:self.mutate(MEDIA_ID,change)
 def test_pending_is_not_blanket_na_or_pass(self):
  for ident in ['cid10#base-encode.13','cid10#base-decode.16','cid10#json-ld-context.1','cid10#vocabulary.1','did11-cr20260305#json-ld-processors.1']:
   report=copy.deepcopy(self.report);next(x for x in report['statements'] if x['id']==ident)['verdict']='NOT_APPLICABLE'
   with self.assertRaises(AssertionError):check.verify_manifest(self.raw,report)
 def test_missing_new_case_cannot_advance_old_guard(self):
  for ident,case in CASES.items():
   raw=copy.deepcopy(self.raw);raw['cases']=[c for c in raw['cases'] if c['case']!=case];live={x['id']:x for x in self.report['statements']}
   with self.assertRaises(AssertionError):check.verify_internal_pending(raw,live,ident)

 def test_observer_identity_never_normalizes_falsy_non_strings(self):
  for value in [0,False,None,[],{}]:
   self.mutate(CAPACITY_IDS[0],lambda e:e['calls'][0]['observer'].update(replacement_version=value))
  self.mutate(CAPACITY_IDS[0],lambda e:e['calls'][0]['observer'].pop('replacement_version'))
