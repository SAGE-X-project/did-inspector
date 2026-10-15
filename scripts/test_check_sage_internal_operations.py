import copy,json,unittest
from check_sage_internal_operations import verify_internal_operations,ITEM_CASE,ITEM_ID,HASH_CASE,HASH_IDS,ROLE,OBSERVER,REPO,MODULE
from check_sage_expansion_source import CASE as EXPANSION_CASE,node
from test_check_sage_url_roles import controls as previous_controls
from test_check_sage_fragment_source import encoded
from sage_item_expansion_scope import verify_item_pending

def controls():
 raw,report=previous_controls();old=next(c for c in raw['cases'] if c['case']==EXPANSION_CASE);proof=json.loads(old['observations'][0]['observed']);items=[]
 for f in json.loads((REPO/'profiles/sageresolution/expansion_source.json').read_text()):
  for path in f['extension_paths']:items.append({'path':path,'original':node(f['document'],path),'expected':node(f['expected'],path),'observed':node(f['document'],path),'qualifies':True})
 e={'proof':proof,'items':items};raw['cases'].append({'case':ITEM_CASE,'statements':[ITEM_ID],'observations':[{'statement':ITEM_ID,'verdict':'FAIL','input':json.dumps(proof['source']['request']),'observed':json.dumps(e),'detail':'independent object/id condition','expected':'process each qualifying id'}]})
 e={'source':copy.deepcopy(proof['source']),'calls':{},'call_errors':{}};e['source']['request']['packages']=['internal/multiformats'];e['source']['files']={n:b for n,b in e['source']['files'].items() if n.rsplit('/',1)[0]=='internal/multiformats'}
 for f in json.loads((REPO/'profiles/sageresolution/multihash.json').read_text()):
  q=f['request'];v={'request':q,'observer':OBSERVER,'role':ROLE,'operation':MODULE+'/internal/multiformats.'+('EncodeMultihash' if q['operation']=='encode' else 'DecodeMultihash'),'encoded':f.get('expected_encoded'),'code':f.get('expected_code',0),'digest':f.get('expected_digest')}
  if f.get('reject') or f.get('diagnostic'):v['error']='literal rejection'
  e['calls'][f['name']]=v
 raw['cases'].append({'case':HASH_CASE,'statements':HASH_IDS,'observations':[{'statement':i,'verdict':'PASS','input':json.dumps(e['source']['request']),'observed':json.dumps(e),'detail':'component probe','expected':'literal header and lengths'} for i in HASH_IDS]})
 for ident,verdict,case in [(ITEM_ID,'FAIL',ITEM_CASE),*[(i,'PASS',HASH_CASE) for i in HASH_IDS]]:
  row=next((x for x in report['statements'] if x['id']==ident),None)
  if row is None:row={'id':ident};report['statements'].append(row)
  row.update(verdict=verdict,cases=[case])
 return raw,report

def changed(raw,case,mutate):
 out=copy.deepcopy(raw);c=next(c for c in out['cases'] if c['case']==case);e=json.loads(c['observations'][0]['observed']);mutate(e)
 for o in c['observations']:o['observed']=json.dumps(e)
 return out
class InternalOperationsEvidenceTests(unittest.TestCase):
 def test_complete_and_omission(self):
  r,p=controls();self.assertEqual(verify_internal_operations(r,p),{ITEM_ID,*HASH_IDS})
  for case in [ITEM_CASE,HASH_CASE]:
   bad=copy.deepcopy(r);bad['cases']=[c for c in bad['cases'] if c['case']!=case]
   with self.assertRaises(AssertionError):verify_internal_operations(bad,p)
 def test_item_conditions_and_same_proof(self):
  r,p=controls()
  for mutate in [lambda e:e.update(items=[]),lambda e:e['items'][0].update(qualifies=1),lambda e:e['items'][0].update(original='absolute'),lambda e:e['items'][0].update(expected='other'),lambda e:e['items'][0].update(observed=e['items'][0]['expected']),lambda e:e['items'][0].update(path=['other']),lambda e:e['proof']['audit'].update(frames={}),lambda e:e.update(analysis_error='lost')]:
   with self.assertRaises((AssertionError,KeyError)):verify_internal_operations(changed(r,ITEM_CASE,mutate),p)
 def test_component_identity_and_source(self):
  r,p=controls()
  for mutate in [lambda e:e['source'].update(files={}),lambda e:e['source'].update(replaced=0),lambda e:e['source'].update(compiler='other'),lambda e:e['source']['request'].update(packages=[]),lambda e:e['calls']['encode-sha2-256']['observer'].update(replacement='other'),lambda e:e['calls']['encode-sha2-256'].update(role='production'),lambda e:e['calls']['decode-sha2-256']['request'].update(code=False),lambda e:e['calls'].pop('decode-sha2-256'),lambda e:e['call_errors'].update(lost='call')]:
   with self.assertRaises((AssertionError,KeyError)):verify_internal_operations(changed(r,HASH_CASE,mutate),p)
 def test_byte_order_and_independent_length_guards(self):
  r,p=controls()
  for mutate in [lambda e:e['calls']['encode-sha2-256'].update(encoded=encoded([32,18])),lambda e:e['calls']['decode-sha2-256'].update(code=0),lambda e:e['calls']['decode-sha2-256'].update(digest=encoded([])),lambda e:e['calls']['decode-sha2-256-declared-actual-short'].update(error=''),lambda e:e['calls']['decode-sha2-384-declared-actual-long'].update(error='')]:
   with self.assertRaises((AssertionError,KeyError)):verify_internal_operations(changed(r,HASH_CASE,mutate),p)
 def test_diagnostic_outcomes_and_partial_rejection_are_not_oracles(self):
  r,p=controls()
  def mutate(e):
   for name,v in e['calls'].items():
    if name.startswith('diagnostic-'):v.update(error='',encoded='YQ==',code=999,digest='Yg==')
    elif v.get('error'):v.update(encoded='YQ==',code=999,digest='Yg==')
  self.assertEqual(verify_internal_operations(changed(r,HASH_CASE,mutate),p),{ITEM_ID,*HASH_IDS})
 def test_findings_scope_and_legacy_guard(self):
  r,p=controls()
  for ident in [ITEM_ID,*HASH_IDS,'res10-crd20261001#resolving-algorithm.26','res10-crd20261001#dereferencing-algorithm-fragment.3']:
   bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==ident)['verdict']='PASS' if ident==ITEM_ID else 'FAIL'
   with self.assertRaises(AssertionError):verify_internal_operations(r,bad)
  old,pending=previous_controls();live={x['id']:x for x in pending['statements']};verify_item_pending(old,live,[ITEM_ID]);live[ITEM_ID]['verdict']='FAIL'
  with self.assertRaises(AssertionError):verify_item_pending(old,live,[ITEM_ID])
  bad=copy.deepcopy(r);bad['cases'].append(copy.deepcopy(next(c for c in bad['cases'] if c['case']==ITEM_CASE)))
  with self.assertRaises(AssertionError):verify_internal_operations(bad,p)
if __name__=='__main__':unittest.main()
