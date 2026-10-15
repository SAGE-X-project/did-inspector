import copy,json,unittest
from check_sage_dispatch import verify_dispatch,CASE,IDS,PENDING,REPO,MODULE
from test_check_sage_selection import controls as previous_controls
from test_check_sage_fragment_source import encoded

def controls():
 raw,report=previous_controls();source=json.loads(raw['cases'][0]['observations'][0]['observed']);values=[]
 for f in json.loads((REPO/'profiles/sageresolution/dispatch.json').read_text()):
  q=f['request'];doc=f['document'];accept=q.get('accept','');rel=q.get('relationship','');opts={'accept':accept} if accept else {};nested=dict(f['parameters'])
  if accept=='application/did':nested['accept']=accept
  if rel:opts['verificationRelationship']=rel;nested['verificationRelationship']=rel
  kind=f['expected_kind'];error=f['diagnostic_error'];content=f['expected_content'];result={'has_content':not bool(error),'content_metadata':{'contentType':'text/uri-list'} if kind=='uri-list' and not error else {},'raw':encoded(content)}
  if error:result['metadata']={'error':{'type':error}}
  else:result.update(metadata={'contentType':f['expected_media']},content_kind=kind,returned_id='did:example:resources' if kind=='document' else content['id'] if kind=='verification-method' else '')
  final=content if kind=='document' and not error else doc
  values.append({'request':{'document':{'data':encoded(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','options':encoded(opts),'resolve_inputs':['did:example:resources'],'resolve_options':[encoded(nested)],'driver_inputs':['did:example:resources'],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did' if accept=='application/did' else '', 'NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':encoded(doc)})],'data_model':encoded(final),'entries':encoded({}),'resolved_data_model':encoded(doc),'resolved_entries':encoded({}),'resolved_metadata':encoded({'contentType':'application/did'}),'result':result})
 e={'source_evidence':source,'audit':json.loads((REPO/'profiles/sageresolution/dispatch_witness.json').read_text()),'runtime':values};obs=[{'statement':i,'verdict':'PASS','input':json.dumps(source['source']['request']),'observed':json.dumps(e),'detail':'bounded source role','expected':'typed dispatch operand'} for i in IDS];raw['cases'].append({'case':CASE,'statements':IDS,'observations':obs})
 for i in IDS:report['statements'].append({'id':i,'verdict':'PASS','cases':[CASE]})
 return raw,report
class DispatchEvidenceTests(unittest.TestCase):
 def test_complete_and_omission(self):
  r,p=controls();self.assertEqual(verify_dispatch(r,p),set(IDS));r['cases'].pop()
  with self.assertRaises((AssertionError,StopIteration)):verify_dispatch(r,p)
 def test_roles_originals_and_conditions(self):
  r,p=controls()
  for mutate in [lambda e:e['audit'].update(frames={}),lambda e:e['audit']['steps'][0].update(correct=1),lambda e:e['audit'].update(roles={}),lambda e:e['audit'].update(call_paths=[]),lambda e:e['runtime'].pop(),lambda e:e['runtime'][0]['request']['request'].update(input='other'),lambda e:e['runtime'][0].update(resolved_data_model=encoded({})),lambda e:e['runtime'][12].update(resolved_data_model=e['runtime'][12]['data_model']),lambda e:e['runtime'][0].update(resolved_entries=encoded({'extra':True})),lambda e:e['runtime'][0].update(resolved_metadata=encoded({'contentType':'text/plain'})),lambda e:e['runtime'][0]['result'].update(has_content=1),lambda e:e['runtime'][2]['result'].update(has_content=True),lambda e:e['runtime'][10]['result'].update(raw=encoded(['https://one.example/base/'])),lambda e:e['runtime'][11].update(options=encoded({'accept':'text/uri-list'})),lambda e:e['runtime'][1]['result'].update(returned_id='other'),lambda e:e['source_evidence'].update(type_checker_compiler='other')]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises(AssertionError):verify_dispatch(bad,p)
 def test_boolean_and_scope(self):
  r,p=controls();bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);v=e['runtime'][0];opts=json.loads(__import__('base64').b64decode(v['driver_options'][0]));opts['NoCache']=0;v['driver_options'][0]=encoded(opts)
  for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
  with self.assertRaises(AssertionError):verify_dispatch(bad,p)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==PENDING[0])['verdict']='PASS'
  with self.assertRaises(AssertionError):verify_dispatch(r,bad)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==IDS[0])['cases']=['other']
  with self.assertRaises(AssertionError):verify_dispatch(r,bad)
if __name__=='__main__':unittest.main()
