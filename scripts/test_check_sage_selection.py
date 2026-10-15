import copy,json,unittest
from check_sage_selection import verify_selection,CASE,IDS,PENDING,REPO,MODULE,MEDIA
from test_check_sage_service_source import controls as previous_controls
from test_check_sage_fragment_source import encoded

def controls():
 raw,report=previous_controls();source=json.loads(raw['cases'][0]['observations'][0]['observed']);values=[]
 for f in json.loads((REPO/'profiles/sageresolution/selection.json').read_text()):
  q=f['request'];doc=f['document'];accept=q.get('accept','');opts={'accept':accept} if accept else {};nested=dict(f['parameters'])
  if accept in MEDIA:nested['accept']=accept
  media=accept or 'application/did'
  result={'has_content':not bool(f['diagnostic_error']),'content_metadata':{} if f['expected_kind']=='document' or f['diagnostic_error'] else {'contentType':'text/uri-list'},'raw':encoded(f['expected_content'])}
  if f['diagnostic_error']:result['metadata']={'error':{'type':'https://www.w3.org/ns/did#'+f['diagnostic_error']}}
  else:result.update(metadata={'contentType':media},content_kind=f['expected_kind'],returned_id='did:example:resources' if f['expected_kind']=='document' else '')
  final=f['expected_content'] if f['expected_kind']=='document' and not f['diagnostic_error'] else doc
  values.append({'request':{'document':{'data':encoded(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','options':encoded(opts),'resolve_inputs':['did:example:resources'],'resolve_options':[encoded(nested)],'driver_inputs':['did:example:resources'],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did' if accept=='application/did' else '', 'NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':encoded(doc)})],'data_model':encoded(final),'entries':encoded({}),'resolved_data_model':encoded(doc),'resolved_entries':encoded({}),'resolved_metadata':encoded({'contentType':accept if accept in MEDIA else 'application/did'}),'result':result})
 e={'source_evidence':source,'audit':json.loads((REPO/'profiles/sageresolution/selection_witness.json').read_text()),'runtime':values};obs=[{'statement':i,'verdict':'PASS','input':json.dumps(source['source']['request']),'observed':json.dumps(e),'detail':'bounded source role','expected':'typed selection operand'} for i in IDS];raw['cases'].append({'case':CASE,'statements':IDS,'observations':obs})
 for i in IDS:report['statements'].append({'id':i,'verdict':'PASS','cases':[CASE]})
 return raw,report
class SelectionEvidenceTests(unittest.TestCase):
 def test_complete_and_omission(self):
  r,p=controls();self.assertEqual(verify_selection(r,p),set(IDS));r['cases'].pop()
  with self.assertRaises((AssertionError,StopIteration)):verify_selection(r,p)
 def test_roles_and_separate_originals(self):
  r,p=controls()
  for mutate in [lambda e:e['audit'].update(frames={}),lambda e:e['audit']['steps'][0].update(correct=1),lambda e:e['audit'].update(roles={}),lambda e:e['audit'].update(call_paths=[]),lambda e:e['runtime'].pop(),lambda e:e['runtime'][0]['request']['request'].update(input='other'),lambda e:e['runtime'][0].update(data_model=encoded({})),lambda e:e['runtime'][0].update(resolved_data_model=e['runtime'][0]['data_model']),lambda e:e['runtime'][0].update(resolved_entries=encoded({'extra':True})),lambda e:e['runtime'][0].update(resolved_metadata=encoded({'contentType':'text/plain'})),lambda e:e['runtime'][0]['result'].update(has_content=1),lambda e:e['runtime'][6]['result'].update(raw=encoded(['https://one.example/next'])),lambda e:e['source_evidence'].update(type_checker_compiler='other'),lambda e:e['runtime'][8].update(options=encoded({'accept':''}))]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises(AssertionError):verify_selection(bad,p)
 def test_boolean_and_scope(self):
  r,p=controls();bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);v=e['runtime'][0];opts=json.loads(__import__('base64').b64decode(v['driver_options'][0]));opts['NoCache']=0;v['driver_options'][0]=encoded(opts)
  for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
  with self.assertRaises(AssertionError):verify_selection(bad,p)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==PENDING[-1])['verdict']='PASS'
  with self.assertRaises(AssertionError):verify_selection(r,bad)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']=='res10-crd20261001#dereferencing-algorithm-resource.28')['cases']=[CASE]
  with self.assertRaises(AssertionError):verify_selection(r,bad)
if __name__=='__main__':unittest.main()
