import copy,json,unittest
from check_sage_service_source import verify_service,CASE,IDS,PENDING,REPO,MODULE
from test_check_sage_fragment_source import controls as source_controls,encoded

def controls():
 raw,report=source_controls();source=json.loads(raw['cases'][0]['observations'][0]['observed']);values=[]
 for f in json.loads((REPO/'profiles/sageresolution/service_source.json').read_text()):
  q=f['request'];doc=f['document'];opts={'accept':q['accept']};nested=dict(f['parameters'])
  if q['accept']=='application/did':nested['accept']='application/did'
  media='application/did' if f['expected_kind']=='document' else 'text/uri-list'
  result={'has_content':not bool(f['diagnostic_error']),'content_metadata':{} if media=='application/did' or f['diagnostic_error'] else {'contentType':media},'raw':encoded(f['expected_content'])}
  if f['diagnostic_error']:result['metadata']={'error':{'type':'https://www.w3.org/ns/did#'+f['diagnostic_error']}}
  else:result.update(metadata={'contentType':media},content_kind=f['expected_kind'],returned_id='did:example:resources' if media=='application/did' else '')
  values.append({'request':{'document':{'data':encoded(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','options':encoded(opts),'resolve_inputs':['did:example:resources'],'resolve_options':[encoded(nested)],'driver_inputs':['did:example:resources'],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did' if q['accept']=='application/did' else '', 'NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':encoded(doc)})],'data_model':encoded(doc),'entries':encoded({}),'result':result})
 e={'source_evidence':source,'audit':json.loads((REPO/'profiles/sageresolution/service_source_witness.json').read_text()),'runtime':values};obs=[{'statement':i,'verdict':'PASS','input':json.dumps(source['source']['request']),'observed':json.dumps(e),'detail':'bounded source role','expected':'typed service operand'} for i in IDS];raw['cases'].append({'case':CASE,'statements':IDS,'observations':obs})
 for i in IDS:report['statements'].append({'id':i,'verdict':'PASS','cases':[CASE]})
 for i in PENDING:report['statements'].append({'id':i,'verdict':'NOT_RUN','cases':[]})
 report['statements'].append({'id':'res10-crd20261001#dereferencing-algorithm-resource.28','verdict':'PASS','cases':['did-1.1/sage-resolution/remaining-routing-relative-endpoint']})
 return raw,report
class ServiceEvidenceTests(unittest.TestCase):
 def test_complete_and_omission(self):
  r,p=controls();self.assertEqual(verify_service(r,p),set(IDS));r['cases'].pop()
  with self.assertRaises((AssertionError,StopIteration)):verify_service(r,p)
 def test_role_and_capture(self):
  r,p=controls()
  for mutate in [lambda e:e['audit'].update(frames={}),lambda e:e['audit']['steps'][0].update(correct=1),lambda e:e['audit'].update(roles={}),lambda e:e['audit'].update(call_paths=[]),lambda e:e['runtime'].pop(),lambda e:e['runtime'][0]['request']['request'].update(input='other'),lambda e:e['runtime'][0].update(data_model=encoded({})),lambda e:e['runtime'][0]['result'].update(has_content=1),lambda e:e['runtime'][2]['result'].update(raw=encoded(['https://agent.example/send'])),lambda e:e['source_evidence'].update(type_checker_compiler='other'),lambda e:e['runtime'][4].update(resolve_options=[encoded({'service':'one'})])]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises(AssertionError):verify_service(bad,p)
 def test_boolean_and_scope(self):
  r,p=controls();bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);v=e['runtime'][0];opts=json.loads(__import__('base64').b64decode(v['driver_options'][0]));opts['NoCache']=0;v['driver_options'][0]=encoded(opts)
  for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
  with self.assertRaises(AssertionError):verify_service(bad,p)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==PENDING[-1])['verdict']='PASS'
  with self.assertRaises(AssertionError):verify_service(r,bad)
  bad=copy.deepcopy(p);bad['statements'][-1]['cases']=[CASE]
  with self.assertRaises(AssertionError):verify_service(r,bad)
if __name__=='__main__':unittest.main()
