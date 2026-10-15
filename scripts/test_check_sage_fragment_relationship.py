import base64,copy,json,unittest
from check_sage_fragment_relationship import verify_relationship,CASE,IDS,REPO,MODULE
from test_check_sage_fragment_source import controls as source_controls,encoded

def controls():
 raw,report=source_controls();source=json.loads(raw['cases'][0]['observations'][0]['observed']);values=[]
 for f in json.loads((REPO/'profiles/sageresolution/fragment_relationship.json').read_text()):
  opts={'accept':'application/did'};q=f['request'];doc=f['document']
  if q.get('relationship'):opts['verificationRelationship']=q['relationship']
  result={'has_content':not bool(f['diagnostic_error']),'content_metadata':{},'raw':encoded(f['expected_content'])}
  if f['diagnostic_error']:result['metadata']={'error':{'type':'https://w3id.org/security#'+f['diagnostic_error']}}
  else:result.update(metadata={'contentType':'application/ld+json'},content_kind=f['expected_kind'],returned_id=f['expected_content']['id'])
  values.append({'request':{'document':{'data':encoded(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','options':encoded(opts),'resolve_inputs':['did:example:resources'],'resolve_options':[encoded(opts)],'driver_inputs':['did:example:resources'],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':encoded(doc)})],'data_model':encoded(doc),'entries':encoded({}),'result':result})
 e={'source_evidence':source,'audit':json.loads((REPO/'profiles/sageresolution/fragment_relationship_witness.json').read_text()),'runtime':values};obs=[{'statement':i,'verdict':'PASS','input':json.dumps(source['source']['request']),'observed':json.dumps(e),'detail':'bounded source role','expected':'typed option'} for i in IDS];raw['cases'].append({'case':CASE,'statements':IDS,'observations':obs})
 for i in IDS:report['statements'].append({'id':i,'verdict':'PASS','cases':[CASE]})
 for i in ['cid10#retrieve-verification-method.3','res10-crd20261001#dereferencing-algorithm-fragment.3','res10-crd20261001#dereferencing-algorithm-resource.11']:report['statements'].append({'id':i,'verdict':'NOT_RUN','cases':[]})
 return raw,report
class RelationshipEvidenceTests(unittest.TestCase):
 def test_complete_and_case_omission(self):
  r,p=controls();self.assertEqual(verify_relationship(r,p),set(IDS));r['cases'].pop()
  with self.assertRaises((AssertionError,StopIteration)):verify_relationship(r,p)
 def test_typed_role_and_runtime_capture(self):
  r,p=controls()
  for mutate in [lambda e:e['audit'].update(frame='other'),lambda e:e['audit']['steps'][0].update(correct=1),lambda e:e['audit'].update(roles={}),lambda e:e['runtime'].pop(),lambda e:e['runtime'][0]['request']['request'].update(relationship='assertionMethod'),lambda e:e['runtime'][0].update(data_model=encoded({})),lambda e:e['runtime'][0]['result'].update(has_content=1),lambda e:e['runtime'][2]['result'].update(raw=encoded({})),lambda e:e['source_evidence'].update(type_checker_compiler='other')]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises(AssertionError):verify_relationship(bad,p)
 def test_boolean_and_pending_scope(self):
  r,p=controls();bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);v=e['runtime'][0];options=json.loads(base64.b64decode(v['driver_options'][0]));options['NoCache']=0;v['driver_options'][0]=encoded(options)
  for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
  with self.assertRaises(AssertionError):verify_relationship(bad,p)
  bad=copy.deepcopy(p);bad['statements'][-1]['verdict']='PASS'
  with self.assertRaises(AssertionError):verify_relationship(r,bad)
if __name__=='__main__':unittest.main()
