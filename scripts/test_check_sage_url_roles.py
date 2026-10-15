import base64,copy,io,json,unittest,zipfile
from check_sage_url_roles import verify_url_roles,CASE,IDS,PENDING,PACKAGES,REPO,MODULE,VERSION
from test_check_sage_expansion_source import controls as previous_controls
from test_check_sage_fragment_source import encoded
from sage_url_role_scope import verify_url_pending

def controls():
 raw,report=previous_controls();old=json.loads(raw['cases'][0]['observations'][0]['observed']);e=copy.deepcopy(old);s=e['source'];s['request']['packages']=PACKAGES;prefix=MODULE+'@'+VERSION+'/'
 with zipfile.ZipFile(io.BytesIO(base64.b64decode(s['archive']))) as z:s['files']={n[len(prefix):]:base64.b64encode(z.read(n)).decode() for n in z.namelist() if n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
 e['audit']=json.loads((REPO/'profiles/sageresolution/url_roles_witness.json').read_text());e['handler']=[];e['retrieval']=[];e.pop('runtime',None)
 fs=json.loads((REPO/'profiles/sageresolution/url_roles.json').read_text())
 for f in fs['handlers']:
  doc=f['document'];q=f['request'];opts={'accept':'application/did'};nested=dict(opts)
  if f['parts']['has_query']:nested['relativeRef']='next'
  result={'raw':encoded(f['expected_content']),'content_metadata':{},'has_content':not bool(f['diagnostic_error'])}
  if f['diagnostic_error']:result['metadata']={'error':{'type':f['diagnostic_error']}}
  else:result.update(metadata={'contentType':'application/ld+json'},content_kind=f['expected_kind'])
  v={'request':{'observe_resource_handler':True,'document':{'data':encoded(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','options':encoded(opts),'resolve_inputs':['did:example:resources'],'resolve_options':[encoded(nested)],'driver_inputs':['did:example:resources'],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':encoded(doc)})],'consumption':[{'operation':MODULE+'/consumer.Consumer.Consume','input':encoded(doc),'media_type':'application/did','require':'unknown','expected':'unknown','strict':False,'json_ld':False,'dropped_terms':[],'model':encoded(doc),'entries':encoded({})}],'resolved_data_model':encoded(doc),'data_model':encoded(doc),'entries':encoded({}),'resolved_entries':encoded({}),'resolved_metadata':encoded({'contentType':'application/did'}),'result':result}
  if f['handler_calls']:v['resource_handler']=[{'operation':MODULE+'/dereferencer.ResourceHandler','role':'literal passive resource handler; records actual values and returns unhandled','url':f['parts'],'options':encoded(opts),'model':encoded(doc),'entries':encoded({}),'metadata':encoded({'contentType':'application/did'})}]
  e['handler'].append(v)
 for f in fs['retrieval']:
  q=f['request'];v={'operation':MODULE+'/relyingparty.RelyingParty.VerificationMethod','clock':1800000000,'reference':q['reference'],'purpose':q['purpose'],'parsed_url':f['parts'],'calls':[]}
  if f['expected_method'] is None:v.update(error='diagnostic only',method=None,problem=None)
  else:
   doc={'id':f['record']['did'],'verificationMethod':[f['expected_method']],q['purpose']:[q['reference']]};v.update(method=encoded(f['expected_method']),problem=None);v['calls']=[{'input':f['parts']['primary'],'options':encoded({}),'result':{'has_content':True,'returned_id':f['record']['did'],'content_kind':'document','snapshot':encoded(doc)}}]
  e['retrieval'].append(v)
 obs=[{'statement':i,'verdict':v,'input':json.dumps(s['request']),'observed':json.dumps(e),'detail':'bounded independent URL roles','expected':'literal URL split'} for i,v in zip(IDS,['FAIL','PASS'])];raw['cases'].append({'case':CASE,'statements':IDS,'observations':obs})
 for i,v in zip(IDS,['FAIL','PASS']):next(x for x in report['statements'] if x['id']==i).update(verdict=v,cases=[CASE])
 return raw,report
class URLRoleEvidenceTests(unittest.TestCase):
 def test_complete_and_omission(self):
  r,p=controls();self.assertEqual(verify_url_roles(r,p),set(IDS));r['cases'].pop()
  with self.assertRaises(AssertionError):verify_url_roles(r,p)
 def test_provenance_and_original_handler(self):
  r,p=controls()
  for mutate in [lambda e:e['source'].update(files={}),lambda e:e['source']['request'].update(packages=[]),lambda e:e['source'].update(replaced=0),lambda e:e['audit']['steps'][0].update(correct=0),lambda e:e['audit']['steps'][1].update(correct=False),lambda e:e['audit'].update(frames={}),lambda e:e['audit'].update(call_paths=[]),lambda e:e['handler'].pop(),lambda e:e['handler'][1]['resource_handler'][0]['url'].update(fragment='other'),lambda e:e['handler'][1]['resource_handler'][0]['url'].update(has_fragment=1),lambda e:e['handler'][1]['resource_handler'][0].update(model=encoded({})),lambda e:e['handler'][1]['consumption'][0].update(strict=0),lambda e:e['handler'][1]['request'].update(observe_resource_handler=1),lambda e:e['handler'][0]['result'].update(has_content=0),lambda e:e['handler'][6]['result'].update(raw=encoded({})),lambda e:e.update(handler_errors=['lost'])]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises((AssertionError,KeyError)):verify_url_roles(bad,p)
 def test_same_reference_and_diagnostic_independence(self):
  r,p=controls()
  for mutate in [lambda e:e['retrieval'].pop(),lambda e:e['retrieval'][0]['parsed_url'].update(fragment='wrong'),lambda e:e['retrieval'][0]['parsed_url'].update(has_fragment=1),lambda e:e['retrieval'][0].update(reference='other'),lambda e:e['retrieval'][0]['calls'][0].update(input='other'),lambda e:e['retrieval'][0].update(method=encoded({})),lambda e:e['retrieval'][0]['calls'][0]['result'].update(snapshot=encoded({})),lambda e:e.update(retrieval_errors=['lost'])]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises((AssertionError,KeyError)):verify_url_roles(bad,p)
  e=json.loads(r['cases'][-1]['observations'][0]['observed'])
  for v in e['retrieval'][2:]:v.update(error='',method=encoded({'different':'downstream'}),calls=[])
  for o in r['cases'][-1]['observations']:o['observed']=json.dumps(e)
  self.assertEqual(verify_url_roles(r,p),set(IDS))
 def test_findings_scope_and_legacy_guards(self):
  r,p=controls()
  for ident in IDS+PENDING:
   bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==ident)['verdict']='FAIL' if ident==IDS[1] else 'PASS'
   with self.assertRaises(AssertionError):verify_url_roles(r,bad)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==IDS[0])['cases']=['other']
  with self.assertRaises(AssertionError):verify_url_roles(r,bad)
  bad=copy.deepcopy(r);bad['cases'].append(copy.deepcopy(bad['cases'][-1]))
  with self.assertRaises(AssertionError):verify_url_roles(bad,p)
  before,pending=previous_controls();live={x['id']:x for x in pending['statements']};verify_url_pending(before,live,IDS)
  live[IDS[0]]['verdict']='FAIL'
  with self.assertRaises(AssertionError):verify_url_pending(before,live,IDS)
if __name__=='__main__':unittest.main()
