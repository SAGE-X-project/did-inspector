import base64,copy,io,json,unittest,zipfile
from check_sage_expansion_source import verify_expansion_source,CASE,IDS,PENDING,PACKAGES,REPO,MODULE,VERSION,node
from test_check_sage_dispatch import controls as previous_controls
from test_check_sage_fragment_source import encoded

def controls():
 raw,report=previous_controls();old=json.loads(raw['cases'][0]['observations'][0]['observed']);e=copy.deepcopy(old);s=e['source'];s['request']['packages']=PACKAGES
 prefix=MODULE+'@'+VERSION+'/'
 with zipfile.ZipFile(io.BytesIO(base64.b64decode(s['archive']))) as z:s['files']={n[len(prefix):]:base64.b64encode(z.read(n)).decode() for n in z.namelist() if n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
 e['audit']=json.loads((REPO/'profiles/sageresolution/expansion_source_witness.json').read_text());e['runtime']=[]
 for f in json.loads((REPO/'profiles/sageresolution/expansion_source.json').read_text()):
  doc=f['document'];q=f['request'];enabled=q.get('options',{}).get('expandRelativeUrls') is True;opts={'accept':'application/did'}
  if enabled:opts['expandRelativeUrls']=True
  model=copy.deepcopy(f['expected'])
  for path in f['extension_paths']:
   parent=node(model,path[:-1]);parent[int(path[-1]) if isinstance(parent,list) else path[-1]]=node(doc,path)
  wire=copy.deepcopy(model)
  if enabled:wire['@context']='https://www.w3.org/ns/did/v1.1'
  e['runtime'].append({'request':{'document':{'data':encoded(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/resolver.DefaultResolver.Resolve','options':encoded(opts),'resolve_inputs':['did:example:123'],'resolve_options':[encoded(opts)],'driver_inputs':['did:example:123'],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':encoded(doc)})],'consumption':[{'operation':MODULE+'/consumer.Consumer.Consume','input':encoded(doc),'media_type':'application/did','require':'unknown','expected':'unknown','strict':False,'json_ld':False,'dropped_terms':[],'model':encoded(doc),'entries':encoded({})}],'data_model':encoded(model),'resolved_data_model':encoded(model),'entries':encoded({}),'resolved_entries':encoded({}),'resolved_metadata':encoded({'contentType':'application/did'}),'result':{'has_content':True,'returned_id':'did:example:123','content_kind':'document','metadata':{'contentType':'application/did'},'content_metadata':{},'raw':encoded(wire)}})
 obs=[{'statement':i,'verdict':v,'input':json.dumps(s['request']),'observed':json.dumps(e),'detail':'bounded roles','expected':'ordinary expansion'} for i,v in zip(IDS,['PASS','FAIL'])];raw['cases'].append({'case':CASE,'statements':IDS,'observations':obs})
 for i,v in zip(IDS,['PASS','FAIL']):report['statements'].append({'id':i,'verdict':v,'cases':[CASE]})
 for i in PENDING:report['statements'].append({'id':i,'verdict':'NOT_RUN','cases':[]})
 return raw,report
class ExpansionEvidenceTests(unittest.TestCase):
 def test_complete_and_omission(self):
  r,p=controls();self.assertEqual(verify_expansion_source(r,p),set(IDS));r['cases'].pop()
  with self.assertRaises(AssertionError):verify_expansion_source(r,p)
 def test_provenance_and_same_call(self):
  r,p=controls()
  for mutate in [lambda e:e['source'].update(files={}),lambda e:e['source']['request'].update(packages=[]),lambda e:e['source'].update(replaced=0),lambda e:e.update(type_checker_compiler='other'),lambda e:e['audit']['steps'][0].update(correct=1),lambda e:e['audit']['steps'][1].update(correct=True),lambda e:e['audit'].update(frames={}),lambda e:e['audit'].update(call_paths=[]),lambda e:e['runtime'].pop(),lambda e:e['runtime'][0].update(consumption=[]),lambda e:e['runtime'][2]['consumption'][0].update(model=encoded({})),lambda e:e['runtime'][0]['consumption'][0].update(strict=0),lambda e:e['runtime'][0].update(driver_options=[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':0})]),lambda e:e['runtime'][0]['result'].update(has_content=1),lambda e:e['runtime'][2].update(data_model=encoded({})),lambda e:e['runtime'][3]['result'].update(raw=encoded({})),lambda e:e['runtime'][0].update(resolved_metadata=encoded({})),lambda e:e['runtime'][0]['consumption'][0].update(error='diagnostic')]:
   bad=copy.deepcopy(r);e=json.loads(bad['cases'][-1]['observations'][0]['observed']);mutate(e)
   for o in bad['cases'][-1]['observations']:o['observed']=json.dumps(e)
   with self.assertRaises((AssertionError,KeyError)):verify_expansion_source(bad,p)
 def test_findings_and_scope(self):
  r,p=controls()
  for ident in IDS+PENDING:
   bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==ident)['verdict']='PASS' if ident!=IDS[0] else 'FAIL'
   with self.assertRaises(AssertionError):verify_expansion_source(r,bad)
  bad=copy.deepcopy(r);bad['cases'][-1]['observations'][1]['verdict']='PASS'
  with self.assertRaises(AssertionError):verify_expansion_source(bad,p)
  bad=copy.deepcopy(p);next(x for x in bad['statements'] if x['id']==IDS[0])['cases']=['other']
  with self.assertRaises(AssertionError):verify_expansion_source(r,bad)
if __name__=='__main__':unittest.main()
