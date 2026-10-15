import base64
import copy
import json
import unittest
from pathlib import Path
from check_sage_fragment_search import verify_fragment_search,INITIAL,PREFIX,IDS,RULE,MODULE,matches
from test_check_sage_fragment_source import controls as source_controls

REPO=Path(__file__).resolve().parents[1]
def enc(v):return base64.b64encode(json.dumps(v).encode()).decode()

def controls():
 raw,report=source_controls();old=json.loads(raw['cases'][0]['observations'][0]['observed'])
 initial={'source_evidence':copy.deepcopy(old),'initial':{'binding':copy.deepcopy(old['audit']),'search':MODULE+'/dereferencer.findFragment','result_types':['any','bool'],'result_roles':['found','ok'],'initial_values':['nil interface (no fragment)','false (no match)'],'language_rule':RULE,'unknown':[]}}
 obs={'statement':IDS[0],'verdict':'PASS','input':json.dumps(old['source']['request']),'observed':json.dumps(initial),'detail':'selected source role','expected':'semantic initial nil'}
 raw['cases'].append({'case':INITIAL,'statements':[IDS[0]],'observations':[obs]})
 init=next(s for s in report['statements'] if s['id']==IDS[0]);init.update(verdict='PASS',cases=[INITIAL])
 fs=json.loads((REPO/'profiles/sageresolution/fragment_search.json').read_text());caseids=[]
 for f in fs:
  name=PREFIX+f['name'];caseids.append(name);values=[]
  for i in range(3):
   doc=f['control_document'] if i==1 else f['document'];q=dict(f['request'])
   if i==2:q['input']='did:example:resources#absent'
   good=i==1 or i==0 and f['name']=='extension-list'
   result={'has_content':good,'raw':enc(f['expected_content'] if good else None),'content_metadata':{},'metadata':{'contentType':'application/ld+json'} if good else {'error':{'type':'https://www.w3.org/ns/did#NOT_FOUND'}}}
   if good:result.update(content_kind='map',returned_id=f['expected_content']['id'])
   values.append({'request':{'document':{'data':enc(doc),'media_type':'application/did'},'request':q},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','options':enc({'accept':'application/did'}),'resolve_inputs':['did:example:resources'],'resolve_options':[enc({'accept':'application/did'})],'driver_inputs':['did:example:resources'],'driver_options':[enc({'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False})],'driver_results':[enc({'ContentType':'application/did','Data':enc(doc)})],'data_model':enc(doc),'entries':enc({}),'result':result})
  o={'statement':IDS[1],'verdict':'PASS' if f['name']=='extension-list' else 'FAIL','input':json.dumps(f),'observed':json.dumps(values),'detail':'selected ordinary maps','expected':'unique map found'}
  raw['cases'].append({'case':name,'statements':[IDS[1]],'observations':[o]})
 row=next(s for s in report['statements'] if s['id']==IDS[1]);row.update(verdict='FAIL',cases=caseids)
 return raw,report

class FragmentSearchArtifactTests(unittest.TestCase):
 def test_complete_contract_and_case_omissions(self):
  raw,report=controls();self.assertEqual(verify_fragment_search(raw,report),set(IDS))
  for index in [1,2,6]:
   bad=copy.deepcopy(raw);bad['cases'].pop(index)
   with self.assertRaises((AssertionError,KeyError)):verify_fragment_search(bad,report)
  self.assertEqual(len(matches({'a':[False,{'id':'#target'},{'id':'did:example:resources#target','child':{'id':'#target'}}]})),3)
 def test_initial_source_and_role_controls(self):
  raw,report=controls()
  for mutate in [lambda e:e['initial'].update(result_types=['string','bool']),lambda e:e['initial'].update(result_roles=['other','ok']),lambda e:e['initial'].update(initial_values=['empty map','false']),lambda e:e['initial'].update(language_rule='untrusted'),lambda e:e['initial'].update(unknown=['missing']),lambda e:e['source_evidence']['source'].update(files={})]:
   bad=copy.deepcopy(raw);o=bad['cases'][1]['observations'][0];e=json.loads(o['observed']);mutate(e);o['observed']=json.dumps(e)
   with self.assertRaises(AssertionError):verify_fragment_search(bad,report)
 def test_same_call_and_control_mutations(self):
  raw,report=controls()
  for mutate in [lambda v:v[0].update(data_model=enc({})),lambda v:v[0].update(role='other'),lambda v:v[0].update(resolve_options=[enc({})]),lambda v:v[0].update(entries=enc({'lost':1})),lambda v:v[1]['result'].update(has_content=False),lambda v:v[2]['result'].update(has_content=True),lambda v:v[0]['result'].update(raw=enc({'id':'other'}))]:
   bad=copy.deepcopy(raw);o=bad['cases'][3]['observations'][0];v=json.loads(o['observed']);mutate(v);o['observed']=json.dumps(v)
   with self.assertRaises(AssertionError):verify_fragment_search(bad,report)
  bad=copy.deepcopy(report);next(s for s in bad['statements'] if s['id']==IDS[1])['cases']=[]
  with self.assertRaises(AssertionError):verify_fragment_search(raw,bad)

 def test_boolean_number_input_provenance(self):
  raw,report=controls()
  for field in ['request','driver','fixture','presence','no_cache']:
   bad=copy.deepcopy(raw);o=bad['cases'][3]['observations'][0];values=json.loads(o['observed']);v=values[0]
   if field=='request':
    doc=json.loads(base64.b64decode(v['request']['document']['data']));doc['verificationMethod'][0]['extra']['container'][0]['child']['values'][0]=0;v['request']['document']['data']=enc(doc)
   if field=='driver':
    read=json.loads(base64.b64decode(v['driver_results'][0]));doc=json.loads(base64.b64decode(read['Data']));doc['verificationMethod'][0]['extra']['container'][0]['child']['values'][0]=0;read['Data']=enc(doc);v['driver_results'][0]=enc(read)
   if field=='fixture':
    f=json.loads(o['input']);f['document']['verificationMethod'][0]['extra']['container'][0]['child']['values'][0]=0;o['input']=json.dumps(f)
   if field=='presence':v['result']['has_content']=0
   if field=='no_cache':
    opts=json.loads(base64.b64decode(v['driver_options'][0]));opts['NoCache']=0;v['driver_options'][0]=enc(opts)
   o['observed']=json.dumps(values)
   with self.assertRaises(AssertionError,msg=field):verify_fragment_search(bad,report)

if __name__=='__main__':unittest.main()
