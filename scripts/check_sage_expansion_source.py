"""Verify bounded resolver expansion roles and same-call original models."""
import argparse,base64,copy,hashlib,io,json,zipfile
from pathlib import Path
from check_sage_contracts import semantic_equal
from check_sage_dispatch import verify_dispatch
from check_sage_fragment_source import MODULE,VERSION,SUM,REPO,data
from check_sage_service_source import decoded
CASE='did-1.1/sage-resolution/expansion-source-roles'
IDS=['res10-crd20261001#resolving-algorithm.'+str(i) for i in (27,28)]
PENDING=['res10-crd20261001#resolving-algorithm.'+str(i) for i in (26,29)]
PACKAGES=['resolver','method','did','document','internal/multiformats','representation','resolution','spec','vm']
def node(root,path):
 for key in path:root=root[int(key)] if isinstance(root,list) else root[key]
 return root
def verify_expansion_source(raw,report,repo=REPO):
 verify_dispatch(raw,report,repo)
 selected=[c for c in raw['cases'] if '/expansion-source-' in c['case']];assert len(selected)==1
 c=selected[0];assert c['case']==CASE and c['statements']==IDS and len(c['observations'])==2
 obs=c['observations'];assert [o['statement'] for o in obs]==IDS and [o['verdict'] for o in obs]==['PASS','FAIL']
 assert all(o['detail'] and o['expected'] and o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
 e=json.loads(obs[0]['observed']);s=e['source'];q=json.loads(obs[0]['input'])
 assert q==s['request']=={'module':MODULE,'version':VERSION,'packages':PACKAGES,'diagnostics':None}
 assert (s['module'],s['version'],s['sum'])==(MODULE,VERSION,SUM)
 assert s['operation']=='debug.ReadBuildInfo + local go env + module cache/ZIP byte capture' and s['replaced'] is False and not s['diagnostics'] and not e.get('analysis_error')
 assert s['compiler']==s['environment_compiler']==e['type_checker_compiler']=='go1.26.8' and e['type_checker_architecture'] in ['arm64','amd64']
 prefix=MODULE+'@'+VERSION+'/'
 with zipfile.ZipFile(io.BytesIO(data(s['archive']))) as z:
  names=z.namelist();assert names and len(names)==len(set(names)) and all(n.startswith(prefix) and chr(10) not in n and chr(13) not in n for n in names)
  files={n:z.read(n) for n in names}
 digest=''.join(hashlib.sha256(files[n]).hexdigest()+'  '+n+chr(10) for n in sorted(files))
 assert 'h1:'+base64.b64encode(hashlib.sha256(digest.encode()).digest()).decode()==SUM
 chosen={n[len(prefix):]:b for n,b in files.items() if n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
 assert len(chosen)==39 and set(chosen)==set(s['files']) and all(data(s['files'][n])==b for n,b in chosen.items())
 witness=json.loads((repo/'profiles/sageresolution/expansion_source_witness.json').read_text());a=e['audit']
 assert semantic_equal(a,witness,'unknown') and not a['unknown'] and len(a['frames'])==315 and len(a['call_paths'])==7
 assert [x['correct'] for x in a['steps']]==[True,False] and all(type(x['correct']) is bool and x['expressions'] for x in a['steps'])
 assert a['roles']['method_extensions']==a['roles']['service_extensions']=='false'
 fs=json.loads((repo/'profiles/sageresolution/expansion_source.json').read_text());assert len(fs)==len(e['runtime'])==5
 assert [f['name'] for f in fs]==['absent','disabled','nested-extras','root-relocated','empty-collections']
 missing=[]
 for f,v in zip(fs,e['runtime']):
  doc=f['document'];q=f['request'];enabled=q.get('options',{}).get('expandRelativeUrls') is True;opts={'accept':'application/did'}
  if enabled:opts['expandRelativeUrls']=True
  assert semantic_equal(v['request']['request'],q,'unknown') and v['request']['document']['media_type']=='application/did' and semantic_equal(decoded(v['request']['document']['data']),doc,'unknown')
  assert v['operation']==MODULE+'/resolver.DefaultResolver.Resolve' and v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and not v.get('capture_error')
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:123'] and len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==len(v['consumption'])==1
  assert semantic_equal(decoded(v['options']),opts,'unknown') and semantic_equal(decoded(v['resolve_options'][0]),opts,'unknown')
  assert semantic_equal(decoded(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False},'unknown')
  read=decoded(v['driver_results'][0]);assert read['ContentType']=='application/did' and semantic_equal(decoded(read['Data']),doc,'unknown')
  con=v['consumption'][0];assert con['operation']==MODULE+'/consumer.Consumer.Consume' and data(con['input'])==data(v['request']['document']['data'])
  assert con['media_type']=='application/did' and con['require']==con['expected']=='unknown' and con['strict'] is False and con['json_ld'] is False and not con['dropped_terms'] and not con.get('error') and not con.get('capture_error')
  assert semantic_equal(decoded(con['model']),doc,'unknown') and decoded(con['entries'])=={}
  result=v['result'];assert result['has_content'] is True and result['returned_id']=='did:example:123' and result['content_kind']=='document' and not result.get('native') and not result.get('exchange')
  assert result['metadata']=={'contentType':'application/did'} and result['content_metadata']=={} and decoded(v['entries'])==decoded(v['resolved_entries'])=={} and decoded(v['resolved_metadata'])=={'contentType':'application/did'}
  model=decoded(v['data_model']);assert semantic_equal(model,decoded(v['resolved_data_model']),'unknown')
  wire=decoded(result['raw'])
  if enabled:assert wire.pop('@context')=='https://www.w3.org/ns/did/v1.1'
  assert semantic_equal(wire,model,'unknown')
  adjusted=copy.deepcopy(model)
  for path in f['extension_paths']:
   got,want,original=node(model,path),node(f['expected'],path),node(doc,path)
   assert type(got) is str and got in (want,original)
   if got==original:missing.append((f['name'],path))
   parent=node(adjusted,path[:-1]);parent[int(path[-1]) if isinstance(parent,list) else path[-1]]=want
  assert semantic_equal(adjusted,f['expected'],'unknown')
 assert len(missing)==5 and all(name=='nested-extras' for name,path in missing)
 live={x['id']:x for x in report['statements']}
 for ident,verdict in zip(IDS,['PASS','FAIL']):assert live[ident]['verdict']==verdict and live[ident]['cases']==[CASE]
 for ident in PENDING:assert live[ident]['verdict']=='NOT_RUN'
 return set(IDS)
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();ids=verify_expansion_source(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified',len(ids),'expansion predicates, 39 source files and five actual calls; complete extension traversal FAIL preserved')
if __name__=='__main__':main()
