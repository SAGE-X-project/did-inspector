"""Verify primary-resource URL and DID parser/typed RP integration evidence."""
import argparse,base64,hashlib,io,json,zipfile
from pathlib import Path
from check_sage_contracts import semantic_equal
from check_sage_expansion_source import verify_expansion_source
from check_sage_fragment_source import MODULE,VERSION,SUM,REPO,data
from check_sage_service_source import decoded
from sage_url_role_scope import CASE,VERDICTS,verify_url_pending
IDS=list(VERDICTS)
PACKAGES=['dereferencer','relyingparty','did','document','internal/multiformats','representation','resolution','spec','vm']
PENDING=['res10-crd20261001#dereferencing-algorithm-fragment.3','res10-crd20261001#resolving-algorithm.26','res10-crd20261001#resolving-algorithm.29']
def verify_url_roles(raw,report,repo=REPO):
 verify_expansion_source(raw,report,repo)
 selected=[c for c in raw['cases'] if '/url-source-' in c['case']];assert len(selected)==1
 c=selected[0];assert c['case']==CASE and c['statements']==IDS
 obs=c['observations'];assert len(obs)==2 and [o['statement'] for o in obs]==IDS and [o['verdict'] for o in obs]==['FAIL','PASS']
 assert all(o['expected'] and o['detail'] and o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
 e=json.loads(obs[0]['observed']);s=e['source'];q=json.loads(obs[0]['input'])
 assert q==s['request']=={'module':MODULE,'version':VERSION,'packages':PACKAGES,'diagnostics':None}
 assert (s['module'],s['version'],s['sum'])==(MODULE,VERSION,SUM) and s['operation']=='debug.ReadBuildInfo + local go env + module cache/ZIP byte capture'
 assert s['replaced'] is False and not s['diagnostics'] and not e.get('analysis_error') and not e.get('handler_errors') and not e.get('retrieval_errors')
 assert s['compiler']==s['environment_compiler']==e['type_checker_compiler']=='go1.26.8' and e['type_checker_architecture'] in ['arm64','amd64']
 prefix=MODULE+'@'+VERSION+'/'
 with zipfile.ZipFile(io.BytesIO(data(s['archive']))) as z:
  names=z.namelist();assert names and len(names)==len(set(names)) and all(n.startswith(prefix) and chr(10) not in n and chr(13) not in n for n in names);files={n:z.read(n) for n in names}
 digest=''.join(hashlib.sha256(files[n]).hexdigest()+'  '+n+chr(10) for n in sorted(files))
 assert 'h1:'+base64.b64encode(hashlib.sha256(digest.encode()).digest()).decode()==SUM
 chosen={n[len(prefix):]:b for n,b in files.items() if n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
 assert len(chosen)==39 and set(chosen)==set(s['files']) and all(data(s['files'][n])==b for n,b in chosen.items())
 w=json.loads((repo/'profiles/sageresolution/url_roles_witness.json').read_text());a=e['audit'];assert semantic_equal(a,w,'unknown') and not a['unknown'] and len(a['frames'])==337 and len(a['call_paths'])==10
 assert [x['correct'] for x in a['steps']]==[False,True] and all(type(x['correct']) is bool and x['expressions'] for x in a['steps'])
 fs=json.loads((repo/'profiles/sageresolution/url_roles.json').read_text());assert len(fs['handlers'])==len(e['handler'])==7 and len(fs['retrieval'])==len(e['retrieval'])==7
 missing=[]
 for f,v in zip(fs['handlers'],e['handler']):
  doc=f['document'];q=f['request'];opts={'accept':'application/did'};nested=dict(opts)
  if f['parts']['has_query']:nested['relativeRef']='next'
  assert v['request']['observe_resource_handler'] is True and semantic_equal(v['request']['request'],q,'unknown') and v['request']['document']['media_type']=='application/did' and semantic_equal(decoded(v['request']['document']['data']),doc,'unknown')
  assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources'] and len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==len(v['consumption'])==1
  assert semantic_equal(decoded(v['options']),opts,'unknown') and semantic_equal(decoded(v['resolve_options'][0]),nested,'unknown')
  assert semantic_equal(decoded(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False},'unknown')
  read=decoded(v['driver_results'][0]);assert read['ContentType']=='application/did' and semantic_equal(decoded(read['Data']),doc,'unknown')
  assert semantic_equal(decoded(v['resolved_data_model']),doc,'unknown') and semantic_equal(decoded(v['data_model']),doc,'unknown') and decoded(v['resolved_entries'])==decoded(v['entries'])=={} and decoded(v['resolved_metadata'])=={'contentType':'application/did'}
  con=v['consumption'][0];assert con['operation']==MODULE+'/consumer.Consumer.Consume' and data(con['input'])==data(v['request']['document']['data']) and con['media_type']=='application/did' and con['require']==con['expected']=='unknown' and con['strict'] is False and con['json_ld'] is False and not con['dropped_terms'] and not con.get('error') and not con.get('capture_error') and semantic_equal(decoded(con['model']),doc,'unknown') and decoded(con['entries'])=={}
  hs=v.get('resource_handler',[]);assert len(hs)==f['handler_calls']
  for h in hs:
   assert h['operation']==MODULE+'/dereferencer.ResourceHandler' and h['role']=='literal passive resource handler; records actual values and returns unhandled' and not h.get('capture_error')
   assert semantic_equal(decoded(h['options']),opts,'unknown') and semantic_equal(decoded(h['model']),doc,'unknown') and decoded(h['entries'])=={} and decoded(h['metadata'])=={'contentType':'application/did'}
   assert semantic_equal(h['url'],f['parts'],'unknown')
   if f['parts']['has_fragment']:assert h['url']['input']!=f['adjusted']['input'];missing.append(f['name'])
  result=v['result'];assert result['content_metadata']=={} and not result.get('native') and not result.get('exchange')
  if f['diagnostic_error']:assert result['has_content'] is False and decoded(result['raw']) is None and result['metadata']['error']['type']==f['diagnostic_error']
  else:assert result['has_content'] is True and result['content_kind']==f['expected_kind'] and result['metadata']=={'contentType':'application/ld+json'} and semantic_equal(decoded(result['raw']),f['expected_content'],'unknown')
 assert missing==['path-fragment','empty-fragment','query-fragment','path-query-fragment','percent-fragment']
 for f,v in zip(fs['retrieval'],e['retrieval']):
  q=f['request'];assert v['operation']==MODULE+'/relyingparty.RelyingParty.VerificationMethod' and v['clock']==1800000000 and v['reference']==q['reference'] and v['purpose']==q['purpose'] and not v.get('capture_error') and semantic_equal(v['parsed_url'],f['parts'],'unknown')
  # Downstream diagnostic outcomes do not judge the independent parser step.
  if f['expected_method'] is None:continue
  assert not v.get('error') and not v.get('problem') and not v.get('problem_serializer') and semantic_equal(decoded(v['method']),f['expected_method'],'unknown') and len(v['calls'])==1
  call=v['calls'][0];assert call['input']==f['parts']['primary'] and decoded(call['options'])=={}
  result=call['result'];assert result['has_content'] is True and result['returned_id']==f['record']['did'] and result['content_kind']=='document'
  doc=result['snapshot'];assert isinstance(doc,dict);assert doc['id']==f['record']['did'] and any(semantic_equal(m,f['expected_method'],'unknown') for m in doc['verificationMethod']) and q['reference'] in doc[q['purpose']]
 live={x['id']:x for x in report['statements']};verify_url_pending(raw,live,IDS)
 for ident in PENDING:assert live[ident]['verdict']=='NOT_RUN'
 return set(IDS)
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();ids=verify_url_roles(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified',len(ids),'independent URL predicates, 39 source files, seven handler and seven parser/RP calls; URL separation FAIL preserved')
if __name__=='__main__':main()
