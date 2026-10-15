"""Verify all nine internal review rows and the four bounded actual judgments."""
import argparse,base64,hashlib,json
from pathlib import Path
from check_sage_returned_representation import verify_returned_representation
from check_sage_contracts import semantic_equal
from sage_internal_boundary_scope import CASES,CAPACITY_IDS,MEDIA_ID,CONTEXT_ID,verify_internal_pending
REPO=Path(__file__).resolve().parents[1]
MODULE='github.com/sage-x-project/did-go'
ROLE='root resolver/dereferencer library with literal example driver; not SAGE Source'
def data(s):return base64.b64decode(s,validate=True)
def unique(pairs):
 assert len({k for k,_ in pairs})==len(pairs)
 return dict(pairs)
def parsed(s):return json.loads(data(s).decode('utf-8'),object_pairs_hook=unique)
def component_encoding(b):
 alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
 zeros=len(b)-len(b.lstrip(b'\x00'));n=int.from_bytes(b,'big');out=''
 while n:n,digit=divmod(n,64);out=alphabet[digit]+out
 return 'u'+'A'*zeros+out

def verify_manifest(raw,report,repo=REPO):
 manifest=json.loads((repo/'docs/sage-internal-evidence-boundaries.json').read_text());live={x['id']:x for x in report['statements']}
 assert manifest['schema']=='sage-internal-evidence-boundaries/1' and (manifest['reviewed'],manifest['new_observed'],manifest['retained_not_run'])==(9,4,5)
 ids={x['id'] for x in manifest['clauses']};assert len(ids)==len(manifest['clauses'])==9
 audit=json.loads((repo/'docs/sage-remaining-clause-review.json').read_text());original={x['id']:x for x in audit['clauses']}
 expected=set(CASES)|{'cid10#base-encode.13','cid10#base-decode.16','cid10#json-ld-context.1','cid10#vocabulary.1','did11-cr20260305#json-ld-processors.1'};assert ids==expected
 for x in manifest['clauses']:
  assert all(x[k]==original[x['id']][k] for k in ['text','text_sha256','level','actor']) and x['text_sha256']==hashlib.sha256(x['text'].encode()).hexdigest()
  assert x['basis'] and x['completion_boundary'] and x['expected_live_verdict']==live[x['id']]['verdict']
  if x['id'] in CASES:assert x['status']=='observed-selected-branch' and x['cases']==[CASES[x['id']]];verify_internal_pending(raw,live,x['id'])
  else:assert x['status']=='reviewed-awaiting-evidence' and not x['cases'] and x['expected_live_verdict']=='NOT_RUN' and x['remaining_reason'] in ['normative-text-conflict','processing-applicability-unresolved'] and not live[x['id']].get('cases')
 return manifest

def verify_internal_boundaries(raw,report,repo=REPO):
 verify_returned_representation(raw,report,repo);verify_manifest(raw,report,repo)
 bycase={c['case']:c for c in raw['cases']};live={x['id']:x for x in report['statements']}
 def case(ident,ids):
  c=bycase[CASES[ident]];obs=c['observations'];assert c['statements']==ids and [o['statement'] for o in obs]==ids
  assert all(o['verdict']=='PASS' and o['input'] and o['observed'] and o['detail'] and o['expected'] and o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
  return obs[0],json.loads(obs[0]['observed'])
 o,e=case(CAPACITY_IDS[0],CAPACITY_IDS);prior=json.loads(bycase['did-1.1/sage-resolution/multihash-component-operations']['observations'][0]['observed'])
 assert semantic_equal(e['source'],prior['source'],'unknown') and json.loads(o['input'])==e['source']['request'] and type(e.get('analysis_error','')) is str and not e.get('analysis_error')
 assert e['type_checker_compiler']=='go1.26.8' and e['type_checker_architecture'] in ['arm64','amd64']
 witness=json.loads((repo/'profiles/sageresolution/capacity_witness.json').read_text());assert semantic_equal(e['audit'],witness,'unknown') and not e['audit']['unknown'] and all(s['correct'] is True for s in e['audit']['steps'])
 fixtures=json.loads((repo/'profiles/sageresolution/capacity.json').read_text());assert len(fixtures)==len(e['calls'])==18
 for f,v in zip(fixtures,e['calls']):
  q=f['request'];assert v['request']==q and q['header']==117 and type(q['header']) is int and v['role']=='Inspector-owned direct internal multiformats component probe; not a SAGE production caller' and type(v.get('error','')) is str and not v.get('error')
  observer=dict(v['observer']);assert type(observer.get('replacement_version')) is str and observer['replacement_version'] in ['', '(devel)'];observer['replacement_version']='(devel)' if observer['replacement_version']=='' else observer['replacement_version'];assert observer=={'module':MODULE+'/inspectorprobe','version':'v0.0.0','replacement':'../sageprobe','replacement_version':'(devel)','replacement_sum':'','compiler':'go1.26.8'}
  b=data(f['expected_data']);assert len(b)<=4096 and component_encoding(b)==f['expected_encoded']
  if q['operation']=='encode':assert v['operation']==MODULE+'/internal/multiformats.EncodeMultibase' and data(q['data'])==b and v['encoded']==f['expected_encoded']
  else:assert v['operation']==MODULE+'/internal/multiformats.DecodeMultibase' and q['encoded']==f['expected_encoded'] and type(v['header']) is int and v['header']==117 and data(v['data'])==b
 # Exact power-of-two ratios and bounded pre-division multiplication, not float logs.
 assert 256==2**8 and 64==2**6 and 4096*8+1<2**31 and 4096*6+1<2**31
 o,v=case(CONTEXT_ID,[CONTEXT_ID]);q=json.loads(o['input'])
 assert q=={'id':'did:sage:web:registry.example:agent-1','controllers':['did:sage:web:registry.example:controller-a','did:sage:web:registry.example:controller-b'],'fields':None,'entries':None,'json_ld':True} and q['json_ld'] is True
 assert v['id']==q['id'] and v['controllers']==q['controllers'] and v['controller_shape']=='set' and not v['fields'] and not v['entries'] and not v.get('build_error') and not v.get('capture_error') and len(v['calls'])==1
 c=v['calls'][0];model={'id':q['id'],'controller':q['controllers']}
 assert c['operation']==MODULE+'/producer.Producer.Produce' and c['version']=='1.1' and c['json_ld'] is True and c['include_secret'] is False and not c.get('capture_error') and not c.get('error')
 assert parsed(c['model'])==model and parsed(c['entries'])=={} and c['media_type']=='application/did'
 assert parsed(c['output'])==dict(model,**{'@context':'https://www.w3.org/ns/did/v1.1'})
 assert hashlib.sha256((repo/'profiles/sageresolution/did-v1.1-context.jsonld').read_bytes()).hexdigest()=='ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85'
 o,e=case(MEDIA_ID,[MEDIA_ID]);prior=json.loads(bycase['did-1.1/sage-resolution/fragment-source-bindings']['observations'][0]['observed'])
 assert semantic_equal(e['source'],prior['source'],'unknown') and json.loads(o['input'])==e['source']['request'] and type(e.get('analysis_error','')) is str and not e.get('analysis_error')
 witness=json.loads((repo/'profiles/sageresolution/fragment_media_witness.json').read_text());assert semantic_equal(e['audit'],witness,'unknown') and not e['audit']['unknown'] and all(s['correct'] is True for s in e['audit']['steps'])
 f=json.loads((repo/'profiles/sageresolution/fragment_media.json').read_text());assert len(f['document']['verificationMethod'])==1 and f['document']['verificationMethod'][0]==f['method'] and f['document']['authentication']==[f['method']['id']]
 assert len(e['runtime'])==2
 for i,v in enumerate(e['runtime']):
  q=v['request'];assert q['plain_json_fragment'] is True and not q.get('observe_production') and not q.get('observe_resource_handler')
  assert q['request']=={'function':'dereference','input':'did:example:resources#'+('sign' if i==0 else 'missing'),'accept':'application/did+json','relationship':'authentication'} and q['document']['media_type']=='application/did+json' and parsed(q['document']['data'])==f['document']
  assert v['role']==ROLE and v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error') and not v.get('production') and not v.get('resource_handler')
  opts={'accept':'application/did+json','verificationRelationship':'authentication'};assert parsed(v['options'])==opts and len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==len(v['consumption'])==1 and parsed(v['resolve_options'][0])==opts
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources']
  options=parsed(v['driver_options'][0]);assert options=={'VersionID':'','VersionTime':None,'MediaType':'application/did+json','NoCache':False} and options['NoCache'] is False
  driver=parsed(v['driver_results'][0]);assert driver['ContentType']=='application/did+json' and data(driver['Data'])==data(q['document']['data']) and driver['Metadata']=={}
  c=v['consumption'][0];assert c['operation']==MODULE+'/consumer.Consumer.Consume' and data(c['input'])==data(q['document']['data']) and c['media_type']=='application/did+json' and c['version']=='1.0' and c['json_ld'] is False and c['strict'] is False and c['require']==c['expected']=='unknown' and not c['dropped_terms'] and not c.get('error') and not c.get('capture_error')
  assert parsed(c['model'])==parsed(v['data_model'])==parsed(v['resolved_data_model'])==f['document'] and parsed(c['entries'])==parsed(v['entries'])==parsed(v['resolved_entries'])=={}
  result=v['result'];assert not result.get('native') and not result.get('exchange') and result['content_metadata']=={} and parsed(v['resolved_metadata'])=={'contentType':'application/did+json'}
  if i==0:assert result['has_content'] is True and result['content_kind']=='verification-method' and result['returned_id']==f['method']['id'] and parsed(result['raw'])==f['method'] and result['metadata']=={'contentType':'application/json'}
  else:assert result['has_content'] is False and parsed(result['raw']) is None and result['metadata']['error']['type']=='https://w3id.org/security#INVALID_VERIFICATION_METHOD'
 return set(CASES)
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();verify_internal_boundaries(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified all nine internal boundary rows, four selected judgments, eighteen original u calls and actual plain-JSON/context injection receipts; five remain NOT_RUN')
if __name__=='__main__':main()
