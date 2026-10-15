"""Verify bounded service selection and exact media branches from fresh receipts."""
from sage_url_role_scope import verify_url_pending
import argparse,base64,json
from pathlib import Path
from check_sage_contracts import semantic_equal
from check_sage_fragment_source import CASE as SOURCE,MODULE
from check_sage_service_source import verify_service,decoded
REPO=Path(__file__).resolve().parents[1]
CASE='did-1.1/sage-resolution/selection-source-roles'
IDS=['res10-crd20261001#dereferencing-algorithm-resource.'+str(i) for i in [17,21,29,35]]
MEDIA=['application/did','application/did+ld+json','application/did+json']
PENDING=['res10-crd20261001#dereferencing-algorithm-resource.11','cid10#retrieve-verification-method.3','res10-crd20261001#dereferencing-algorithm-fragment.3']
def verify_selection(raw,report,repo=REPO):
 verify_service(raw,report,repo)
 selected=[c for c in raw['cases'] if '/selection-source-' in c['case']];assert len(selected)==1
 c=selected[0];assert c['case']==CASE and c['statements']==IDS and len(c['observations'])==4
 o=c['observations'];assert [x['statement'] for x in o]==IDS
 assert all(x['verdict']=='PASS' and x['detail'] and x['expected'] and x['observed']==o[0]['observed'] and x['input']==o[0]['input'] for x in o)
 e=json.loads(o[0]['observed']);source=json.loads(next(c for c in raw['cases'] if c['case']==SOURCE)['observations'][0]['observed'])
 assert semantic_equal(e['source_evidence'],source,'unknown') and semantic_equal(json.loads(o[0]['input']),source['source']['request'],'unknown')
 witness=json.loads((repo/'profiles/sageresolution/selection_witness.json').read_text());assert semantic_equal(e['audit'],witness,'unknown')
 assert not e['audit']['unknown'] and len(e['audit']['call_paths'])==3 and len(e['audit']['steps'])==4
 assert all(type(s['correct']) is bool and s['correct'] and s['expressions'] for s in e['audit']['steps'])
 fs=json.loads((repo/'profiles/sageresolution/selection.json').read_text());assert len(fs)==len(e['runtime'])==12
 assert [f['name'] for f in fs]==['service-only','type-multiple','intersection','wrong-type','wrong-id','other-intersection','each-service-relative','each-service-plain','missing-accept','did-json','did-ld-json','unoffered-media']
 for f,v in zip(fs,e['runtime']):
  q=f['request'];doc=f['document'];accept=q.get('accept','');opts={'accept':accept} if accept else {};nested=dict(f['parameters'])
  if accept in MEDIA:nested['accept']=accept
  assert v['request']['request']==q and v['request']['document']['media_type']=='application/did' and semantic_equal(decoded(v['request']['document']['data']),doc,'unknown')
  assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources']
  assert len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
  assert semantic_equal(decoded(v['options']),opts,'unknown') and semantic_equal(decoded(v['resolve_options'][0]),nested,'unknown')
  assert semantic_equal(decoded(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'application/did' if accept=='application/did' else '', 'NoCache':False},'unknown')
  read=decoded(v['driver_results'][0]);assert read['ContentType']=='application/did' and semantic_equal(decoded(read['Data']),doc,'unknown')
  assert semantic_equal(decoded(v['resolved_data_model']),doc,'unknown') and decoded(v['resolved_entries'])=={}
  assert decoded(v['resolved_metadata'])=={'contentType':accept if accept in MEDIA else 'application/did'}
  result=v['result'];assert not result.get('native') and not result.get('exchange') and type(result['has_content']) is bool
  if f['diagnostic_error']:assert not result['has_content'] and decoded(result['raw']) is None and result['metadata']['error']['type']=='https://www.w3.org/ns/did#'+f['diagnostic_error']
  else:
   media=accept or 'application/did'
   assert result['has_content'] and 'error' not in result['metadata'] and result['metadata']['contentType']==media and result['content_kind']==f['expected_kind']
   assert semantic_equal(decoded(result['raw']),f['expected_content'],'unknown')
   if f['expected_kind']=='document':
    assert result['content_metadata']=={} and result['returned_id']=='did:example:resources'
    assert semantic_equal(decoded(v['data_model']),f['expected_content'],'unknown') and decoded(v['entries'])=={}
   else:assert result['content_metadata']=={'contentType':'text/uri-list'}
 live={x['id']:x for x in report['statements']}
 for ident in IDS:assert live[ident]['verdict']=='PASS' and live[ident]['cases']==[CASE]
 verify_url_pending(raw,live,PENDING)
 return set(IDS)
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();ids=verify_selection(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified',len(ids),'selection roles and twelve ordinary actual calls with original models')
if __name__=='__main__':main()
