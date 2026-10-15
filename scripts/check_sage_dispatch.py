"""Verify same resolved-document and bounded dispatch roles from fresh receipts."""
import argparse,json
from pathlib import Path
from check_sage_contracts import semantic_equal
from check_sage_fragment_source import CASE as SOURCE,MODULE
from check_sage_service_source import decoded
from check_sage_selection import verify_selection
REPO=Path(__file__).resolve().parents[1]
CASE='did-1.1/sage-resolution/dispatch-source-roles'
IDS=['res10-crd20261001#dereferencing-algorithm-resource.'+str(i) for i in [10,44]]+['res10-crd20261001#dereferencing-algorithm-fragment.7']
PENDING=['res10-crd20261001#dereferencing-algorithm-resource.11','cid10#retrieve-verification-method.3','res10-crd20261001#dereferencing-algorithm-fragment.3']
def verify_dispatch(raw,report,repo=REPO):
 verify_selection(raw,report,repo)
 selected=[c for c in raw['cases'] if '/dispatch-source-' in c['case']];assert len(selected)==1
 c=selected[0];assert c['case']==CASE and c['statements']==IDS and len(c['observations'])==3
 o=c['observations'];assert [x['statement'] for x in o]==IDS
 assert all(x['verdict']=='PASS' and x['detail'] and x['expected'] and x['observed']==o[0]['observed'] and x['input']==o[0]['input'] for x in o)
 e=json.loads(o[0]['observed']);source=json.loads(next(c for c in raw['cases'] if c['case']==SOURCE)['observations'][0]['observed'])
 assert semantic_equal(e['source_evidence'],source,'unknown') and semantic_equal(json.loads(o[0]['input']),source['source']['request'],'unknown')
 witness=json.loads((repo/'profiles/sageresolution/dispatch_witness.json').read_text());assert semantic_equal(e['audit'],witness,'unknown')
 assert not e['audit']['unknown'] and len(e['audit']['call_paths'])==6 and len(e['audit']['steps'])==3
 assert all(type(s['correct']) is bool and s['correct'] and s['expressions'] for s in e['audit']['steps'])
 fs=json.loads((repo/'profiles/sageresolution/dispatch.json').read_text());assert len(fs)==len(e['runtime'])==13
 assert [f['name'] for f in fs]==['plain-document','document-fragment','path-fallback','query-fallback','path-query-fallback','service-priority-path','endpoint-fragment','endpoint-without-fragment','multiple-endpoint-fragment','endpoint-existing-fragment','endpoint-empty-fragment','relationship-priority','selected-document']
 for f,v in zip(fs,e['runtime']):
  q=f['request'];doc=f['document'];accept=q.get('accept','');rel=q.get('relationship','');opts={'accept':accept} if accept else {};nested=dict(f['parameters'])
  if accept=='application/did':nested['accept']=accept
  if rel:opts['verificationRelationship']=rel;nested['verificationRelationship']=rel
  assert v['request']['request']==q and v['request']['document']['media_type']=='application/did' and semantic_equal(decoded(v['request']['document']['data']),doc,'unknown')
  assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources']
  assert len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
  assert semantic_equal(decoded(v['options']),opts,'unknown') and semantic_equal(decoded(v['resolve_options'][0]),nested,'unknown')
  assert semantic_equal(decoded(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'application/did' if accept=='application/did' else '', 'NoCache':False},'unknown')
  read=decoded(v['driver_results'][0]);assert read['ContentType']=='application/did' and semantic_equal(decoded(read['Data']),doc,'unknown')
  assert semantic_equal(decoded(v['resolved_data_model']),doc,'unknown') and decoded(v['resolved_entries'])=={}
  assert decoded(v['resolved_metadata'])=={'contentType':'application/did'}
  result=v['result'];assert not result.get('native') and not result.get('exchange') and type(result['has_content']) is bool
  if f['diagnostic_error']:
   assert not result['has_content'] and decoded(result['raw']) is None and result['metadata']['error']['type']==f['diagnostic_error']
  else:
   assert result['has_content'] and 'error' not in result['metadata'] and result['metadata']['contentType']==f['expected_media'] and result['content_kind']==f['expected_kind']
   assert semantic_equal(decoded(result['raw']),f['expected_content'],'unknown')
   if f['expected_kind']=='document':
    assert result['content_metadata']=={} and result['returned_id']=='did:example:resources'
    assert semantic_equal(decoded(v['data_model']),f['expected_content'],'unknown') and decoded(v['entries'])=={}
   elif f['expected_kind']=='verification-method':assert result['content_metadata']=={} and result['returned_id']==f['expected_content']['id']
   else:assert result['content_metadata']=={'contentType':'text/uri-list'}
 live={x['id']:x for x in report['statements']}
 for ident in IDS:assert live[ident]['verdict']=='PASS' and live[ident]['cases']==[CASE]
 for ident in PENDING:assert live[ident]['verdict']=='NOT_RUN'
 return set(IDS)
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();ids=verify_dispatch(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified',len(ids),'dispatch roles and thirteen ordinary actual calls with original models')
if __name__=='__main__':main()
