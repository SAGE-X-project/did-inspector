"""Validate bounded typed relationship source roles and normal actual receipts."""
from sage_url_role_scope import verify_url_pending
import argparse,base64,json
from pathlib import Path
from check_sage_contracts import semantic_equal
from check_sage_fragment_source import verify_fragment_source,CASE as SOURCE,MODULE
REPO=Path(__file__).resolve().parents[1]
CASE='did-1.1/sage-resolution/fragment-relationship-source'
IDS=['res10-crd20261001#dereferencing-algorithm-fragment.1','res10-crd20261001#dereferencing-algorithm-fragment.2']
def decoded(v):return json.loads(base64.b64decode(v,validate=True))
def verify_relationship(raw,report,repo=REPO):
 verify_fragment_source(raw,report,repo)
 selected=[c for c in raw['cases'] if '/fragment-relationship-' in c['case']];assert len(selected)==1
 c=selected[0];assert c['case']==CASE and c['statements']==IDS and len(c['observations'])==2
 o=c['observations'];assert [x['statement'] for x in o]==IDS
 assert all(x['verdict']=='PASS' and x['detail'] and x['expected'] and x['observed']==o[0]['observed'] and x['input']==o[0]['input'] for x in o)
 e=json.loads(o[0]['observed']);source=json.loads(next(c for c in raw['cases'] if c['case']==SOURCE)['observations'][0]['observed'])
 assert semantic_equal(e['source_evidence'],source,'unknown') and semantic_equal(json.loads(o[0]['input']),source['source']['request'],'unknown')
 witness=json.loads((repo/'profiles/sageresolution/fragment_relationship_witness.json').read_text());assert semantic_equal(e['audit'],witness,'unknown')
 assert all(type(s['correct']) is bool and s['correct'] for s in e['audit']['steps'])
 fs=json.loads((repo/'profiles/sageresolution/fragment_relationship.json').read_text());assert len(fs)==len(e['runtime'])==5
 assert [f['name'] for f in fs]==['referenced','embedded','other-relationship','no-fragment','without-relationship']
 for f,v in zip(fs,e['runtime']):
  q=f['request'];doc=f['document'];opts={'accept':'application/did'}
  if q.get('relationship'):opts['verificationRelationship']=q['relationship']
  assert v['request']['request']==q and v['request']['document']['media_type']=='application/did' and semantic_equal(decoded(v['request']['document']['data']),doc,'unknown')
  assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources']
  assert len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
  assert semantic_equal(decoded(v['options']),opts,'unknown') and semantic_equal(decoded(v['resolve_options'][0]),opts,'unknown')
  assert semantic_equal(decoded(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False},'unknown')
  read=decoded(v['driver_results'][0]);assert read['ContentType']=='application/did' and semantic_equal(decoded(read['Data']),doc,'unknown')
  assert semantic_equal(decoded(v['data_model']),doc,'unknown') and decoded(v['entries'])=={}
  r=v['result'];assert not r.get('native') and not r.get('exchange') and type(r['has_content']) is bool and r['content_metadata']=={}
  if f['diagnostic_error']:assert not r['has_content'] and decoded(r['raw']) is None and r['metadata']['error']['type']=='https://w3id.org/security#'+f['diagnostic_error']
  else:
   assert r['has_content'] and 'error' not in r['metadata'] and r['metadata']['contentType']=='application/ld+json' and r['content_kind']==f['expected_kind'] and r['returned_id']==f['expected_content']['id']
   assert semantic_equal(decoded(r['raw']),f['expected_content'],'method' if f['expected_kind']=='verification-method' else 'unknown')
 live={x['id']:x for x in report['statements']}
 for ident in IDS:assert live[ident]['verdict']=='PASS' and live[ident]['cases']==[CASE]
 verify_url_pending(raw,live,['cid10#retrieve-verification-method.3','res10-crd20261001#dereferencing-algorithm-fragment.3','res10-crd20261001#dereferencing-algorithm-resource.11'])
 return set(IDS)
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();ids=verify_relationship(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified',len(ids),'typed relationship roles and five ordinary actual calls')
if __name__=='__main__':main()
