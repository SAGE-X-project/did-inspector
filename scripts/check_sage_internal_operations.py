"""Verify qualifying expansion items and direct pinned multihash component calls."""
import argparse,json
from pathlib import Path
from check_sage_url_roles import verify_url_roles
from check_sage_expansion_source import CASE as EXPANSION_CASE,node
from check_sage_fragment_source import MODULE,VERSION,SUM,REPO,data
from check_sage_contracts import semantic_equal
from check_sage_service_source import decoded
from sage_item_expansion_scope import ITEM_CASE,ITEM_ID,verify_item_pending
HASH_CASE='did-1.1/sage-resolution/multihash-component-operations'
HASH_IDS=['cid10#multihash.2','cid10#multihash.3']
ROLE='Inspector-owned direct internal multiformats component probe; not a SAGE production caller'
OBSERVER={'module':MODULE+'/inspectorprobe','version':'v0.0.0','replacement':'../sageprobe','compiler':'go1.26.8','replacement_version':'(devel)','replacement_sum':''}
def verify_internal_operations(raw,report,repo=REPO):
 verify_url_roles(raw,report,repo);live={x['id']:x for x in report['statements']}
 verify_item_pending(raw,live,[ITEM_ID])
 selected=[c for c in raw['cases'] if '/item-expansion-' in c['case']];assert len(selected)==1 and selected[0]['case']==ITEM_CASE
 c=selected[0];o=c['observations'][0];e=json.loads(o['observed'])
 prior=next(c for c in raw['cases'] if c['case']==EXPANSION_CASE);proof=json.loads(prior['observations'][0]['observed'])
 assert semantic_equal(e['proof'],proof,'unknown')
 expected=[]
 for f,v in zip(json.loads((repo/'profiles/sageresolution/expansion_source.json').read_text()),proof['runtime']):
  for path in f['extension_paths']:
   parent=node(f['document'],path[:-1]);original=node(f['document'],path);want=node(f['expected'],path);actual=node(decoded(v['data_model']),path)
   assert path[-1]=='id' and type(parent) is dict and type(parent['id']) is str and parent['id']==original and original.startswith('#') and len(original)>1 and want=='did:example:123'+original and actual==original
   expected.append({'path':path,'original':original,'expected':want,'observed':actual,'qualifies':True})
 assert len(expected)==5 and semantic_equal(e['items'],expected,'unknown')
 selected=[c for c in raw['cases'] if '/multihash-component-' in c['case']];assert len(selected)==1 and selected[0]['case']==HASH_CASE and selected[0]['statements']==HASH_IDS
 c=selected[0];obs=c['observations'];assert len(obs)==2 and [o['statement'] for o in obs]==HASH_IDS and all(o['verdict']=='PASS' and o['detail'] and o['expected'] and o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
 e=json.loads(obs[0]['observed']);s=e['source'];q={'module':MODULE,'version':VERSION,'packages':['internal/multiformats'],'diagnostics':None}
 assert json.loads(obs[0]['input'])==s['request']==q and not e.get('analysis_error') and not e['call_errors']
 assert (s['module'],s['version'],s['sum'])==(MODULE,VERSION,SUM) and s['operation']==proof['source']['operation'] and s['replaced'] is False and not s['diagnostics'] and s['compiler']==s['environment_compiler']=='go1.26.8'
 assert data(s['archive'])==data(proof['source']['archive'])
 files={n:b for n,b in proof['source']['files'].items() if n.rsplit('/',1)[0]=='internal/multiformats'}
 assert len(files)==3 and semantic_equal(s['files'],files,'unknown')
 fs=json.loads((repo/'profiles/sageresolution/multihash.json').read_text());assert len(fs)==32 and set(e['calls'])=={f['name'] for f in fs}
 counts={'encode':0,'decode':0,'reject':0,'diagnostic':0};independent_lengths=0
 for f in fs:
  v=e['calls'][f['name']];q=f['request'];meta=dict(v['observer']);meta['replacement_version']='(devel)' if meta.get('replacement_version')=='' else meta.get('replacement_version')
  assert semantic_equal(v['request'],q,'unknown') and v['role']==ROLE and semantic_equal(meta,OBSERVER,'unknown') and v['operation']==MODULE+'/internal/multiformats.'+('EncodeMultihash' if q['operation']=='encode' else 'DecodeMultihash')
  if f.get('diagnostic'):counts['diagnostic']+=1;continue
  assert type(v.get('error','')) is str
  if f.get('reject'):
   counts['reject']+=1;assert v.get('error')
   b=data(q['encoded']);n={0x12:32,0x20:48,0x16:32,0x15:48}[b[0]]
   if b[1]==len(b)-2 and b[1]!=n:independent_lengths+=1
   continue
  assert not v.get('error')
  if q['operation']=='encode':counts['encode']+=1;assert data(v['encoded'])==data(f['expected_encoded'])
  else:counts['decode']+=1;assert type(v['code']) is int and v['code']==f['expected_code'] and data(v['digest'])==data(f['expected_digest'])
 assert counts=={'encode':4,'decode':4,'reject':20,'diagnostic':4} and independent_lengths==8
 for ident in HASH_IDS:assert live[ident]['verdict']=='PASS' and live[ident]['cases']==[HASH_CASE]
 verify_item_pending(raw,live,['res10-crd20261001#resolving-algorithm.26','res10-crd20261001#dereferencing-algorithm-fragment.3'])
 return {ITEM_ID,*HASH_IDS}
def main():
 p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args();verify_internal_operations(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()));print('Verified five qualifying object ids, preserved traversal finding and 32 pinned direct component calls with eight independent expected-length controls')
if __name__=='__main__':main()
