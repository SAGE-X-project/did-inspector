"""Keep the old pending guard unless the exact same-call minimal class is proved."""
import base64,json
REPRESENTATION_ID='res10-crd20261001#resolving-algorithm.26'
REPRESENTATION_CASE='did-1.1/sage-resolution/returned-minimal-representation'
MODULE='github.com/sage-x-project/did-go'
VERSION='v0.0.0-20261012015322-ed54c505eafe'
SUM='h1:phZzJEVaBYD9ylcNhmODNZ4mSp3N4j/4HwILUmFWnrE='
PACKAGES=['resolver','consumer','producer','representation']
LITERALS=[b'{"id":"did:example:123"}',b' { \n "id" : "did:example:123" } \n']
def data(value):return base64.b64decode(value,validate=True)
def unique(pairs):
 assert len({k for k,_ in pairs})==len(pairs)
 return dict(pairs)
def parsed(value):return json.loads(data(value).decode('utf-8'),object_pairs_hook=unique)
def verify_representation_pending(raw,live):
 cases=[c for c in raw['cases'] if c['case']==REPRESENTATION_CASE]
 if not cases:assert live[REPRESENTATION_ID]['verdict']=='NOT_RUN';return
 assert len(cases)==1 and cases[0]['statements']==[REPRESENTATION_ID]
 obs=cases[0]['observations'];assert len(obs)==1
 o=obs[0];assert o['statement']==REPRESENTATION_ID and o['verdict']=='PASS' and o['detail'] and o['expected']
 e=json.loads(o['observed']);source=e['source'];q={'module':MODULE,'version':VERSION,'packages':PACKAGES,'diagnostics':None}
 assert json.loads(o['input'])==source['request']==q and len(e['runtime'])==2
 assert (source['module'],source['version'],source['sum'])==(MODULE,VERSION,SUM) and source['replaced'] is False and not source['diagnostics']
 assert source['compiler']==source['environment_compiler']=='go1.26.8' and source['operation']=='debug.ReadBuildInfo + local go env + module cache/ZIP byte capture'
 model={'id':'did:example:123'};options={'accept':'application/did+json'};metadata={'contentType':'application/did+json'}
 for literal,v in zip(LITERALS,e['runtime']):
  request={'observe_production':True,'document':{'data':base64.b64encode(literal).decode(),'media_type':'application/did'},'request':{'function':'resolve','input':'did:example:123','accept':'application/did+json'}}
  assert v['request']==request and v['request']['observe_production'] is True
  assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and v['operation']==MODULE+'/resolver.DefaultResolver.Resolve' and not v.get('capture_error') and not v.get('resource_handler')
  assert v['resolve_inputs']==v['driver_inputs']==['did:example:123'] and len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
  assert parsed(v['options'])==parsed(v['resolve_options'][0])==options and data(v['options'])==data(v['resolve_options'][0])
  driver_options=parsed(v['driver_options'][0]);assert driver_options=={'VersionID':'','VersionTime':None,'MediaType':'','NoCache':False} and driver_options['NoCache'] is False
  driver=parsed(v['driver_results'][0]);assert data(driver['Data'])==literal and driver['ContentType']=='application/did' and driver['Metadata']=={}
  assert len(v['consumption'])==len(v['production'])==1
  c,p=v['consumption'][0],v['production'][0]
  assert c['operation']==MODULE+'/consumer.Consumer.Consume' and data(c['input'])==literal and c['media_type']=='application/did' and c['require']==c['expected']=='unknown'
  assert c['strict'] is False and c['version']=='1.1' and c['json_ld'] is False and not c['dropped_terms'] and not c.get('error') and not c.get('capture_error')
  assert p['operation']==MODULE+'/producer.Producer.Produce' and p['version']=='1.0' and p['json_ld'] is False and p['include_secret'] is False and not p.get('error') and not p.get('capture_error')
  result=v['result'];assert result['has_content'] is True and result['content_kind']=='document' and result['returned_id']=='did:example:123' and not result.get('sage_code') and not result.get('native') and not result.get('exchange')
  assert parsed(c['model'])==parsed(p['model'])==parsed(v['data_model'])==parsed(v['resolved_data_model'])==result['snapshot']==model
  assert parsed(c['entries'])==parsed(p['entries'])==parsed(v['entries'])==parsed(v['resolved_entries'])==result['content_metadata']=={}
  assert result['metadata']==parsed(v['resolved_metadata'])==metadata and p['media_type']=='application/did+json'
  assert data(p['output'])==data(result['raw']) and parsed(result['raw'])==model
 assert live[REPRESENTATION_ID]['verdict']=='PASS' and live[REPRESENTATION_ID]['cases']==[REPRESENTATION_CASE]
