"""Advance the old pending guard only with the exact independently judged item case."""
import json
ITEM_CASE='did-1.1/sage-resolution/item-expansion-conditions'
ITEM_ID='res10-crd20261001#resolving-algorithm.29'
def verify_item_pending(raw,live,ids):
 cases=[c for c in raw['cases'] if c['case']==ITEM_CASE]
 for ident in ids:
  if ident!=ITEM_ID or not cases:
   assert live[ident]['verdict']=='NOT_RUN';continue
  assert len(cases)==1 and cases[0]['statements']==[ITEM_ID]
  obs=cases[0]['observations'];assert len(obs)==1 and obs[0]['statement']==ITEM_ID and obs[0]['verdict']=='FAIL' and obs[0]['detail'] and obs[0]['expected']
  e=json.loads(obs[0]['observed']);assert not e.get('analysis_error') and not e['proof'].get('analysis_error') and json.loads(obs[0]['input'])==e['proof']['source']['request']
  assert len(e['items'])==5
  for item in e['items']:assert item['qualifies'] is True and type(item['original']) is str and item['original'].startswith('#') and item['expected']=='did:example:123'+item['original'] and item['observed']==item['original']
  assert live[ident]['verdict']=='FAIL' and live[ident]['cases']==[ITEM_CASE]
