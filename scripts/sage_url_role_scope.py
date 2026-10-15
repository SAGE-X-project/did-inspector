"""Preserve older pending guards until exact new URL observations exist."""
from sage_internal_boundary_scope import MEDIA_ID,verify_internal_pending
CASE='did-1.1/sage-resolution/url-source-roles'
VERDICTS={'res10-crd20261001#dereferencing-algorithm-resource.11':'FAIL','cid10#retrieve-verification-method.3':'PASS'}
def verify_url_pending(raw,live,ids):
 selected=[c for c in raw['cases'] if c['case']==CASE]
 for ident in ids:
  if ident==MEDIA_ID:
   verify_internal_pending(raw,live,ident);continue
  if ident in VERDICTS and selected:
   assert len(selected)==1 and selected[0]['statements']==list(VERDICTS)
   obs=selected[0]['observations'];assert len(obs)==2 and [o['statement'] for o in obs]==list(VERDICTS)
   o=next(o for o in obs if o['statement']==ident)
   assert o['verdict']==live[ident]['verdict']==VERDICTS[ident] and o['input'] and o['observed'] and o['detail']
   assert live[ident]['cases']==[CASE]
  else:assert live[ident]['verdict']=='NOT_RUN'
