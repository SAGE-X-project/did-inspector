"""Advance earlier guards only with exact new independently checked cases."""
CAPACITY_IDS=['cid10#base-encode.4','cid10#base-decode.5']
MEDIA_ID='res10-crd20261001#dereferencing-algorithm-fragment.3'
CONTEXT_ID='cid10#context-injection.1'
CASES={**{i:'did-1.1/sage-resolution/capacity-u64-component' for i in CAPACITY_IDS},MEDIA_ID:'did-1.1/sage-resolution/fragment-plain-json-media',CONTEXT_ID:'did-1.1/sage-resolution/context-injection-no-context'}
def verify_internal_pending(raw,live,ident):
 cases=[c for c in raw['cases'] if c['case']==CASES[ident]]
 if not cases:assert live[ident]['verdict']=='NOT_RUN';return
 assert len(cases)==1 and ident in cases[0]['statements']
 obs=[o for o in cases[0]['observations'] if o['statement']==ident];assert len(obs)==1
 o=obs[0];assert o['verdict']=='PASS' and o['input'] and o['observed'] and o['detail'] and o['expected']
 assert live[ident]['verdict']=='PASS' and live[ident]['cases']==[CASES[ident]]
