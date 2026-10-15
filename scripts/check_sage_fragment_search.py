#!/usr/bin/env python3
"""Verify initial-state role receipts and benign recursive-search evidence.

Go result initialization is an explicit language premise, not a physical
trace. The search oracle walks every map in the fixed typed input independently
of the subject. NOT_FOUND is a pinned diagnostic, not a CID-required error code.
"""
import argparse
import base64
import json
from pathlib import Path
from check_sage_contracts import semantic_equal
from check_sage_fragment_source import verify_fragment_source, CASE, MODULE

REPO=Path(__file__).resolve().parents[1]
INITIAL='did-1.1/sage-resolution/fragment-initial-source'
PREFIX='did-1.1/sage-resolution/fragment-search-'
IDS=['cid10#fragment-resolution.1','cid10#fragment-resolution.4']
RULE="https://go.dev/ref/spec#Return_statements; function-entry result values have their type's zero value"


def decoded(v):
    return json.loads(base64.b64decode(v,validate=True))


def matches(v,full='did:example:resources#target',short='#target'):
    out=[]
    if isinstance(v,dict):
        if isinstance(v.get('id'),str) and v['id'] in [full,short]:out.append(v)
        for value in v.values():out.extend(matches(value,full,short))
    elif isinstance(v,list):
        for value in v:out.extend(matches(value,full,short))
    return out


def match_result(result,want):
    return result.get('has_content') and result.get('content_kind')=='map' and result.get('returned_id')==want['id'] and 'error' not in result['metadata'] and result['metadata'].get('contentType')=='application/ld+json' and result['content_metadata']=={} and semantic_equal(decoded(result['raw']),want,'unknown')


def verify_fragment_search(raw,report,repo=REPO):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    verify_fragment_source(raw,report,repo)
    cases={c['case']:c for c in raw['cases']};assert len(cases)==len(raw['cases'])
    live={r['id']:r for r in report['statements']}
    original=json.loads(cases[CASE]['observations'][0]['observed'])
    initial=cases[INITIAL];assert initial['statements']==[IDS[0]] and len(initial['observations'])==1
    o=initial['observations'][0];assert o['statement']==IDS[0] and o['verdict']=='PASS' and o['detail'] and o['expected']
    e=json.loads(o['observed']);a=e['initial']
    assert json.loads(o['input'])==original['source']['request']
    # Both fresh source captures must bind the same canonical bytes, caller and
    # corroborating literals; this equality is not an initial-value oracle.
    assert semantic_equal(e['source_evidence'],original,'unknown') and semantic_equal(a['binding'],original['audit'],'unknown')
    assert a['search']==MODULE+'/dereferencer.findFragment' and a['unknown']==[]
    assert a['result_types']==['any','bool'] and a['result_roles']==['found','ok']
    assert a['initial_values']==['nil interface (no fragment)','false (no match)'] and a['language_rule']==RULE
    assert live[IDS[0]]['verdict']=='PASS' and live[IDS[0]]['cases']==[INITIAL]
    fixtures=json.loads((repo/'profiles/sageresolution/fragment_search.json').read_text())
    assert len(fixtures)==5 and {f['name'] for f in fixtures}=={'extension-list','method-extra','embedded-extra','service-extra','endpoint-map'}
    selected={name:c for name,c in cases.items() if name.startswith(PREFIX)}
    assert set(selected)=={PREFIX+f['name'] for f in fixtures}
    for f in fixtures:
        c=selected[PREFIX+f['name']];assert c['statements']==[IDS[1]] and len(c['observations'])==1
        o=c['observations'][0];expected='PASS' if f['name']=='extension-list' else 'FAIL'
        assert o['statement']==IDS[1] and o['verdict']==expected and o['detail'] and o['expected'] and semantic_equal(json.loads(o['input']),f,'unknown')
        values=json.loads(o['observed']);assert len(values)==3
        for i,v in enumerate(values):
            doc=f['control_document'] if i==1 else f['document'];q=dict(f['request'])
            if i==2:q['input']='did:example:resources#absent'
            assert v['request']['request']==q and v['request']['document']['media_type']=='application/did' and semantic_equal(decoded(v['request']['document']['data']),doc,'unknown')
            assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
            assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources']
            assert len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
            assert decoded(v['options'])==decoded(v['resolve_options'][0])=={'accept':'application/did'}
            assert semantic_equal(decoded(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False},'unknown')
            read=decoded(v['driver_results'][0]);assert read['ContentType']=='application/did' and semantic_equal(decoded(read['Data']),doc,'unknown')
            assert type(v['result']['has_content']) is bool
            assert not v['result'].get('native') and not v['result'].get('exchange')
            model=decoded(v['data_model']);assert semantic_equal(model,doc,'unknown') and decoded(v['entries'])=={}
            found=matches(model);assert len(found)==1 and semantic_equal(found[0],f['expected_content'],'unknown')
        assert match_result(values[1]['result'],f['expected_content'])
        miss=values[2]['result'];assert not miss['has_content'] and decoded(miss['raw']) is None and miss['metadata']['error']['type']=='https://www.w3.org/ns/did#NOT_FOUND'
        original=values[0]['result']
        if expected=='PASS':assert match_result(original,f['expected_content'])
        else:assert not original['has_content'] and decoded(original['raw']) is None and original['metadata']['error']['type']=='https://www.w3.org/ns/did#NOT_FOUND'
    assert live[IDS[1]]['verdict']=='FAIL' and set(live[IDS[1]]['cases'])==set(selected)
    return set(IDS)


def main():
    p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args()
    verify_fragment_search(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()))
    print('Verified typed initial-state roles and five recursive-search cases with fifteen benign same-call receipts; four misses aggregate to one finding')

if __name__=='__main__':main()
