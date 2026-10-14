#!/usr/bin/env python3
"""Verify selected native resource and DID parameter capability evidence."""
import argparse
import json
from pathlib import Path
from check_sage_batch import btc, jsonbytes
from check_sage_contracts import semantic_equal
RESOURCE='res10-crd20261001#dereferencing.9'
PARAMETERS='res10-crd20261001#did-parameters.2'
DID='did:example:resources'
ROLE='root resolver/dereferencer library with literal example driver; not SAGE Source'


def fixtures():
    key=btc(bytes.fromhex('ed01d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'))
    method={'id':DID+'#sign','type':'Multikey','controller':DID,'publicKeyMultibase':key}
    embedded={**method,'id':DID+'#embedded'}
    one={'id':'#one','type':'Messaging','serviceEndpoint':'https://agent.example/base/'}
    two={'id':'#two','type':'Other','serviceEndpoint':'https://agent.example/other/'}
    full={'id':DID+'#nested','values':['first',{'count':2},False]};short={'id':'#short','label':'nested relative fragment'}
    document={'id':DID,'verificationMethod':[method],'authentication':[embedded],'service':[one,two],'extension':{'container':[{'child':full},short]}}
    rows={}
    for name,fragment,kind,value,identifier,media in [('document','','document',document,DID,'application/did'),('method','#sign','verification-method',method,DID+'#sign','application/ld+json'),('embedded-method','#embedded','verification-method',embedded,DID+'#embedded','application/ld+json'),('service','#one','service',one,'#one','application/ld+json'),('nested-full','#nested','map',full,DID+'#nested','application/ld+json'),('nested-relative','#short','map',short,'#short','application/ld+json')]:
        rows[name]={'name':name,'statement':RESOURCE,'document':document,'requests':[{'function':'dereference','input':DID+fragment,'accept':'application/did'},{'function':'dereference','input':DID+'#missing-control','accept':'application/did'}],'expected_content':value,'expected_kind':kind,'expected_id':identifier,'expected_media':media,'expected_parameters':{}}
    for name,query,parameters,value,kind,identifier,media in [('parameter-service','?service=one',{'service':'one'},{**document,'service':[one]},'document',DID,'application/did'),('parameter-service-type','?serviceType=Messaging',{'serviceType':'Messaging'},{**document,'service':[one]},'document',DID,'application/did'),('parameter-relative-reference','?service=one&relativeRef=..%2Fsend',{'service':'one','relativeRef':'../send'},['https://agent.example/send'],'uri-list','','text/uri-list')]:
        rows[name]={'name':name,'statement':PARAMETERS,'document':document,'requests':[{'function':'dereference','input':DID+query,'accept':media},{'function':'dereference','input':DID,'accept':'application/did'}],'expected_content':value,'expected_kind':kind,'expected_id':identifier,'expected_media':media,'expected_parameters':parameters}
    return rows


def verify_resources(raw,report):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    cases=[c for c in raw['cases'] if '/resource-choice-' in c['case']];expected=fixtures()
    assert len(cases)==len({c['case'] for c in cases})==9
    assert {c['case'].split('/resource-choice-')[1] for c in cases}==set(expected)
    live={r['id']:r for r in report['statements']};checked=set()
    for c in cases:
        name=c['case'].split('/resource-choice-')[1];f=expected[name]
        assert len(c['observations'])==1;o=c['observations'][0]
        assert o['statement']==f['statement'] and o['verdict']=='PASS' and o['detail'] and o['input'] and o['observed']
        q=json.loads(o['input']);values=json.loads(o['observed']);assert q==f and len(values)==2
        for i,v in enumerate(values):
            assert v['role']==ROLE and v['operation']=='github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
            assert v['request']['request']==f['requests'][i] and v['request']['document']['media_type']=='application/did'
            assert jsonbytes(v['request']['document']['data'])==f['document']
            assert v['resolve_inputs']==v['driver_inputs']==[DID] and len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
            assert jsonbytes(v['options'])=={'accept':f['requests'][i]['accept']}
            assert isinstance(jsonbytes(v['resolve_options'][0]),dict)
            # Nested option values have their own mandatory forwarding check;
            # they cannot change this MAY/OPTIONAL selected-output verdict.
            driver=jsonbytes(v['driver_options'][0]);media='application/did' if f['requests'][i]['accept']=='application/did' else ''
            assert driver=={'VersionID':'','VersionTime':None,'MediaType':media,'NoCache':False}
            read=jsonbytes(v['driver_results'][0]);assert read['ContentType']=='application/did' and jsonbytes(read['Data'])==f['document']
            assert not v['result'].get('native') and not v['result'].get('exchange')
        v=values[0];result=v['result']
        assert result['has_content'] is True and result['content_kind']==f['expected_kind'] and result.get('returned_id','')==f['expected_id']
        assert result['metadata']['contentType']==f['expected_media'] and 'error' not in result['metadata']
        assert isinstance(result['content_metadata'],dict)
        content=jsonbytes(result['raw']);kind=f['expected_kind']
        if kind=='document':
            assert jsonbytes(v['entries'])=={};model=jsonbytes(v['data_model']);assert semantic_equal(model,f['expected_content'],'document')
        if kind=='uri-list':assert result['content_metadata']['contentType']=='text/uri-list'
        assert semantic_equal(content,f['expected_content'],'document' if kind=='document' else 'method' if kind=='verification-method' else 'service' if kind=='service' else 'unknown')
        # Control output is diagnostic only, but its actual call is attributable.
        identifier=f['statement'];assert live[identifier]['verdict']=='PASS' and c['case'] in live[identifier]['cases'];checked.add(identifier)
    assert checked=={RESOURCE,PARAMETERS}
    return checked


def main():
    p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);args=p.parse_args();r=args.reports
    ids=verify_resources(json.loads((r/'resolution-did-1.1-raw.json').read_text()),json.loads((r/'resolution-did-1.1.json').read_text()))
    print(f'Verified {len(ids)} selected resource/parameter clauses across nine actual cases')


if __name__=='__main__':main()
