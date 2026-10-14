#!/usr/bin/env python3
"""Verify selected MAY capability evidence independently of the subject."""
import argparse
import json
from pathlib import Path
from check_sage_batch import jsonbytes, decode
from check_sage_choices import owned
PRODUCER='did11-cr20260305#production-and-consumption.9'
CONSUMER='did11-cr20260305#production-and-consumption.14'
PROOF='res10-crd20261001#resolver-architectures.3'
DID='did:sage:web:registry.example:agent-1'
MODEL={'id':'did:example:options'}
LD={'@context':'https://www.w3.org/ns/did/v1.1',**MODEL}
STRUCTURE=[{'type':'ExampleStructuralProof','publicFixture':'optional-return-only'}]


def verify_options(raw,report):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    cases=[c for c in raw['cases'] if '/representation-options-' in c['case']]
    expected={'producer-false','producer-true','consumer-false','consumer-true','resolver-proof'}
    assert len(cases)==len({c['case'] for c in cases})==5
    assert {c['case'].split('/representation-options-')[1] for c in cases}==expected
    live={r['id']:r for r in report['statements']};checked=set()
    for c in cases:
        name=c['case'].split('/representation-options-')[1]
        assert len(c['observations'])==1
        o=c['observations'][0]
        assert o['verdict']=='PASS' and o['detail'] and o['input'] and o['observed']
        q=json.loads(o['input']);v=json.loads(o['observed'])
        if name.startswith('producer-'):
            identifier=PRODUCER;enabled=name.endswith('true')
            assert q=={'controller_shape':'absent','version':'1.1','id':'did:example:options','controllers':None,'fields':None,'entries':None,'json_ld':enabled}
            assert not v.get('build_error') and not v.get('capture_error') and len(v['calls'])==1
            call=v['calls'][0]
            assert call['operation']=='github.com/sage-x-project/did-go/producer.Producer.Produce'
            assert call['version']=='1.1' and call['json_ld'] is enabled and call['include_secret'] is False
            assert not call.get('error') and not call.get('capture_error')
            assert jsonbytes(call['model'])==MODEL and jsonbytes(call['entries'])=={}
            assert call['media_type']=='application/did' and jsonbytes(call['output'])==(LD if enabled else MODEL)
        elif name.startswith('consumer-'):
            identifier=CONSUMER;enabled=name.endswith('true')
            assert q['require']=='1.1' and q['strict'] is enabled and set(q)=={'document','require','strict'}
            assert q['document']=={'data':q['document']['data'],'media_type':'application/did'} and jsonbytes(q['document']['data'])==LD
            assert v['operation']=='github.com/sage-x-project/did-go/consumer.Consumer.Consume' and v['input']==q['document']['data']
            assert v['media_type']=='application/did' and v['require']=='1.1' and v['expected']=='unknown' and v['strict'] is enabled
            assert not v.get('error') and not v.get('capture_error') and v['version']=='1.1' and v['json_ld'] is True
            assert jsonbytes(v['model'])==MODEL and jsonbytes(v['entries'])=={'@context':'https://www.w3.org/ns/did/v1.1'}
        else:
            identifier=PROOF
            assert len(q)==len(v)==2
            for i,(request,value) in enumerate(zip(q,v)):
                assert set(request)=={'request','post','reply'} and request['post'] is False
                assert request['request']=={'function':'resolve','input':DID,'accept':'application/did'}
                reply=jsonbytes(request['reply'])
                metadata={'contentType':'application/did'}
                if i==0:metadata['proof']=STRUCTURE
                assert reply=={'didDocument':{'id':DID},'didResolutionMetadata':metadata,'didDocumentMetadata':{}}
                assert value['request']==request and value['operation']=='github.com/sage-x-project/did-go/resolution/universal.Client.resolve'
                owned(value['endpoint'])
                assert value['server_role']=='controlled client response fixture; not SAGE server output' and value['server_tls'] is True and value['server_calls']==1
                assert len(value['wire'])==len(value['consumer'])==1 and not value['native']
                wire=value['wire'][0];consumer=value['consumer'][0]
                assert wire['url']==value['endpoint']+DID and wire['method']=='GET' and wire['accept']=='application/did'
                assert not wire['content_type'] and not decode(wire['body']) and not wire.get('capture_error')
                assert consumer['operation']=='github.com/sage-x-project/did-go/consumer.Consumer.Consume' and consumer['media_type']=='application/did'
                assert jsonbytes(consumer['input'])=={'id':DID} and consumer['require']==consumer['expected']=='unknown' and consumer['strict'] is False
                assert not consumer.get('error') and not consumer.get('capture_error')
                result=value['result'];assert result['has_content'] is True and result['returned_id']==DID
                assert isinstance(result['metadata'],dict)
                if i==0:assert result['metadata']['proof']==STRUCTURE
                # The absent control and unrelated document metadata cannot add
                # obligations to this proof-inclusion MAY. No signature oracle.
        assert o['statement']==identifier and live[identifier]['verdict']=='PASS' and c['case'] in live[identifier]['cases']
        checked.add(identifier)
    assert checked=={PRODUCER,CONSUMER,PROOF}
    return checked


def main():
    p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);args=p.parse_args();r=args.reports
    checked=verify_options(json.loads((r/'resolution-did-1.1-raw.json').read_text()),json.loads((r/'resolution-did-1.1.json').read_text()))
    print(f'Verified {len(checked)} selected additional-option/proof clauses across five actual cases')


if __name__=='__main__':main()
