"""Independently check bounded extension receipts; never infer SAGE method support."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from check_sage_internal_operations import verify_internal_operations
from check_sage_internal_boundaries import parsed, data
from check_sage_contracts import semantic_equal
REPO=Path(__file__).resolve().parents[1]
MODULE='github.com/sage-x-project/did-go'
BASE='cid10#multibase-0.1'
HASH='cid10#multihash.1'
APP='res10-crd20261001#dereferencing-algorithm-resource.48'
IDS={BASE,HASH,APP}
PREFIX='did-1.1/sage-resolution/extension-'
OBSERVER={'module':MODULE+'/inspectorprobe','version':'v0.0.0','replacement':'../sageprobe','replacement_version':'(devel)','replacement_sum':'','compiler':'go1.26.8'}
ROLE='Inspector-owned direct internal multiformats component probe; not a SAGE production caller'
DID='did:example:resources'
URL=DID+'/public-resource'
DOC={'@context':'https://www.w3.org/ns/did/v1.1','id':DID}
MODEL={'id':DID}
ENTRIES={'@context':DOC['@context']}
RESOURCE={'id':URL,'label':'public application resource'}
REFERENCE_SHA='d30c8e2bb1bb13d679bf776e24727537548a4ff30398de6ad3f4109593a9a0b5'

def same(a,b):
    assert semantic_equal(a,b,'unknown')

def encoded(b):
    return base64.b64encode(b).decode()

def fixtures():
    bases=[]
    for header,value in [(122,'z1ftS'),(117,'uAf7_'),(102,'f0001feff')]:
        bases.extend([{'operation':'encode','header':header,'data':'AAH+/w==','encoded':''},{'operation':'decode','header':0,'data':None,'encoded':value}])
    hashes=[]
    for code,length in [(0x12,32),(0x20,48),(0x16,32),(0x15,48),(0x13,64)]:
        digest=bytes(range(length));wire=bytes([code,length])+digest
        hashes.extend([{'operation':'encode','code':code,'digest':encoded(digest),'encoded':None},{'operation':'decode','code':0,'digest':None,'encoded':encoded(wire)}])
    return bases,hashes

def verify_codecs(e):
    assert not any(e.get(k) for k in ['capture_error','multibase_capture_error','multihash_capture_error'])
    for name,qs,start,refusal in [('multibase',fixtures()[0],4,"multiformats: header 'f' is not defined by CID 1.0"),('multihash',fixtures()[1],8,'multiformats: Multihash header 0x13 is not defined by CID 1.0')]:
        vs=e[name];assert len(vs)==len(qs)
        for i,(q,v) in enumerate(zip(qs,vs)):
            same(v['request'],q)
            observer=dict(v['observer'])
            assert type(observer['replacement_version']) is str and observer['replacement_version'] in ['', '(devel)']
            observer['replacement_version']='(devel)';same(observer,OBSERVER)
            assert v['role']==ROLE and v['operation']==MODULE+'/internal/multiformats.'+('Encode' if i%2==0 else 'Decode')+('Multibase' if name=='multibase' else 'Multihash')
            if i>=start:
                assert v['error']==refusal
                assert not v.get('encoded') and not v.get('data') and not v.get('digest')
                field='header' if name=='multibase' else 'code'
                assert type(v[field]) is int and v[field]==(102 if name=='multibase' and i%2 else 0)
            else:
                assert not v.get('error')
                if i%2==1:assert not v.get('encoded')
                if i%2==0:same(v['encoded'],qs[i+1]['encoded'])
                elif name=='multibase':
                    assert type(v['header']) is int and v['header']==qs[i-1]['header'];assert data(v['data'])==bytes([0,1,254,255])
                else:
                    assert type(v['code']) is int and v['code']==qs[i-1]['code'];assert data(v['digest'])==data(qs[i-1]['digest'])

def requests():
    return [{'application_handler':mode,'document':{'data':encoded(json.dumps(DOC,separators=(',',':')).encode()),'media_type':'application/did'},'request':{'function':'dereference','input':URL if i<3 else DID}} for i,mode in enumerate(['handled','unhandled','','handled'])]

def verify_application(qs,vs):
    assert len(qs)==len(vs)==4
    for i,(q,v) in enumerate(zip(qs,vs)):
        expected=requests()[i]
        # Omitted Go zero fields remain semantically empty; booleans stay typed.
        assert q.get('application_handler','')==expected['application_handler']
        same(q['request'],expected['request']);assert parsed(q['document']['data'])==DOC and q['document']['media_type']=='application/did'
        assert all(k not in q or q[k] is False for k in ['plain_json_fragment','observe_production','observe_resource_handler'])
        same(v['request'],q)
        assert v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source' and not v.get('capture_error')
        assert v['resolve_inputs']==v['driver_inputs']==[DID] and len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==len(v['consumption'])==1
        assert not v.get('production') and not v.get('resource_handler') and parsed(v['options'])==parsed(v['resolve_options'][0])=={}
        same(parsed(v['driver_options'][0]),{'VersionID':'','VersionTime':None,'MediaType':'','NoCache':False})
        driver=parsed(v['driver_results'][0]);assert driver['ContentType']=='application/did' and parsed(driver['Data'])==DOC and driver['Metadata']=={}
        c=v['consumption'][0]
        assert c['operation']==MODULE+'/consumer.Consumer.Consume' and c['media_type']=='application/did' and c['require']==c['expected']=='unknown' and c['strict'] is False and c['version']=='1.1' and c['json_ld'] is True
        assert not c.get('error') and not c.get('capture_error') and not c.get('dropped_terms') and parsed(c['input'])==DOC
        assert parsed(c['model'])==parsed(v['data_model'])==parsed(v['resolved_data_model'])==MODEL and parsed(c['entries'])==parsed(v['entries'])==parsed(v['resolved_entries'])==ENTRIES
        assert parsed(v['resolved_metadata'])=={'contentType':'application/did'}
        result=v['result'];assert not result.get('native') and not result.get('exchange')
        handlers=v.get('application_handler') or [];assert len(handlers)==(1 if i<2 else 0)
        if i<2:
            h=handlers[0];a=h['input'];assert a['operation']==MODULE+'/dereferencer.ResourceHandler' and a['role']=='explicit controlled application callback; not SAGE method support' and not a.get('capture_error')
            same(a['url'],{'input':URL,'primary':URL,'path':'/public-resource','query':'','fragment':'','has_fragment':False,'has_query':False})
            assert parsed(a['options'])=={} and parsed(a['model'])==MODEL and parsed(a['entries'])==ENTRIES and parsed(a['metadata'])=={'contentType':'application/did'}
            assert h['handled'] is (i==0)
            if i==0:
                for r in [h['returned'],result]:
                    same(r['snapshot'],RESOURCE)
                    assert r['has_content'] is True and r['content_kind']=='map' and r['returned_id']==URL and parsed(r['raw'])==RESOURCE and r['metadata']=={'contentType':'application/json'} and r['content_metadata']=={'versionId':'application-1'} and not r.get('native') and not r.get('exchange')
            else:
                r=h['returned'];assert r['has_content'] is False and parsed(r['raw']) is None and r['metadata']==r['content_metadata']=={}
        if 0<i<3:assert result['has_content'] is False and parsed(result['raw']) is None and result['metadata']['error']['type']=='https://www.w3.org/ns/did#NOT_FOUND'
        elif i==3:assert result['has_content'] is True and result['content_kind']=='document' and result['returned_id']==DID and result['metadata']=={'contentType':'application/did'}

def verify_extensions(raw,report,repo=REPO):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    assert hashlib.sha256((repo/'docs/sage-extension-references.json').read_bytes()).hexdigest()==REFERENCE_SHA
    verify_internal_operations(raw,report,repo)
    selected=[c for c in raw['cases'] if '/extension-' in c['case']]
    assert len(selected)==2 and {c['case'] for c in selected}=={PREFIX+'codecs',PREFIX+'application-handler'}
    live={r['id']:r for r in report['statements']}
    for c in selected:
        ids=[BASE,HASH] if c['case'].endswith('codecs') else [APP]
        verdict='NOT_SUPPORTED' if len(ids)==2 else 'PASS'
        obs=c['observations'];assert c['statements']==ids and [o['statement'] for o in obs]==ids
        assert all(o['verdict']==verdict and o['input'] and o['observed'] and o['detail'] and o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
        q=json.loads(obs[0]['input']);e=json.loads(obs[0]['observed'])
        if len(ids)==2:
            prior=next(c for c in raw['cases'] if c['case']=='did-1.1/sage-resolution/multihash-component-operations')
            source=json.loads(prior['observations'][0]['observed'])['source'];same(e['source'],source);same(q,source['request']);verify_codecs(e)
        else:verify_application(q,e)
        for ident in ids:assert live[ident]['verdict']==verdict and c['case'] in live[ident]['cases']
    return IDS

def main():
    p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args()
    raw=json.loads((a.reports/'resolution-did-1.1-raw.json').read_text());report=json.loads((a.reports/'resolution-did-1.1.json').read_text())
    print('Verified',len(verify_extensions(raw,report)),'selected extension clauses: six base calls, ten hash calls and four actual dispatcher calls')
if __name__=='__main__':main()
