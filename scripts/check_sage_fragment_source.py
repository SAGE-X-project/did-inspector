#!/usr/bin/env python3
"""Check fixed-source fragment binding evidence and its literal runtime receipts.

The Go observer resolves typed source symbols. This checker verifies bytes,
reviewed witness and omissions; it does not independently parse Go or attest
that cache bytes are verbatim compiled binary bytes.
"""
from sage_internal_boundary_scope import verify_internal_pending
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import zipfile

from check_sage_contracts import semantic_equal

REPO=Path(__file__).resolve().parents[1]
IDS=['cid10#fragment-resolution.2','cid10#fragment-resolution.3','cid10#fragment-resolution.5']
CASE='did-1.1/sage-resolution/fragment-source-bindings'
MODULE='github.com/sage-x-project/did-go'
VERSION='v0.0.0-20261012015322-ed54c505eafe'
SUM='h1:phZzJEVaBYD9ylcNhmODNZ4mSp3N4j/4HwILUmFWnrE='
PACKAGES=['dereferencer','did','document','internal/multiformats','representation','resolution','spec','vm']


def data(value):
    return base64.b64decode(value,validate=True)


def verify_fragment_source(raw,report,repo=REPO):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    cases=[c for c in raw['cases'] if '/fragment-source-' in c['case']]
    assert len(cases)==1 and cases[0]['case']==CASE
    obs=cases[0]['observations'];assert len(obs)==3 and [o['statement'] for o in obs]==IDS
    assert all(o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
    e=json.loads(obs[0]['observed']);s=e['source'];q=json.loads(obs[0]['input'])
    assert q==s['request']=={'module':MODULE,'version':VERSION,'packages':PACKAGES,'diagnostics':None}
    assert (s['module'],s['version'],s['sum'])==(MODULE,VERSION,SUM)
    assert s['operation']=='debug.ReadBuildInfo + local go env + module cache/ZIP byte capture'
    assert s['replaced'] is False and not s['diagnostics'] and not e.get('analysis_error')
    assert s['compiler']==s['environment_compiler']==e['type_checker_compiler']=='go1.26.8'
    assert e['type_checker_architecture'] in ['arm64','amd64']
    prefix=MODULE+'@'+VERSION+'/'
    with zipfile.ZipFile(io.BytesIO(data(s['archive']))) as z:
        names=z.namelist();assert names and len(names)==len(set(names))
        assert all(n.startswith(prefix) and '\n' not in n and '\r' not in n for n in names)
        files={n:z.read(n) for n in names}
    digest=''.join(hashlib.sha256(files[n]).hexdigest()+'  '+n+'\n' for n in sorted(files))
    assert 'h1:'+base64.b64encode(hashlib.sha256(digest.encode()).digest()).decode()==SUM
    selected={n[len(prefix):]:b for n,b in files.items() if n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
    assert len(selected)==38 and set(selected)==set(s['files'])
    assert all(data(s['files'][n])==b for n,b in selected.items())
    witness=json.loads((repo/'profiles/sageresolution/fragment_source_witness.json').read_text())
    assert semantic_equal(e['audit'],witness,'unknown') and not witness['unknown'] and len(witness['steps'])==3
    assert len(witness['call_paths'])==3 and len(witness['roles'])==4 and len(witness['scope'])==4
    assert all(step['correct'] is True and step['expressions'] for step in witness['steps'])
    assert MODULE+'/resolution.ErrorDereferenceResult' in witness['frames']
    fixtures=[f for f in json.loads((repo/'profiles/sageresolution/resource_choices.json').read_text()) if f['name'] in ['nested-full','nested-relative']]
    assert len(fixtures)==len(e['runtime'])==2
    for f,values in zip(fixtures,e['runtime']):
        assert len(values)==2
        for request,v in zip(f['requests'],values):
            assert v['request']['request']==request and json.loads(data(v['request']['document']['data']))==f['document'] and v['request']['document']['media_type']=='application/did'
            assert v['role']=='root resolver/dereferencer library with literal example driver; not SAGE Source'
            assert v['operation']==MODULE+'/dereferencer.Dereferencer.Dereference' and not v.get('capture_error')
            assert v['resolve_inputs']==v['driver_inputs']==['did:example:resources']
            assert len(v['resolve_options'])==len(v['driver_options'])==len(v['driver_results'])==1
            assert json.loads(data(v['options']))=={'accept':'application/did'}
            assert json.loads(data(v['driver_options'][0]))=={'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False}
            record=json.loads(data(v['driver_results'][0]));assert record['ContentType']=='application/did' and json.loads(data(record['Data']))==f['document']
            assert not v['result'].get('native') and not v['result'].get('exchange')
        good,miss=[v['result'] for v in values]
        assert good['has_content'] and good['content_kind']=='map' and good['returned_id']==f['expected_id']
        assert semantic_equal(json.loads(data(good['raw'])),f['expected_content'],'unknown')
        metadata=good['metadata'];assert 'error' not in metadata and metadata['contentType']==f['expected_media']
        assert not miss['has_content'] and json.loads(data(miss['raw'])) is None
        assert miss['metadata']['error']['type']=='https://www.w3.org/ns/did#NOT_FOUND'
    live={r['id']:r for r in report['statements']}
    for o in obs:
        assert o['verdict']==live[o['statement']]['verdict']=='PASS' and o['detail'] and o['expected']
        assert CASE in live[o['statement']]['cases']
    for ident in ['cid10#base-encode.4','cid10#base-decode.5']:
        verify_internal_pending(raw,live,ident)
    for ident,prefix,wanted in [('cid10#fragment-resolution.1','/fragment-initial-','PASS'),('cid10#fragment-resolution.4','/fragment-search-','FAIL')]:
        linked=[c['case'] for c in raw['cases'] if prefix in c['case']]
        assert live[ident]['verdict']==(wanted if linked else 'NOT_RUN')
        if linked: assert set(live[ident]['cases'])==set(linked)
    return set(IDS)


def main():
    p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);a=p.parse_args()
    ids=verify_fragment_source(json.loads((a.reports/'resolution-did-1.1-raw.json').read_text()),json.loads((a.reports/'resolution-did-1.1.json').read_text()))
    print(f'Verified {len(ids)} fragment source bindings, 38 cache files and four literal runtime calls')

if __name__=='__main__':main()
