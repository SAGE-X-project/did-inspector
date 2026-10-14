#!/usr/bin/env python3
"""Verify fixed-pin source identity and reviewed typed arithmetic artifact witness.

Go parser/types performs semantic analysis. This independent artifact check
binds ZIP/cache bytes and detects omissions or changes against the reviewed
fixed-source witness; it does not independently parse Go or attest binary bytes.
"""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import zipfile

REPO=Path(__file__).resolve().parents[1]
IDS=['cid10#base-encode.1','cid10#base-decode.1','cid10#base-encode.8','cid10#base-encode.9','cid10#base-encode.10','cid10#base-decode.9','cid10#base-decode.10','cid10#base-decode.11','cid10#base-encode.6','cid10#base-encode.11','cid10#base-decode.2','cid10#base-decode.7','cid10#base-decode.12','cid10#base-decode.13','cid10#base-encode.5','cid10#base-encode.12','cid10#base-decode.6']
CASE='did-1.1/sage-resolution/integer-source-arithmetic'
OPERATION='debug.ReadBuildInfo + local go env + module cache/ZIP byte capture'


def archive_files(encoded,prefix):
    data=base64.b64decode(encoded,validate=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names=z.namelist()
        assert len(names)==len(set(names)) and names
        assert all(n.startswith(prefix+'/') and '\n' not in n and '\r' not in n for n in names)
        files={n:z.read(n) for n in names}
    lines=''.join(hashlib.sha256(files[n]).hexdigest()+'  '+n+'\n' for n in sorted(files))
    digest='h1:'+base64.b64encode(hashlib.sha256(lines.encode()).digest()).decode()
    selected={n[len(prefix)+1:]:b for n,b in files.items() if n[len(prefix)+1:].rsplit('/',1)[0] in ['vm','did','internal/multiformats'] and n.endswith('.go') and not n.endswith('_test.go')}
    return digest,selected


def verify_integer_source(raw,report,repo=REPO):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    cases=[c for c in raw['cases'] if '/integer-source-' in c['case']]
    assert len(cases)==1 and cases[0]['case']==CASE
    observations=cases[0]['observations'];assert len(observations)==17
    assert [o['statement'] for o in observations]==IDS
    witness=json.loads((repo/'profiles/sageresolution/integer_source_witness.json').read_text())
    assert witness['schema']=='sage-integer-source-witness/1'
    assert all(o['input']==observations[0]['input'] and o['observed']==observations[0]['observed'] for o in observations)
    q=json.loads(observations[0]['input']);v=json.loads(observations[0]['observed']);s=v['source']
    assert q==s['request']==witness['request']
    for k in ['module','version','sum']:assert s[k]==witness[k]
    assert s['operation']==OPERATION and s['replaced'] is False
    assert s['compiler']==s['environment_compiler']==v['type_checker_compiler']=='go1.26.8'
    assert v['type_checker_architecture'] in ['arm64','amd64'] and not v.get('analysis_error')
    prefix=s['module']+'@'+s['version'];digest,files=archive_files(s['archive'],prefix)
    assert digest==s['sum'] and len(files)==16 and set(files)==set(s['files'])
    assert all(base64.b64decode(s['files'][n],validate=True)==b for n,b in files.items())
    assert hashlib.sha256(files['internal/multiformats/base.go']).hexdigest()=='42e24ce29efbe606550c0d118081f35606c0c976c80a2b48a2f807084900708e'
    assert v['call_paths']==[[s['module']+'/vm.'+op+'Multikey',s['module']+'/internal/multiformats.'+op+'Multibase',s['module']+'/internal/multiformats.Base'+op] for op in ['Encode','Decode']]
    assert v['audits']==witness['audits']
    assert v['carry']==witness['carry']
    assert v['state']==witness['state']
    assert v['cursor']==witness['cursor']
    assert len(v['cursor'])==2
    for audit,count in zip(v['cursor'],[2,1]):
        assert not audit['unknown'] and len(audit['steps'])==count and audit['projection'] and audit['roles'] and audit['scope']
        assert all(step['correct'] is True and step['expressions'] for step in audit['steps'])
    assert len(v['state'])==2
    for audit,count in zip(v['state'],[2,4]):
        assert not audit['unknown'] and len(audit['steps'])==count and audit['roles'] and audit['scope']
        assert all(step['correct'] is True and step['expressions'] for step in audit['steps'])
    assert len(v['carry'])==2
    for audit in v['carry']:
        assert not audit['unknown'] and len(audit['steps'])==3
        assert all(step['correct'] is True and step['operation']['integer'] is True for step in audit['steps'])
    for audit,count in zip(v['audits'],[33,39]):
        assert len(audit['operations'])==count and not audit['unknown']
        assert all(op['integer'] is True and op['types'] and op['line']>0 and op['column']>0 for op in audit['operations'])
    assert len(s['diagnostics'])==len(q['diagnostics'])==2
    for request,result in zip(q['diagnostics'],s['diagnostics']):
        assert result['request']==request and result['operation']==s['module']+'/vm.EncodeMultikey+DecodeMultikey'
        # Actual output and codec errors remain diagnostic for this clause.
    live={row['id']:row for row in report['statements']}
    for o in observations:
        assert o['verdict']=='PASS' and o['detail'] and o['expected']
        assert live[o['statement']]['verdict']=='PASS' and CASE in live[o['statement']]['cases']
    return set(IDS)


def main():
    p=argparse.ArgumentParser();p.add_argument('--reports',type=Path,required=True);args=p.parse_args();r=args.reports
    ids=verify_integer_source(json.loads((r/'resolution-did-1.1-raw.json').read_text()),json.loads((r/'resolution-did-1.1.json').read_text()))
    print(f'Verified {len(ids)} fixed-source arithmetic and state clauses, canonical h1 and 16 cache files')


if __name__=='__main__':main()
