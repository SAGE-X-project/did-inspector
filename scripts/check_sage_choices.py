#!/usr/bin/env python3
"""Independently verify actual selected-choice and conversion report evidence."""
import argparse
import json
import subprocess
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from check_sage_batch import btc, decode, verify_codec, verify_client
from check_sage_optional import base, verify_call

CODECS={('P-256',False):('8024',33),('P-384',False):('8124',49),('Ed25519',False):('ed01',32),('BLS12-381-G2',False):('eb01',96),('SM2',False):('8624',33),('P-256',True):('8626',32),('P-384',True):('8726',48),('Ed25519',True):('8026',32),('SM2',True):('9026',32)}
PUBLIC={'P-256':'036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296','P-384':'03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7','Ed25519':'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a','BLS12-381-G2':'93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8','SM2':'0232c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'}
CODEC_IDS={'cid10#algorithms.1','cid10#multibase-0.3','cid10#multibase-0.5'}
CONVERSION_IDS={'cid10#verification-material.2','cid10#verification-material.3'}
PROXY='res10-crd20261001#resolver-architectures-proxied.1'
IP_CERT='res10-crd20261001#bindings-https.3'
MULTIKEY='cid10#Multikey.2'


def keys(name,secret):
    _,length=CODECS[name,secret]
    if secret:return [bytes(length-1)+bytes([n]) for n in [1,2]]
    first=bytes.fromhex(PUBLIC[name]);second=bytearray(first)
    if name=='Ed25519':second=bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
    else:second[0]^=0x20 if name=='BLS12-381-G2' else 1
    return [first,bytes(second)]


def owned(endpoint):
    u=urlsplit(endpoint)
    assert u.scheme=='https' and u.hostname in ['127.0.0.1','::1'] and u.port
    assert u.path=='/1.0/identifiers/' and not u.username and not u.password and not u.query and not u.fragment
    return u


def certificate_ips(text):
    # Only the Subject Alternative Name extension identifies TLS IP names.
    # Subject CN and other extension text are not SAN evidence.
    lines=text.splitlines();section_indent=None
    for index,line in enumerate(lines):
        stripped=line.strip();indent=len(line)-len(line.lstrip())
        if stripped=='X509v3 extensions:':
            section_indent=indent
            continue
        if section_indent is None:continue
        if stripped and indent<=section_indent:
            section_indent=None
            continue
        if not stripped.startswith('X509v3 Subject Alternative Name:'):continue
        contents=[]
        for following in lines[index+1:]:
            depth=len(following)-len(following.lstrip())
            if following.strip() and depth<=indent:break
            contents.append(following)
        return {ipaddress.ip_address(value) for value in re.findall(r"IP Address:([0-9a-fA-F:.]+)",' '.join(contents))}
    return set()


def verify_choices(raw,report):
    assert raw['profile']==report['profile']=='did-1.1' and raw['subject']==report['subject']
    selected=[c for c in raw['cases'] if '/choice-' in c['case']]
    assert len(selected)==len({c['case'] for c in selected})==16
    expected_names={'codec-'+n+'-'+('public-test-secret' if secret else 'public') for n,secret in CODECS}
    expected_names|={'key-conversion-'+n for n in ['P-256','P-384','Ed25519']}
    expected_names|={'proxy-post-false','proxy-post-true','ip-certificate','optional-public-multibase-local-model'}
    assert {c['case'].split('/choice-')[1] for c in selected}==expected_names
    checked=set();live={c['id']:c for c in report['statements']}
    for c in selected:
        name=c['case'].split('/choice-')[1];obs=c['observations']
        assert obs and len(obs)==len({o['statement'] for o in obs})
        assert all(o['verdict']=='PASS' and o['detail'] and o['input'] and o['observed'] for o in obs)
        assert all(o['input']==obs[0]['input'] and o['observed']==obs[0]['observed'] for o in obs)
        q=json.loads(obs[0]['input']);v=json.loads(obs[0]['observed'])
        ids={o['statement'] for o in obs}
        if name.startswith('codec-'):
            assert ids==CODEC_IDS and len(q)==len(v)==3
            kind,secret=q[0]['name'],q[0]['secret'];prefix,length=CODECS[kind,secret]
            assert isinstance(secret,bool) and name=='codec-'+kind+'-'+('public-test-secret' if secret else 'public')
            assert [decode(x['key']) for x in q[:2]]==keys(kind,secret)
            verify_codec({'fixture':{'name':kind,'secret':secret,'prefix':v[0]['prefix'],'length':length},'requests':q[:2]},v[:2])
            expected=dict(q[0]);expected['encoded']='z0';assert q[2]==expected
            assert v[2]['request']==expected and v[2]['operation']=='github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey'
            assert v[2]['encoded']==q[0]['encoded'] and not v[2].get('encode_error')
            # Decoder error shape for the invalid alphabet is diagnostic only.
        elif name.startswith('proxy-'):
            assert ids=={PROXY} and q['statements']==[PROXY]
            assert q['request']['request']=={'function':'resolve','input':q['record']['did']} and q['request']['post']==name.endswith('true')
            assert not q['request'].get('reply');verify_client(q,v)
        elif name=='ip-certificate':
            assert ids=={IP_CERT} and len(v)==2 and not v[0]['client_missing'] and v[1]['client_missing']
            good=v[0];endpoint=owned(good['endpoint'])
            assert good['role']=='actual universal Client with owned self-hosted SAGE handler and explicit fixture Source; no operational trust claim' and not good.get('capture_error')
            assert good['server_verified'] and good['server_peer']==good['server_certificate']
            certificate=subprocess.run(['openssl','x509','-inform','DER','-noout','-text'],input=decode(good['server_certificate']),capture_output=True,check=True).stdout.decode()
            assert ipaddress.ip_address(endpoint.hostname) in certificate_ips(certificate)
            # mTLS client-auth outcomes belong to separate trust predicates.
        elif name.startswith('key-conversion-'):
            assert ids==CONVERSION_IDS and len(q)==len(v)==2
            kind=name.removeprefix('key-conversion-');prefix,_=CODECS[kind,False]
            for request,value,key in zip(q,v,keys(kind,False)):
                assert request['name']==kind and decode(request['key'])==key and value['request']==request
                assert value['operation']=='github.com/sage-x-project/did-go/crypto.NewPublicKey+PublicKey.CryptoKey+FromCryptoKey+PublicKey.Multikey'
                assert not any(value.get(k) for k in ['build_error','before_error','convert_error','after_error'])
                assert value['before']==value['after']==btc(bytes.fromhex(prefix)+key)
                # Actual internal values are archived diagnostics, not additional
                # MUST NOT external-value predicates.
                assert all(k in value for k in ['crypto_type','before_type','after_type','before_raw','after_raw'])
        else:
            assert ids=={MULTIKEY} and q['statements']==[MULTIKEY] and len(q['variants'])==len(v['variants'])==2
            public,local=base(),base()
            for doc in [public,local]:
                m=doc['verificationMethod'][0];m['type']='Multikey';del m['publicKeyJwk']
            public['verificationMethod'][0]['publicKeyMultibase']=btc(bytes.fromhex('ed01'+PUBLIC['Ed25519']))
            seed=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
            local['verificationMethod'][0]['secretKeyMultibase']=btc(bytes.fromhex('8026')+seed)
            verify_call(q['control'],v['control'],public)
            for request,value,expected in zip(q['variants'],v['variants'],[public,local]):verify_call(request,value,expected)
        for identifier in ids:
            assert live[identifier]['verdict']=='PASS' and c['case'] in live[identifier]['cases']
        checked|=ids
    assert checked==CODEC_IDS|CONVERSION_IDS|{PROXY,IP_CERT,MULTIKEY}
    return checked


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--reports',type=Path,required=True);args=parser.parse_args()
    r=args.reports
    checked=verify_choices(json.loads((r/'resolution-did-1.1-raw.json').read_text()),json.loads((r/'resolution-did-1.1.json').read_text()))
    print(f'Verified {len(checked)} selected-choice clauses across sixteen actual cases')


if __name__=='__main__':main()
