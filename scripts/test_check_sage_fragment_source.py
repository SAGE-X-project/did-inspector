"""Omission and source/runtime identity controls for the artifact checker."""
import base64
import copy
import json
import unittest
import zipfile

from check_sage_fragment_source import CASE,IDS,MODULE,VERSION,SUM,PACKAGES,REPO,verify_fragment_source


def encoded(value):
    return base64.b64encode(json.dumps(value,separators=(',',':')).encode()).decode()


def controls():
    archive=(REPO/'checks/sourcearith/testdata/did-go-pinned.zip').read_bytes()
    prefix=MODULE+'@'+VERSION+'/'
    with zipfile.ZipFile(REPO/'checks/sourcearith/testdata/did-go-pinned.zip') as z:
        files={n[len(prefix):]:base64.b64encode(z.read(n)).decode() for n in z.namelist() if n.startswith(prefix) and n[len(prefix):].rsplit('/',1)[0] in PACKAGES and n.endswith('.go') and not n.endswith('_test.go')}
    q={'module':MODULE,'version':VERSION,'packages':PACKAGES,'diagnostics':None}
    source={'request':q,'module':MODULE,'version':VERSION,'sum':SUM,'operation':'debug.ReadBuildInfo + local go env + module cache/ZIP byte capture','replaced':False,'diagnostics':[],'compiler':'go1.26.8','environment_compiler':'go1.26.8','archive':base64.b64encode(archive).decode(),'files':files}
    witness=json.loads((REPO/'profiles/sageresolution/fragment_source_witness.json').read_text())
    e={'source':source,'audit':witness,'type_checker_compiler':'go1.26.8','type_checker_architecture':'arm64','runtime':[]}
    fixtures=[f for f in json.loads((REPO/'profiles/sageresolution/resource_choices.json').read_text()) if f['name'] in ['nested-full','nested-relative']]
    for f in fixtures:
        values=[]
        for i,request in enumerate(f['requests']):
            r={'native':None,'exchange':None,'has_content':i==0,'raw':encoded(f['expected_content'] if i==0 else None),'metadata':{'contentType':f['expected_media']} if i==0 else {'error':{'type':'https://www.w3.org/ns/did#NOT_FOUND'}},'content_kind':'map' if i==0 else '', 'returned_id':f['expected_id'] if i==0 else ''}
            values.append({'request':{'document':{'data':encoded(f['document']),'media_type':'application/did'},'request':request},'role':'root resolver/dereferencer library with literal example driver; not SAGE Source','operation':MODULE+'/dereferencer.Dereferencer.Dereference','resolve_inputs':['did:example:resources'],'driver_inputs':['did:example:resources'],'resolve_options':[encoded({'accept':'application/did'})],'options':encoded({'accept':'application/did'}),'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'application/did','NoCache':False})],'driver_results':[encoded({'Data':encoded(f['document']),'ContentType':'application/did'})],'result':r})
        e['runtime'].append(values)
    obs=[{'statement':ident,'verdict':'PASS','input':json.dumps(q),'observed':json.dumps(e),'detail':'selected scope','expected':'selected binding'} for ident in IDS]
    statements=[{'id':ident,'verdict':'PASS','cases':[CASE]} for ident in IDS]+[{'id':ident,'verdict':'NOT_RUN','cases':[]} for ident in ['cid10#fragment-resolution.1','cid10#fragment-resolution.4','cid10#base-encode.4','cid10#base-decode.5']]
    raw={'profile':'did-1.1','subject':{'name':'selected'},'cases':[{'case':CASE,'observations':obs}]};report={'profile':'did-1.1','subject':raw['subject'],'statements':statements}
    return raw,report


class FragmentArtifactTests(unittest.TestCase):
    def test_complete_fixture_and_omissions(self):
        raw,report=controls();self.assertEqual(verify_fragment_source(raw,report),set(IDS))
        for key in ['statement','input','observed']:
            changed=copy.deepcopy(raw);changed['cases'][0]['observations'][0][key]='changed'
            with self.assertRaises((AssertionError,ValueError)):verify_fragment_source(changed,report)
        for ident in ['cid10#fragment-resolution.1','cid10#base-encode.4']:
            changed=copy.deepcopy(report);next(r for r in changed['statements'] if r['id']==ident)['verdict']='PASS'
            with self.assertRaises(AssertionError):verify_fragment_source(raw,changed)

    def test_source_and_runtime_mutation(self):
        raw,report=controls()
        for mutate in [
            lambda e:e['source'].update(sum='other'),
            lambda e:e['source'].update(files={}),
            lambda e:e['audit']['frames'].update({'other':'unknown'}),
            lambda e:e['audit']['steps'][0].update(correct=1),
            lambda e:e['runtime'][0][0].update(role='other'),
            lambda e:e['runtime'][0][0]['result'].update(raw=encoded({})),
            lambda e:e['runtime'][0][1]['result'].update(has_content=True),
            lambda e:e['runtime'].pop(),
        ]:
            changed=copy.deepcopy(raw);e=json.loads(changed['cases'][0]['observations'][0]['observed']);mutate(e)
            for o in changed['cases'][0]['observations']:o['observed']=json.dumps(e)
            with self.assertRaises(AssertionError):verify_fragment_source(changed,report)

    def test_missing_case_and_verdict_receipt(self):
        raw,report=controls();changed=copy.deepcopy(raw);changed['cases']=[]
        with self.assertRaises(AssertionError):verify_fragment_source(changed,report)
        changed=copy.deepcopy(report);changed['statements'][0]['cases']=[]
        with self.assertRaises(AssertionError):verify_fragment_source(raw,changed)


if __name__=='__main__':unittest.main()
