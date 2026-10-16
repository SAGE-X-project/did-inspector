import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import check_sage_extensions as c

def encoded(v):return c.encoded(json.dumps(v,separators=(',',':')).encode())
def codecs():
    # Synthetic unit receipts; only CI supplies original runtime evidence.
    e={}
    for name,qs,start in [('multibase',c.fixtures()[0],4),('multihash',c.fixtures()[1],8)]:
        e[name]=[]
        for i,q in enumerate(qs):
            v={'request':q,'observer':dict(c.OBSERVER),'role':c.ROLE,'operation':c.MODULE+'/internal/multiformats.'+('Encode' if i%2==0 else 'Decode')+('Multibase' if name=='multibase' else 'Multihash')}
            if name=='multibase':v.update(encoded=qs[i+1]['encoded'] if i%2==0 else '',header=qs[i-1]['header'] if i%2 else 0,data=qs[i-1]['data'] if i%2 else None)
            else:v.update(encoded=qs[i+1]['encoded'] if i%2==0 else None,code=qs[i-1]['code'] if i%2 else 0,digest=qs[i-1]['digest'] if i%2 else None)
            if i>=start:
                v.update(encoded='' if name=='multibase' else None)
                if name=='multibase':v.update(data=None,error="multiformats: header 'f' is not defined by CID 1.0")
                else:v.update(code=0,digest=None,error='multiformats: Multihash header 0x13 is not defined by CID 1.0')
            e[name].append(v)
    return e

def application():
    qs=c.requests();vs=[]
    for i,q in enumerate(qs):
        v={'request':q,'operation':c.MODULE+'/dereferencer.Dereferencer.Dereference','role':'root resolver/dereferencer library with literal example driver; not SAGE Source','resolve_inputs':[c.DID],'driver_inputs':[c.DID],'options':encoded({}),'resolve_options':[encoded({})],'driver_options':[encoded({'VersionID':'','VersionTime':None,'MediaType':'','NoCache':False})],'driver_results':[encoded({'ContentType':'application/did','Data':q['document']['data'],'Metadata':{}})],'consumption':[{'operation':c.MODULE+'/consumer.Consumer.Consume','input':q['document']['data'],'media_type':'application/did','require':'unknown','expected':'unknown','strict':False,'version':'1.1','json_ld':True,'model':encoded(c.MODEL),'entries':encoded(c.ENTRIES)}],'data_model':encoded(c.MODEL),'resolved_data_model':encoded(c.MODEL),'entries':encoded(c.ENTRIES),'resolved_entries':encoded(c.ENTRIES),'resolved_metadata':encoded({'contentType':'application/did'})}
        result={'has_content':False,'raw':encoded(None),'metadata':{'error':{'type':'https://www.w3.org/ns/did#NOT_FOUND'}},'content_metadata':{}}
        resource={'has_content':True,'raw':encoded(c.RESOURCE),'snapshot':copy.deepcopy(c.RESOURCE),'content_kind':'map','returned_id':c.URL,'metadata':{'contentType':'application/json'},'content_metadata':{'versionId':'application-1'}}
        if i<2:v['application_handler']=[{'input':{'operation':c.MODULE+'/dereferencer.ResourceHandler','role':'explicit controlled application callback; not SAGE method support','url':{'input':c.URL,'primary':c.URL,'path':'/public-resource','query':'','fragment':'','has_fragment':False,'has_query':False},'options':encoded({}),'model':encoded(c.MODEL),'entries':encoded(c.ENTRIES),'metadata':encoded({'contentType':'application/did'})},'handled':i==0,'returned':copy.deepcopy(resource) if i==0 else {'has_content':False,'raw':encoded(None),'metadata':{},'content_metadata':{}}}]
        if i==0:result=resource
        elif i==3:result={'has_content':True,'content_kind':'document','returned_id':c.DID,'metadata':{'contentType':'application/did'}}
        v['result']=result;vs.append(v)
    return qs,vs

class ExtensionTests(unittest.TestCase):
    def test_synthetic_controls(self):
        c.verify_codecs(codecs());c.verify_application(*application())
        e=codecs();e['multibase'][0]['observer']['replacement_version']='';c.verify_codecs(e)

    def test_codec_corruption(self):
        for name in ['multibase','multihash']:
            for index in range(6 if name=='multibase' else 10):
                for field,value in [('role','other'),('operation','other'),('request',{}),('observer',{}),('error','unclassified'),('encoded','corrupt')]:
                    e=codecs();e[name][index][field]=value
                    with self.assertRaises((AssertionError,KeyError,ValueError)):c.verify_codecs(e)
            e=codecs();e[name].pop()
            with self.assertRaises(AssertionError):c.verify_codecs(e)
        for key in ['capture_error','multibase_capture_error','multihash_capture_error']:
            e=codecs();e[key]='lost'
            with self.assertRaises(AssertionError):c.verify_codecs(e)
        for group,index,key,value in [('multibase',1,'header',True),('multihash',1,'code',True),('multibase',4,'header',False),('multihash',8,'code',False),('multibase',4,'data','AQ=='),('multihash',8,'digest','AQ==')]:
            e=codecs();e[group][index][key]=value
            with self.assertRaises(AssertionError):c.verify_codecs(e)

    def test_application_corruption(self):
        changes=[lambda v:v.update(role='SAGE method'),lambda v:v.update(operation='other'),lambda v:v.update(capture_error='lost'),lambda v:v.update(resolve_inputs=[]),lambda v:v.update(driver_inputs=[]),lambda v:v.update(driver_options=[encoded({'VersionID':'','VersionTime':None,'MediaType':'','NoCache':0})]),lambda v:v.update(driver_results=[encoded({'ContentType':'other','Data':encoded(c.DOC),'Metadata':{}})]),lambda v:v.update(production=[{}]),lambda v:v.update(options=encoded({'accept':'other'})),lambda v:v['consumption'][0].update(strict=0),lambda v:v['consumption'][0].update(json_ld=1),lambda v:v['consumption'][0].update(error='refused'),lambda v:v['consumption'][0].update(model=encoded({})),lambda v:v.update(resolved_metadata=encoded({})),lambda v:v.update(application_handler=[]),lambda v:v['application_handler'][0]['input'].update(role='other'),lambda v:v['application_handler'][0]['input'].update(url={}),lambda v:v['application_handler'][0].update(handled=1),lambda v:v['application_handler'][0]['returned'].update(raw=encoded({})),lambda v:v['result'].update(has_content=1),lambda v:v['result'].update(snapshot={}),lambda v:v['result'].update(content_metadata={}),lambda v:v['result'].update(native={"unexpected":True})]
        for change in changes:
            qs,vs=application();change(vs[0])
            with self.assertRaises((AssertionError,KeyError)):c.verify_application(qs,vs)
        for index,change in [(1,lambda v:v['application_handler'][0]['returned'].update(has_content=True)),(1,lambda v:v['result']['metadata']['error'].update(type='other')),(2,lambda v:v['result'].update(has_content=True)),(3,lambda v:v['result'].update(returned_id='other')),(3,lambda v:v.update(application_handler=[{}]))]:
            qs,vs=application();change(vs[index])
            with self.assertRaises((AssertionError,KeyError)):c.verify_application(qs,vs)
        qs,vs=application();qs[0]['request']['input']='other'
        with self.assertRaises(AssertionError):c.verify_application(qs,vs)
        qs,vs=application();vs.pop()
        with self.assertRaises(AssertionError):c.verify_application(qs,vs)

    def test_archived_original_result_shape(self):
        # First actual CI receipt, reused only as frozen regression unit data.
        vs=json.loads((c.REPO/'profiles/sageresolution/application_runtime_control.json').read_text())
        c.verify_application([v['request'] for v in vs],vs)
        vs[0]['result']['snapshot']=encoded(c.RESOURCE)
        with self.assertRaises(AssertionError):c.verify_application([v['request'] for v in vs],vs)

    def test_typed_application_flags(self):
        for key in ['plain_json_fragment','observe_production','observe_resource_handler']:
            qs,vs=application();qs[0][key]=0
            with self.assertRaises(AssertionError):c.verify_application(qs,vs)
        for key in ['has_fragment','has_query']:
            qs,vs=application();vs[0]['application_handler'][0]['input']['url'][key]=0
            with self.assertRaises(AssertionError):c.verify_application(qs,vs)

    def test_synthetic_envelope_integrity(self):
        # Unit data isolates envelope checks; this mock is never actual-source proof.
        source={'request':{'unit':'synthetic source'}}
        qs,vs=application();ev=codecs();ev['source']=source
        cases=[{'case':'did-1.1/sage-resolution/multihash-component-operations','observations':[{'observed':json.dumps({'source':source})}]}]
        for suffix,ids,verdict,q,e in [('codecs',[c.BASE,c.HASH],'NOT_SUPPORTED',source['request'],ev),('application-handler',[c.APP],'PASS',qs,vs)]:
            cases.append({'case':c.PREFIX+suffix,'statements':ids,'observations':[{'statement':ident,'verdict':verdict,'input':json.dumps(q),'observed':json.dumps(e),'detail':'synthetic unit scope'} for ident in ids]})
        raw={'profile':'did-1.1','subject':{},'cases':cases};report={'profile':'did-1.1','subject':{},'statements':[{'id':ident,'verdict':'PASS' if ident==c.APP else 'NOT_SUPPORTED','cases':[c.PREFIX+('application-handler' if ident==c.APP else 'codecs')]} for ident in c.IDS]}
        with patch.object(c,'verify_internal_operations'):
            self.assertEqual(c.verify_extensions(raw,report),c.IDS)
            for mutation in [lambda r:r['cases'].pop(),lambda r:r['cases'][1]['observations'][0].update(verdict='PASS'),lambda r:r['cases'][1]['observations'][0].update(statement=c.APP),lambda r:r['cases'][2].update(statements=[]),lambda r:r.update(profile='did-core-1.0')]:
                r=copy.deepcopy(raw);mutation(r)
                with self.assertRaises(AssertionError):c.verify_extensions(r,report)
            r=copy.deepcopy(raw);ev=codecs();ev['source']={'request':{'unit':'other'}}
            for o in r['cases'][1]['observations']:o['observed']=json.dumps(ev)
            with self.assertRaises(AssertionError):c.verify_extensions(r,report)

    @unittest.skipUnless(os.environ.get('SAGE_BATCH_REPORT_DIR'),'actual reports are supplied by adapter CI')
    def test_actual_evidence_and_omission(self):
        path=Path(os.environ['SAGE_BATCH_REPORT_DIR']);raw=json.loads((path/'resolution-did-1.1-raw.json').read_text());report=json.loads((path/'resolution-did-1.1.json').read_text());self.assertEqual(c.verify_extensions(raw,report),c.IDS)
        for mode in ['omitted','wrong_verdict','wrong_source']:
            r=copy.deepcopy(raw);selected=[x for x in r['cases'] if '/extension-' in x['case']]
            if mode=='omitted':r['cases'].remove(selected[0])
            elif mode=='wrong_verdict':selected[0]['observations'][0]['verdict']='PASS'
            else:
                e=json.loads(selected[0]['observations'][0]['observed']);e['source']['sum']='other'
                for o in selected[0]['observations']:o['observed']=json.dumps(e)
            with self.assertRaises(AssertionError):c.verify_extensions(r,report)
if __name__=='__main__':unittest.main()
