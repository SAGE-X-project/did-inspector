import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, urlsplit

import verify_sage_routing_repair as check


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def fixture():
    manifest = json.loads((check.ROOT / "docs/sage-routing-repair.json").read_text())
    inputs = json.loads((check.ROOT / "scripts/testdata/sage-routing-repair-inputs.json").read_text())
    source = (check.ROOT / "profiles/sageresolution/routing_cases.json").read_text()
    documents = check.documents(source)
    cases, selected, attribution = [], set(), {}
    for f in json.loads(source):
        name, q = f["name"], f["request"]
        data = base64.b64encode(documents[name]).decode()
        incoming = {"accept":q["accept"]}
        if q.get("relationship"):
            incoming["verificationRelationship"] = q["relationship"]
        nested = dict(parse_qsl(urlsplit(q["input"]).query))
        nested.update(incoming)
        c = {"operation":"github.com/sage-x-project/did-go/consumer.Consumer.Consume", "input":data,"media_type":"application/did","strict":False,"require":"unknown","expected":"unknown","version":"1.1","json_ld":False,"dropped_terms":None,"model":encoded(f["document"]),"entries":encoded({})}
        out = {"role":check.ROLE,"operation":"github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference","request":{"document":{"data":data,"media_type":"application/did"},"request":q},"options":encoded(incoming),"resolve_inputs":["did:example:123"],"resolve_options":[encoded(nested)],"driver_inputs":["did:example:123"],"driver_options":[encoded({"VersionID":"","VersionTime":None,"MediaType":"application/did" if q["accept"]=="application/did" else "","NoCache":False})],"driver_results":[encoded({"Data":data,"ContentType":"application/did","Metadata":{}})],"consumption":[c],"resolved_data_model":encoded(f["document"]),"resolved_entries":encoded({}),"resolved_metadata":encoded({"contentType":"application/did"}),"entries":encoded({})}
        if f["error_type"]:
            types = {"non-method-fragment":"https://w3id.org/security#INVALID_VERIFICATION_METHOD","conflicting-fragment":"https://www.w3.org/ns/did#INVALID_DID_URL"}
            out["result"] = {"metadata":{"error":{"type":types.get(name,"https://www.w3.org/ns/did#"+f["error_type"]),"detail":"authored unit refusal"}},"content_metadata":{},"has_content":False,"raw":encoded(None)}
            model = f["document"]
        else:
            is_list = isinstance(f["expected_content"], list)
            out["result"] = {"metadata":{"contentType":q["accept"]},"content_metadata":{"contentType":"text/uri-list"} if is_list else {},"has_content":True,"content_kind":"uri-list" if is_list else "document","raw":encoded(f["expected_content"])}
            if not is_list:
                out["result"]["returned_id"]="did:example:123"
            model = f["document"] if is_list else f["expected_content"]
        out["data_model"] = encoded(model)
        case_id = check.PREFIX+name
        cases.append({"case":case_id,"statements":f["statements"],"observations":[{"statement":i,"verdict":"PASS","input":inputs[name],"observed":json.dumps(out)} for i in f["statements"]]})
        for i in f["statements"]:
            selected.add(i)
            attribution.setdefault(i,[]).append(case_id)
    ids = []
    for name in ["did11-cr20260305","cid10","res10-crd20261001"]:
        ids.extend(r["id"] for r in json.loads((check.ROOT/"statements"/(name+".json")).read_text())["statements"])
    subject = {k:manifest["subject"][k] for k in ["name","version","revision"]}
    report = {"subject":subject,"profile":"did-1.1","specs":copy.deepcopy(manifest["specs"]),"inspector":{"revision":"unit-observer"},"totals":{"statements":486,"PASS":29,"FAIL":0,"NOT_SUPPORTED":0,"NOT_APPLICABLE":0,"ERROR":0,"NOT_RUN":457},"statements":[{"id":i,"verdict":"PASS" if i in selected else "NOT_RUN",**({"cases":attribution[i]} if i in selected else {})} for i in ids],"cases":[{"id":c["case"],"statements":c["statements"],"verdict":"PASS","observations":len(c["observations"])} for c in cases]}
    data=base64.b64encode((check.ROOT/"adapters/sagerouting/control-document.json").read_bytes()).decode()
    control={"role":check.ROLE,"operation":"github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve","request":{"document":{"data":data,"media_type":"application/did"},"request":{"function":"resolve","input":"did:example:123","accept":"text/uri-list"}},"options":encoded({"accept":"text/uri-list"}),"resolve_inputs":["did:example:123"],"resolve_options":[encoded({"accept":"text/uri-list"})],"driver_options":[],"result":{"metadata":{"error":{"type":"https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED","detail":"text/uri-list unavailable"}},"content_metadata":{},"has_content":False}}
    control["resolved_metadata"] = encoded(control["result"]["metadata"])
    return {"scope":check.SCOPE,"runtime_results_merged":False,"report":report,"raw":{"subject":subject,"profile":"did-1.1","cases":cases},"controls":[copy.deepcopy(control),copy.deepcopy(control)]},manifest


def change_call(evidence, name, mutate):
    c=next(c for c in evidence["raw"]["cases"] if c["case"]==check.PREFIX+name)
    out=json.loads(c["observations"][0]["observed"])
    mutate(out)
    for o in c["observations"]:
        o["observed"]=json.dumps(out)


class VerifyRouting(unittest.TestCase):
    def test_authored_fixture(self):
        e,m=fixture();result=check.verify(e,m,"unit-observer")
        self.assertEqual((result["actual_routing_calls"],result["actual_strict_controls"],result["PASS"]),(12,2,29))
        self.assertIs(result["runtime_results_merged"],False)

    def test_identity_inventory_and_attribution(self):
        mutations=[lambda e:e.update(runtime_results_merged=0),lambda e:e.update(scope="complete conformance"),lambda e:e["report"]["subject"].update(revision="other"),lambda e:e["report"]["inspector"].update(revision="other"),lambda e:e["report"]["specs"].pop(),lambda e:e["report"]["totals"].update(ERROR=False),lambda e:e["raw"]["cases"].pop(),lambda e:e["raw"]["cases"][0]["observations"].pop(),lambda e:e["report"]["statements"][0].update(verdict="PASS"),lambda e:e["report"]["cases"][0].update(observations=True),lambda e:e["controls"].pop()]
        for mutate in mutations:
            e,m=fixture();mutate(e)
            with self.assertRaises((ValueError,KeyError,TypeError)):check.verify(e,m,"unit-observer")
        e,m=fixture();next(r for r in e["report"]["statements"] if r["verdict"]=="PASS")["cases"]=["unrelated"]
        with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")

    def test_forwarding_and_capture_tampering(self):
        mutations=[lambda o:o.update(role="authoritative"),lambda o:o.update(capture_error=False),lambda o:o.update(production=[{}]),lambda o:o["request"]["request"].update(accept="application/did"),lambda o:o.update(options=encoded({})),lambda o:o.update(resolve_inputs=["did:example:other"]),lambda o:o.update(resolve_options=[encoded({"service":"one"})]),lambda o:o.update(driver_inputs=[]),lambda o:o.update(driver_options=[encoded({"VersionID":"","VersionTime":None,"MediaType":"text/uri-list","NoCache":False})]),lambda o:o.update(driver_results=[encoded({})]),lambda o:o.update(resolved_metadata=encoded({"contentType":"text/uri-list"})),lambda o:o.update(resolved_data_model=encoded({})),lambda o:o.update(entries=encoded(False)),lambda o:o["consumption"][0].update(strict=0),lambda o:o["consumption"][0].update(capture_error="lost model"),lambda o:o["result"].update(raw=encoded(["https://wrong.example/"]))]
        for mutate in mutations:
            e,m=fixture();change_call(e,"forward-uri-options",mutate)
            with self.assertRaises((ValueError,KeyError,TypeError)):check.verify(e,m,"unit-observer")

    def test_document_and_refusal_tampering(self):
        for name,mutate in [("service-id",lambda o:o["result"].update(returned_id="other")),("service-id",lambda o:o.update(data_model=encoded({}))),("unsupported-service-media",lambda o:o["result"].update(has_content=0)),("unsupported-service-media",lambda o:o["result"].update(raw=encoded({}))),("unsupported-service-media",lambda o:o["result"].update(raw=None)),("unsupported-service-media",lambda o:o["result"].update(raw=encoded(False))),("conflicting-fragment",lambda o:o["result"]["metadata"]["error"].update(type="unexpected")),("non-method-fragment",lambda o:o["result"]["metadata"]["error"].update(detail=""))]:
            e,m=fixture();change_call(e,name,mutate)
            with self.assertRaises((ValueError,KeyError,TypeError)):check.verify(e,m,"unit-observer")

    def test_strict_controls_cannot_be_faked(self):
        for mutate in [lambda o:o.update(resolve_options=[]),lambda o:o.update(consumption=[{}]),lambda o:o.update(data_model=False),lambda o:o.update(resolved_metadata=encoded({})),lambda o:o.update(driver_inputs=["did:example:123"]),lambda o:o["result"]["metadata"]["error"].update(type="other"),lambda o:o["result"].update(has_content=True),lambda o:o["result"].update(content_metadata={"changed":True})]:
            e,m=fixture();mutate(e["controls"][0])
            with self.assertRaises((ValueError,KeyError,TypeError)):check.verify(e,m,"unit-observer")

    def test_sources_and_command(self):
        e,m=fixture();m["fixture_sha256"]="other"
        with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")
        e,m=fixture();m["control_document_sha256"]="other"
        with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")
        with self.assertRaises(ValueError):check.documents('[{"name":"a","document":{},"document":{}}]')
        e,_=fixture()
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"evidence.json";source.write_text(json.dumps(e));out=Path(directory)/"verified.json"
            with patch.object(sys,"argv",["verify","--evidence",str(source),"--observer","unit-observer","--out",str(out)]):
                check.main()
                self.assertEqual(json.loads(out.read_text())["cases"],12)
                with self.assertRaises(FileExistsError):check.main()


if __name__=="__main__":
    unittest.main()
