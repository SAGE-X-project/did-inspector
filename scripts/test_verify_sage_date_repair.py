import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import verify_sage_date_repair as check


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def fixture():
    manifest = json.loads((check.ROOT / "docs/sage-date-repair.json").read_text())
    inputs = json.loads((check.ROOT / "scripts/testdata/sage-date-repair-inputs.json").read_text())
    subject = {key: manifest["subject"][key] for key in ["name", "version", "revision"]}
    cases, selected = [], set()
    for field, fixed in manifest["cases"].items():
        f = json.loads(inputs[field])
        outputs = []
        for index, q in enumerate(f["requests"]):
            c = {"input":q["document"]["data"], "media_type":"application/did",
                 "operation":"github.com/sage-x-project/did-go/consumer.Consumer.Consume",
                 "require":"unknown", "expected":"unknown", "strict":False}
            out = {"role":check.ROLE, "consumer":c, "retrieval":{"clock":0,"operation":"","reference":"","purpose":"","calls":[],"method":None,"problem":None}, "clock_values":[]}
            if index < 6:
                model = check.decoded(c["input"])
                model["verificationMethod"][0][field] = check.NORMAL[index]
                c.update(version="1.1", json_ld=False, dropped_terms=None, model=encoded(model), entries=encoded({}))
                out["methods"] = [{"id":model["verificationMethod"][0]["id"], field:{"kind":"datetime", "text":check.NORMAL[index]}}]
            else:
                c["error"] = "consumer: verificationMethod[0]." + field + ": unit fixture refusal " + f["statement"]
                c.update(capture_error="no actual document accessor maps",model=None,entries=None)
                out["methods"] = None
            outputs.append(out)
        observations = [{"statement":i,"verdict":"PASS","input":inputs[field],"observed":json.dumps(outputs)} for i in fixed["statements"]]
        cases.append({"case":fixed["case"],"statements":fixed["statements"],"observations":observations})
        selected.update(fixed["statements"])
    ids = []
    for name in ["did11-cr20260305", "cid10", "res10-crd20261001"]:
        ids += [r["id"] for r in json.loads((check.ROOT / "statements" / (name + ".json")).read_text())["statements"]]
    report = {"subject":subject,"profile":"did-1.1","inspector":{"revision":"unit-observer"},
              "totals":{"statements":486,"PASS":4,"FAIL":0,"NOT_SUPPORTED":0,"NOT_APPLICABLE":0,"ERROR":0,"NOT_RUN":482},
              "statements":[{"id":i,"verdict":"PASS" if i in selected else "NOT_RUN"} for i in ids],
              "cases":[{"id":c["case"]} for c in cases]}
    return {"scope":"complete XML Schema and SAGE conformance are not established","runtime_results_merged":False,
            "report":report,"raw":{"subject":subject,"profile":"did-1.1","cases":cases}}, manifest


class VerifyReceipt(unittest.TestCase):
    def test_valid_fixture_and_native_limits(self):
        evidence, manifest = fixture()
        result = check.verify(evidence, manifest, "unit-observer")
        self.assertEqual(result["actual_consumer_calls"], 30)
        self.assertEqual(result["PASS"], 4)
        self.assertIs(result["runtime_results_merged"], False)

    def test_receipt_tampering(self):
        mutations = [
            lambda e:e.update(runtime_results_merged=True),
            lambda e:e.update(scope="all conforming"),
            lambda e:e["report"]["subject"].update(revision="other"),
            lambda e:e["report"]["inspector"].update(revision="other"),
            lambda e:e["report"]["totals"].update(PASS=True),
            lambda e:e["raw"]["cases"].pop(),
            lambda e:e["raw"]["cases"][0]["observations"].pop(),
            lambda e:e["raw"]["cases"][0]["observations"][0].update(verdict="FAIL"),
            lambda e:e["raw"]["cases"][0]["observations"][0].update(input="{}"),
            lambda e:e["report"]["statements"][0].update(verdict="FAIL"),
        ]
        for mutate in mutations:
            e,m=fixture();mutate(e)
            with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")

    def test_observed_call_tampering(self):
        mutations = [
            lambda o:o.update(role="authoritative"),
            lambda o:o["consumer"].update(input=encoded({})),
            lambda o:o["consumer"].update(operation="replacement"),
            lambda o:o["consumer"].update(strict=0),
            lambda o:o.update(clock_values=["unexpected"]),
            lambda o:o["consumer"].update(error="valid refused"),
            lambda o:o["consumer"].update(version="1.0"),
            lambda o:o["consumer"].update(capture_error=False),
            lambda o:o["consumer"].update(dropped_terms=False),
            lambda o:o["retrieval"].update(clock=False),
            lambda o:o["consumer"].update(model=encoded({})),
            lambda o:o["methods"][0]["expires"].update(text="2030-01-01T00:00:01Z"),
        ]
        for mutate in mutations:
            e,m=fixture();c=e["raw"]["cases"][0]
            # The manifest preserves field order from the frozen expires case.
            self.assertTrue(c["case"].endswith("expires"))
            observed=json.loads(c["observations"][0]["observed"]);mutate(observed[0])
            for row in c["observations"]:row["observed"]=json.dumps(observed)
            with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")

    def test_malformed_acceptance_and_partial_document(self):
        for partial in [False,True]:
            e,m=fixture();c=e["raw"]["cases"][0];outputs=json.loads(c["observations"][0]["observed"])
            if partial:outputs[12]["consumer"]["model"]=encoded({})
            else:outputs[12]["consumer"].pop("error")
            for row in c["observations"]:row["observed"]=json.dumps(outputs)
            with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")

    def test_malformed_capture_corruption(self):
        for key, value in [("capture_error", "lost document snapshot"), ("model", False), ("entries", 0)]:
            e,m=fixture();c=e["raw"]["cases"][0];outputs=json.loads(c["observations"][0]["observed"])
            outputs[12]["consumer"][key]=value
            for row in c["observations"]:row["observed"]=json.dumps(outputs)
            with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")
        e,m=fixture();c=e["raw"]["cases"][0];outputs=json.loads(c["observations"][0]["observed"]);outputs[12]["methods"]=False
        for row in c["observations"]:row["observed"]=json.dumps(outputs)
        with self.assertRaises(ValueError):check.verify(e,m,"unit-observer")

    def test_command_and_exclusive_output(self):
        e,_=fixture()
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/"evidence.json";source.write_text(json.dumps(e));out=Path(directory)/"verified.json"
            with patch.object(sys,"argv",["verify","--evidence",str(source),"--observer","unit-observer","--out",str(out)]):
                check.main()
                self.assertEqual(json.loads(out.read_text())["cases"],2)
                with self.assertRaises(FileExistsError):check.main()


if __name__ == "__main__":
    unittest.main()
