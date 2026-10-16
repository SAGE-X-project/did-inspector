import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import check_sage_residual_evidence as checker


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def controls():
    # Synthetic unit evidence only; actual runtime evidence is separately archived by CI.
    cases, live = [], []
    for kind in ["history-metadata", "proxy-metadata"]:
        qs, values = [], []
        for index, (request, reply) in enumerate(checker.expected_requests(kind)):
            q = {"request": request, "post": False, "reply": encoded(reply)}
            ep = "https://127.0.0.1:1234/1.0/identifiers/"
            url = ep + checker.DID
            if kind == "history-metadata":
                url = ep + checker.quote(checker.DID, safe="-._~") + "?versionId=" + request["options"]["versionId"]
            values.append({"request": q, "operation": "github.com/sage-x-project/did-go/resolution/universal.Client.resolve", "endpoint": ep,
                "server_role": "controlled client response fixture; not SAGE server output", "server_tls": True, "server_calls": 1, "native": [],
                "wire": [{"url": url, "method": "GET", "accept": "application/did"}],
                "consumer": [{"operation": "github.com/sage-x-project/did-go/consumer.Consumer.Consume", "input": encoded(checker.DOCUMENT), "media_type": "application/json" if kind == "proxy-metadata" and index == 0 else "application/did", "require": "unknown", "expected": "unknown", "strict": False, "version": "1.1", "json_ld": True, "model": encoded({"id": checker.DID}), "entries": encoded({"@context": checker.CONTEXT})}],
                "result": {"has_content": True, "returned_id": checker.DID, "metadata": {"contentType": "application/did"}, "content_metadata": reply["didDocumentMetadata"]}})
            qs.append(q)
        caseid = "did-1.1/sage-resolution/residual-" + kind
        ids = checker.HISTORY if kind == "history-metadata" else [checker.PROXY]
        cases.append({"case": caseid, "observations": [{"statement": i, "verdict": "PASS", "detail": "synthetic unit evidence", "input": json.dumps(qs), "observed": json.dumps(values)} for i in ids]})
    audit = json.loads((checker.REPO / "docs/sage-remaining-clause-review.json").read_text())
    for row in audit["clauses"]:
        live.append({"id": row["id"], "verdict": row["expected_live_verdict"], "cases": row["cases"]})
    return {"profile": "did-1.1", "subject": {}, "cases": cases}, {"profile": "did-1.1", "subject": {}, "statements": live}


class ResidualEvidenceTests(unittest.TestCase):
    def test_selected_controls(self):
        raw, report = controls()
        self.assertEqual(checker.verify_residual(raw, report), checker.SELECTED)

    def test_case_and_observation_loss(self):
        for change in [lambda r: r["cases"].pop(), lambda r: r["cases"].append(r["cases"][0]), lambda r: r["cases"][0]["observations"].pop(), lambda r: r["cases"][0]["observations"][0].update(verdict="NOT_RUN"), lambda r: r["cases"][0].update(case="did-1.1/residual-other")]:
            raw, report = controls(); change(raw)
            with self.assertRaises((AssertionError, KeyError)):
                checker.verify_residual(raw, report)

    def test_attribution_and_field_mutations(self):
        changes = [lambda v: (v.update(endpoint=v["endpoint"]+"?"), v["wire"][0].update(url=v["endpoint"]+checker.DID)), lambda v: v.update(operation="other"), lambda v: v.update(endpoint="https://external.example/"), lambda v: v.update(server_role="SAGE production"), lambda v: v.update(server_tls=False), lambda v: v.update(server_calls=0), lambda v: v.update(native=[{}]), lambda v: v.update(consumer=[]), lambda v: v["wire"][0].update(url="other"), lambda v: v["wire"][0].update(method="POST"), lambda v: v["wire"][0].update(accept="other"), lambda v: v["wire"][0].update(body="e30="), lambda v: v["consumer"][0].update(media_type="other"), lambda v: v["consumer"][0].update(version="unknown"), lambda v: v["consumer"][0].update(json_ld=False), lambda v: v["consumer"][0].update(model="e30="), lambda v: v["consumer"][0].update(entries="e30="), lambda v: v["consumer"][0].update(error="refused"), lambda v: v["consumer"][0].update(capture_error="lost"), lambda v: v["result"].update(has_content=False), lambda v: v["result"].update(returned_id="other"), lambda v: v["request"].update(post=True), lambda v: v["request"].update(post=0), lambda v: v.update(server_tls=1), lambda v: v.update(server_calls=True), lambda v: v["consumer"][0].update(json_ld=1), lambda v: v["consumer"][0].update(strict=0), lambda v: v["result"].update(has_content=1), lambda v: v["result"]["metadata"].update(error={"type": "internalError"})]
        for kind in ["history-metadata", "proxy-metadata"]:
            raw, _ = controls(); c = next(c for c in raw["cases"] if c["case"].endswith(kind));qs = json.loads(c["observations"][0]["input"]);vs = json.loads(c["observations"][0]["observed"])
            for change in changes:
                values = copy.deepcopy(vs); change(values[0])
                with self.assertRaises((AssertionError, KeyError)):
                    checker.verify_client(kind, qs, values)
            values = copy.deepcopy(vs)
            if kind == "history-metadata":
                for field in ["nextUpdate", "nextVersionId", "versionId"]:
                    changed = copy.deepcopy(vs); changed[0]["result"]["content_metadata"][field] = "other"
                    with self.assertRaises(AssertionError):checker.verify_client(kind, qs, changed)
            else:
                values[0]["result"]["metadata"] = {}
                with self.assertRaises(KeyError):checker.verify_client(kind, qs, values)

    def test_optional_controls_do_not_invent_absence_requirement(self):
        raw, _ = controls(); o = raw["cases"][0]["observations"][0];qs, vs = json.loads(o["input"]), json.loads(o["observed"])
        vs[1]["result"]["content_metadata"]["nextVersionId"] = "9"
        checker.verify_client("history-metadata", qs, vs)

    def test_catalog_identity_pending_dependencies_and_reasons(self):
        _, report = controls()
        for change in [lambda d: d["clauses"].pop(), lambda d: d.update(baseline_inspector_revision="other"), lambda d: d["clauses"][0].update(text_sha256="other"), lambda d: d["clauses"][0].update(completion_condition=""), lambda d: d["clauses"][0].update(expected_live_verdict="PASS"), lambda d: d["clauses"][0].update(depends_on=["invented"])]:
            with tempfile.TemporaryDirectory() as directory:
                repo = Path(directory); (repo / "docs").mkdir(); (repo / "statements").symlink_to(checker.REPO / "statements", target_is_directory=True)
                for name in ["sage-residual-evidence-review.json", "sage-remaining-clause-review.json"]:
                    data = json.loads((checker.REPO / "docs" / name).read_text())
                    if name == "sage-residual-evidence-review.json":change(data)
                    (repo / "docs" / name).write_text(json.dumps(data))
                with self.assertRaises(AssertionError):checker.verify_catalog(report, repo)

    @unittest.skipUnless(os.environ.get("SAGE_BATCH_REPORT_DIR"), "actual reports are generated by adapter CI")
    def test_actual_ci_evidence(self):
        root = Path(os.environ["SAGE_BATCH_REPORT_DIR"])
        raw = json.loads((root / "resolution-did-1.1-raw.json").read_text());report = json.loads((root / "resolution-did-1.1.json").read_text())
        self.assertEqual(checker.verify_residual(raw, report), checker.SELECTED)


if __name__ == "__main__":
    unittest.main()
