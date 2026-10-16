import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import inspect_sage_prerequisites as c

MANIFEST = c.load((c.REPO / "docs/sage-evidence-prerequisites.json").read_text())
ERRORS = (AssertionError, KeyError, ValueError, zipfile.BadZipFile)


def synthetic_source():
    # Deliberately synthetic unit bytes, never original-source evidence.
    contents = {f"unit/file{i}.go": f"unit data {i}".encode() for i in range(11)}
    buffer = io.BytesIO()
    prefix = "unit.example/source@v0.0.0"
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in contents.items():
            archive.writestr(prefix + "/" + name, data)
    archive = base64.b64encode(buffer.getvalue()).decode()
    checksum, _ = c.archive_files(archive, prefix)
    source = {"module": "unit.example/source", "version": "v0.0.0", "sum": checksum,
              "archive": archive, "replaced": False}
    manifest = {"source": {k: source[k] for k in ["module", "version", "sum"]},
                "source_zip_files": [{"path": n, "sha256": hashlib.sha256(b).hexdigest()} for n, b in contents.items()]}
    return source, manifest


def synthetic_receipts():
    # Review identity checks in isolation; these are not runtime calls.
    raw, report, manifest = {"cases": []}, {"statements": []}, {"prior_observations": []}
    for i in range(6):
        case, identifier = f"unit/{i}", f"unit#{i}"
        verdict = "FAIL" if i == 2 else "PASS"
        q, v = {"strict": False}, {"operation": "synthetic", "value": i}
        raw["cases"].append({"case": case, "statements": [identifier], "observations": [
            {"statement": identifier, "verdict": verdict, "detail": "unit only", "input": json.dumps(q), "observed": json.dumps(v)}]})
        report["statements"].append({"id": identifier, "verdict": verdict, "cases": [case]})
        manifest["prior_observations"].append({"case": case, "statements": [identifier],
            "verdicts": {identifier: verdict}, "input_sha256": c.digest(q), "observed_sha256": c.digest(v)})
    return raw, report, manifest


class PrerequisiteTests(unittest.TestCase):
    def test_json_types_and_duplicates(self):
        self.assertEqual(c.digest(c.load('{"a":1,"b":false}')), c.digest(c.load('{"b":false,"a":1}')))
        self.assertNotEqual(c.digest(False), c.digest(0))
        self.assertNotEqual(c.digest(None), c.digest([]))
        self.assertNotEqual(c.digest([1, 2]), c.digest([2, 1]))
        with self.assertRaises(ValueError):
            c.load('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            c.digest(c.load('{"a":NaN}'))
        with self.assertRaises(AssertionError):
            c.index_unique([{"id": "a"}, {"id": "a"}], "id")

    def test_selected_source_bytes(self):
        source, manifest = synthetic_source()
        result = c.verify_source(source, manifest)
        self.assertEqual(len(result["selected_zip_files"]), 11)
        for mutate in [lambda s, m: s.update(version="v1"), lambda s, m: s.update(replaced=True),
                       lambda s, m: s.update(archive="!!!"), lambda s, m: m["source"].update(sum="other"),
                       lambda s, m: m["source_zip_files"].pop(),
                       lambda s, m: m["source_zip_files"][0].update(path="missing.go"),
                       lambda s, m: m["source_zip_files"][0].update(sha256="other")]:
            s, m = copy.deepcopy(source), copy.deepcopy(manifest)
            mutate(s, m)
            with self.assertRaises(ERRORS):
                c.verify_source(s, m)
        s = copy.deepcopy(source)
        s["archive"] = base64.b64encode(b"not a zip").decode()
        with self.assertRaises(zipfile.BadZipFile):
            c.verify_source(s, manifest)
        m = copy.deepcopy(manifest)
        m["source_zip_files"][1] = m["source_zip_files"][0]
        with self.assertRaises(AssertionError):
            c.verify_source(source, m)

    def test_prior_receipt_integrity(self):
        raw, report, manifest = synthetic_receipts()
        self.assertEqual(c.verify_receipts(raw, report, manifest), manifest["prior_observations"])
        changes = [lambda r: r["cases"].pop(), lambda r: r["cases"].append(r["cases"][0]),
                   lambda r: r["cases"][0].update(statements=[]),
                   lambda r: r["cases"][0]["observations"][0].update(statement="other"),
                   lambda r: r["cases"][2]["observations"][0].update(verdict="PASS"),
                   lambda r: r["cases"][0]["observations"][0].update(detail=""),
                   lambda r: r["cases"][0]["observations"][0].update(input='{"strict":0}'),
                   lambda r: r["cases"][0]["observations"][0].update(observed='{"operation":"other"}')]
        for change in changes:
            data = copy.deepcopy(raw)
            change(data)
            with self.assertRaises(ERRORS):
                c.verify_receipts(data, report, manifest)
        for change in [lambda r: r["statements"][0].update(cases=[]), lambda r: r["statements"][2].update(verdict="PASS")]:
            data = copy.deepcopy(report)
            change(data)
            with self.assertRaises(AssertionError):
                c.verify_receipts(raw, data, manifest)
        m = copy.deepcopy(manifest)
        m["prior_observations"].pop()
        with self.assertRaises(AssertionError):
            c.verify_receipts(raw, report, m)

    def test_pending_contracts(self):
        report = {"statements": [{"id": r["id"], "verdict": "NOT_RUN"} for r in MANIFEST["clauses"]]}
        self.assertEqual(len(c.verify_pending(report, MANIFEST, c.REPO)), 16)
        mutations = [lambda m: m["clauses"].pop(), lambda m: m["clauses"][0].update(reason="other"),
                     lambda m: m["clauses"][0].update(text_sha256="other"), lambda m: m["clauses"][1].update(depends_on=[]),
                     lambda m: m["clauses"][0].update(runtime_verdict="PASS"),
                     lambda m: m["clauses"][0].update(runtime_cases=["invented"]),
                     lambda m: m["clauses"][0].update(contract_group="other"),
                     lambda m: m["clauses"][0].update(source_zip_references=["missing"]),
                     lambda m: m["clauses"][0].update(prior_observation_references=["missing"])]
        for mutate in mutations:
            m = copy.deepcopy(MANIFEST)
            mutate(m)
            with self.assertRaises(ERRORS):
                c.verify_pending(report, m, c.REPO)
        report["statements"][0]["verdict"] = "NOT_APPLICABLE"
        with self.assertRaises(AssertionError):
            c.verify_pending(report, MANIFEST, c.REPO)

    def test_manifest_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "docs").mkdir()
            (repo / "docs/sage-evidence-prerequisites.json").write_text('{}')
            with self.assertRaises(AssertionError):
                c.build_assessment({}, {}, repo)

    def test_cli_creation_verification_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ["resolution-did-1.1-raw.json", "resolution-did-1.1.json"]:
                (root / name).write_text('{}')
            output = root / "prerequisites.json"
            args = ["--reports", str(root), "--out", str(output)]
            assessment = {"runtime_verdicts_merged": False, "test": "synthetic only"}
            with patch.object(c, "build_assessment", return_value=assessment):
                c.main(args)
                c.main(args + ["--verify"])
                with self.assertRaises(FileExistsError):
                    c.main(args)
                with self.assertRaises(FileExistsError):
                    c.main(["--reports", str(root), "--out", str(root / "resolution-did-1.1.json")])
                link = root / "link.json"
                link.symlink_to(output)
                with self.assertRaises(FileExistsError):
                    c.main(["--reports", str(root), "--out", str(link)])
                output.write_text('{"runtime_verdicts_merged":true}')
                with self.assertRaises(AssertionError):
                    c.main(args + ["--verify"])
            self.assertEqual((root / "resolution-did-1.1.json").read_text(), '{}')

    @unittest.skipUnless(os.environ.get("SAGE_BATCH_REPORT_DIR"), "actual reports are supplied by adapter CI")
    def test_actual_evidence_and_controls(self):
        root = Path(os.environ["SAGE_BATCH_REPORT_DIR"])
        raw = c.load((root / "resolution-did-1.1-raw.json").read_text())
        report = c.load((root / "resolution-did-1.1.json").read_text())
        assessment = c.build_assessment(raw, report)
        self.assertIs(assessment["runtime_verdicts_merged"], False)
        self.assertEqual(assessment["runtime_totals"], c.TOTALS)
        self.assertEqual(len(assessment["pending_contracts"]), 16)
        self.assertEqual(assessment["input_identity"]["raw_sha256"], c.digest(raw))
        mutations = [lambda r: r.update(profile="other"), lambda r: r.update(subject={}),
                     lambda r: r["totals"].update(NOT_RUN=91),
                     lambda r: r["totals"].update(ERROR=False),
                     lambda r: r["statements"][0].update(verdict="ERROR"),
                     lambda r: r["cases"].pop(), lambda r: r["cases"][0].update(id="other")]
        for mutate in mutations:
            r = copy.deepcopy(report)
            mutate(r)
            with self.assertRaises(ERRORS):
                c.build_assessment(raw, r)
        # Actual receipt changes are checked without fabricating a new runtime operation.
        r = copy.deepcopy(raw)
        selected = next(x for x in r["cases"] if x["case"].endswith("/library-context-cache"))
        value = c.load(selected["observations"][0]["observed"])
        value["operation"] = "other"
        selected["observations"][0]["observed"] = json.dumps(value)
        with self.assertRaises(AssertionError):
            c.build_assessment(r, report)


if __name__ == "__main__":
    unittest.main()
