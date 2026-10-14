"""Regression controls for artifact evidence of optional/library capabilities."""
import copy
import json
import os
import unittest
from pathlib import Path
import check_sage_optional as check
from check_sage_batch import decode


class OptionalEvidenceTests(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ["SAGE_BATCH_REPORT_DIR"])
        self.raw = json.loads((root / "resolution-did-1.1-raw.json").read_text())
        self.report = json.loads((root / "resolution-did-1.1.json").read_text())

    def test_actual_calls(self):
        self.assertEqual(len(check.verify_optional(self.raw, self.report)), 17)

    def test_missing_duplicate_or_relabelled_evidence(self):
        for change in [lambda r: r["cases"].pop(next(i for i, c in enumerate(r["cases"]) if "/optional-" in c["case"])),
                       lambda r: r["cases"].append(copy.deepcopy(next(c for c in r["cases"] if "/optional-" in c["case"]))),
                       lambda r: r.update(profile="did-core-1.0")]:
            raw = copy.deepcopy(self.raw)
            change(raw)
            with self.assertRaises(AssertionError):
                check.verify_optional(raw, self.report)

    def test_observer_and_document_mutations(self):
        import base64
        for change in [lambda c: c.update(operation="invented adapter"), lambda c: c.update(strict=True),
                       lambda c: c.update(error="refused"), lambda c: c.update(capture_error="lost"),
                       lambda c: c.update(dropped_terms=["exampleExtra"]),
                       lambda c: c.update(input=base64.b64encode(b"{}").decode()),
                       lambda c: c.update(model=base64.b64encode(b"{}").decode()),
                       lambda c: c.update(entries=base64.b64encode(b'{"unknown":1}').decode())]:
            raw = copy.deepcopy(self.raw)
            case = next(c for c in raw["cases"] if c["case"].endswith("/optional-exampleExtra"))
            out = json.loads(case["observations"][0]["observed"])
            change(out["variants"][1])
            case["observations"][0]["observed"] = json.dumps(out)
            with self.assertRaises(AssertionError):
                check.verify_optional(raw, self.report)

    def test_extension_order_and_date_instant(self):
        import base64
        for name, allowed in [("exampleExtra", False), ("expires", True)]:
            raw = copy.deepcopy(self.raw)
            case = next(c for c in raw["cases"] if c["case"].endswith("/optional-" + name))
            out = json.loads(case["observations"][0]["observed"])
            capture = out["variants"][1]
            doc = json.loads(decode(capture["model"]))
            method = doc["verificationMethod"][0]
            if allowed:
                method[name] = "2030-01-01T09:00:00+09:00"
            else:
                method[name]["sequence"].reverse()
            capture["model"] = base64.b64encode(json.dumps(doc).encode()).decode()
            case["observations"][0]["observed"] = json.dumps(out)
            if allowed:
                self.assertEqual(len(check.verify_optional(raw, self.report)), 17)
            else:
                with self.assertRaises(AssertionError):
                    check.verify_optional(raw, self.report)
