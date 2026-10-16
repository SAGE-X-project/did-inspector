"""Defensive document-evidence controls; no altered subject program is executed."""
import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import inspect_method_document as m


class MethodDocumentTests(unittest.TestCase):
    def setUp(self):
        self.catalog = m.load_catalog()
        # Synthetic public prose checks verifier boundaries only; it is never a
        # conformance corpus and is never accepted by the production catalog loader.
        self.raw = {"format": "did-inspector-method-document-capture/1",
                    "repository": m.REPOSITORY, "revision": m.REVISION, "files": []}
        for item in self.catalog["files"]:
            content = (item["path"] + "\nsecond line\n").encode()
            item["bytes"] = len(content)
            item["sha256"] = m.digest(content)
            self.raw["files"].append({"path": item["path"], "content_base64": base64.b64encode(content).decode()})
        for row in self.catalog["rows"]:
            for evidence in row["evidence"]:
                content = (evidence["path"] + "\nsecond line\n").encode()
                evidence.update(start_line=1, end_line=2, sha256=m.digest(content))

    def test_inventory_and_report_separation(self):
        self.assertEqual(len(self.catalog["rows"]), 51)
        result = m.inspect(self.catalog, self.raw, "observer")
        self.assertEqual(result["totals"], {"PASS": 7, "FAIL": 0, "ERROR": 0, "NOT_RUN": 44})
        self.assertFalse(result["runtime_results_merged"])
        self.assertEqual(result["revision"], m.REVISION)
        self.assertEqual(result["inspector_revision"], "observer")
        self.assertEqual({r["id"] for r in result["statements"] if r["verdict"] == "PASS"}, m.REVIEWED)
        self.raw["verdict"] = "FAIL"
        self.assertEqual(m.inspect(self.catalog, self.raw, "observer")["totals"], result["totals"])

    def test_missing_unreviewed_and_malformed_capture(self):
        variants = []
        for key in ("format", "repository", "revision"):
            value = copy.deepcopy(self.raw);value[key] = "other";variants.append(value)
        variants += [None, [], {}, {"format": self.raw["format"], "repository": m.REPOSITORY, "revision": m.REVISION},
                     {**self.raw, "files": None}, {**self.raw, "files": [None]}, {**self.raw, "files": [{"path": 0, "content_base64": ""}]}, {**self.raw, "files": [{"path": "file", "content_base64": False}]}]
        for value in variants:
            with self.subTest(value=str(value)[:100]):
                result = m.inspect(self.catalog, value, "observer")
                self.assertEqual(result["totals"], {"PASS": 0, "FAIL": 0, "ERROR": 7, "NOT_RUN": 44})

    def test_full_corpus_integrity(self):
        variants = []
        for files in (self.raw["files"][:-1], self.raw["files"] + [self.raw["files"][0]],
                      self.raw["files"] + [{"path": "extra", "content_base64": ""}]):
            variants.append({**self.raw, "files": files})
        for data in (b"different", b"\xff", b""):
            value = copy.deepcopy(self.raw);value["files"][0]["content_base64"] = base64.b64encode(data).decode();variants.append(value)
        value = copy.deepcopy(self.raw);value["files"][0]["content_base64"] = "!!";variants.append(value)
        for value in variants:
            with self.subTest(value=str(value)[:80]):
                self.assertEqual(m.inspect(self.catalog, value, "observer")["totals"]["ERROR"], 7)
        # Same byte length still needs the full SHA, not just a size check.
        value = copy.deepcopy(self.raw)
        data = base64.b64decode(value["files"][0]["content_base64"])
        value["files"][0]["content_base64"] = base64.b64encode(b"x" * len(data)).decode()
        self.assertEqual(m.inspect(self.catalog, value, "observer")["totals"]["ERROR"], 7)

    def test_excerpt_boundaries(self):
        for change in ({"start_line": 0}, {"end_line": 3}, {"start_line": True},
                       {"end_line": "2"}, {"sha256": "0" * 64}, {"start_line": 2, "end_line": 1}):
            c = copy.deepcopy(self.catalog)
            next(r for r in c["rows"] if r["evidence"])["evidence"][0].update(change)
            self.assertEqual(m.inspect(c, self.raw, "observer")["totals"]["ERROR"], 7)

    def test_catalog_drift_refused(self):
        original_read = Path.read_text
        def exercise(change, where="catalog"):
            def read(path, *args, **kwargs):
                data = original_read(path, *args, **kwargs)
                if (where == "catalog" and path.name == "sage-method-document-review.json") or (where == "statement" and path.name == "did11-cr20260305.json"):
                    value = json.loads(data);change(value);return json.dumps(value)
                return data
            with patch.object(Path, "read_text", read), self.assertRaises(m.EvidenceError):
                m.load_catalog()
        for key in ("format", "repository", "revision"):
            exercise(lambda c, key=key: c.update({key: "other"}))
        exercise(lambda c: c["rows"].pop())
        exercise(lambda c: c["rows"].append(c["rows"][0]))
        exercise(lambda c: c["files"].pop())
        exercise(lambda c: c["rows"][0].update(text="different"))
        exercise(lambda c: c["rows"][0].update(text_sha256="different"))
        exercise(lambda c: c["rows"][0].update(status="other"))
        exercise(lambda c: c["rows"][0].update(scope=""))
        exercise(lambda c: c["rows"][0].update(review_basis=""))
        exercise(lambda c: next(r for r in c["rows"] if r["status"] == "reviewed-document").update(evidence=[]))
        exercise(lambda c: c["rows"][0].update(status="reviewed-document", evidence=[{}]))
        exercise(lambda c: next(r for r in c["rows"] if r["status"] == "reviewed-document").update(status="pending"))
        exercise(lambda c: c.update(sha256="other"), "statement")

    def test_git_capture_uses_only_pinned_blobs(self):
        contents = {f["path"]: base64.b64decode(f["content_base64"]) for f in self.raw["files"]}
        def call(args, **kwargs):
            self.assertIn("--no-replace-objects", args)
            self.assertEqual(kwargs["timeout"], 15)
            if "rev-parse" in args:
                self.assertEqual(args[-1], m.REVISION + "^{commit}")
                return (m.REVISION + "\n").encode()
            self.assertEqual(args[-3:-1], ["cat-file", "blob"])
            self.assertTrue(args[-1].startswith(m.REVISION + ":"))
            return contents[args[-1].split(":", 1)[1]]
        with patch.object(subprocess, "check_output", side_effect=call) as invocation:
            self.assertEqual(m.capture(Path("/source"), self.catalog), self.raw)
            self.assertEqual(invocation.call_count, 17)
        for problem in (FileNotFoundError(), subprocess.CalledProcessError(1, "git"), subprocess.TimeoutExpired("git", 15)):
            with patch.object(subprocess, "check_output", side_effect=problem), self.assertRaises(m.EvidenceError):
                m.capture(Path("/source"), self.catalog)
        with patch.object(subprocess, "check_output", return_value=b"wrong"), self.assertRaises(m.EvidenceError):
            m.capture(Path("/source"), self.catalog)

    def test_cli_outputs_and_capture_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); repo = directory / "source";repo.mkdir()
            out = directory / "out/report.json";raw = directory / "out/raw.json"
            args = ["--repository", str(repo), "--out", str(out), "--raw-out", str(raw), "--inspector-revision", "observer"]
            with patch.object(m, "load_catalog", return_value=self.catalog), patch.object(m, "capture", return_value=self.raw), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.main(args), 0)
            self.assertEqual(json.loads(out.read_text())["totals"]["PASS"], 7)
            self.assertEqual(json.loads(raw.read_text()), self.raw)
            with patch.object(m, "load_catalog", return_value=self.catalog), patch.object(m, "capture", side_effect=m.EvidenceError("unavailable")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.main(args), 1)
            self.assertEqual(json.loads(out.read_text())["totals"]["ERROR"], 7)
            self.assertEqual(json.loads(raw.read_text()), {"capture_error": "unavailable"})
            bad = [*args];bad[bad.index("--out") + 1] = str(raw)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):m.main(bad)
            for target in (repo, repo / "file.json"):
                bad = [*args];bad[bad.index("--out") + 1] = str(target)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):m.main(bad)


if __name__ == "__main__":
    unittest.main()
