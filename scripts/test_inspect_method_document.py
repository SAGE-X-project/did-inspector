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
        self.assertEqual(result["totals"], {"PASS": 23, "FAIL": 7, "ERROR": 0, "NOT_APPLICABLE": 19, "NOT_RUN": 2})
        self.assertFalse(result["runtime_results_merged"])
        self.assertEqual(result["revision"], m.REVISION)
        self.assertEqual(result["inspector_revision"], "observer")
        self.assertEqual({r["id"] for r in result["statements"] if r["verdict"] == "PASS"}, m.REVIEWED)
        self.raw["verdict"] = "FAIL"
        self.assertEqual(m.inspect(self.catalog, self.raw, "observer")["totals"], result["totals"])

    def test_completion_contracts_require_verified_corpus(self):
        result = m.inspect(self.catalog, self.raw, "observer")
        self.assertEqual(result["completion_progress"], {"reviewed": 7, "verified": 7, "errors": 0})
        checks = {r["id"]: r for r in result["statements"] if "completion_check" in r}
        self.assertEqual(set(checks), set(m.COMPLETION_DIGESTS))
        self.assertEqual({r["verdict"] for r in checks.values()}, {"PASS", "FAIL", "NOT_RUN"})
        for identifier, row in checks.items():
            assessment = row["completion_check"]["assessment"]
            self.assertEqual(row["completion_check"]["evidence_status"], "VERIFIED")
            self.assertEqual(assessment["outcome"], row["verdict"])
            self.assertGreaterEqual(len(assessment["conditions"]), 2)
            self.assertTrue(all(c["basis"] and c["completion"] for c in assessment["conditions"]))
        # Verified review metadata is not a positive observation when source bytes are absent.
        absent = m.inspect(self.catalog, {}, "observer")
        self.assertEqual(absent["completion_progress"], {"reviewed": 7, "verified": 0, "errors": 7})
        for row in absent["statements"]:
            if row["id"] in checks:
                self.assertEqual(row["completion_check"], {"evidence_status": "ERROR", "assessment": None})
                self.assertEqual(row["verdict"], "NOT_RUN" if row["id"] in m.DEFERRED else "ERROR")

    def test_completion_contract_changes_are_not_semantic_evidence(self):
        original_read = Path.read_text
        def exercise(change):
            def read(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                if path.name == "sage-method-document-review.json":
                    c = json.loads(text);change(c);return json.dumps(c)
                return text
            with patch.object(Path, "read_text", read), self.assertRaises(m.EvidenceError):
                m.load_catalog()
        for identifier in m.COMPLETION_DIGESTS:
            def selected(c):return next(r for r in c["rows"] if r["id"] == identifier)
            exercise(lambda c: selected(c).pop("completion_review"))
            for value in (None, {}, {"outcome": "PASS"}):
                exercise(lambda c, value=value: selected(c).update(completion_review=value))
            exercise(lambda c: selected(c)["completion_review"].update(group="other"))
            exercise(lambda c: selected(c)["completion_review"]["conditions"][0].update(status="SUPPORTED", basis="invented"))
        exercise(lambda c: c["rows"][0].update(completion_review={"outcome": "PASS"}))

    def test_missing_unreviewed_and_malformed_capture(self):
        variants = []
        for key in ("format", "repository", "revision"):
            value = copy.deepcopy(self.raw);value[key] = "other";variants.append(value)
        variants += [None, [], {}, {"format": self.raw["format"], "repository": m.REPOSITORY, "revision": m.REVISION},
                     {**self.raw, "files": None}, {**self.raw, "files": [None]}, {**self.raw, "files": [{"path": 0, "content_base64": ""}]}, {**self.raw, "files": [{"path": "file", "content_base64": False}]}]
        for value in variants:
            with self.subTest(value=str(value)[:100]):
                result = m.inspect(self.catalog, value, "observer")
                self.assertEqual(result["totals"], {"PASS": 0, "FAIL": 0, "ERROR": 49, "NOT_APPLICABLE": 0, "NOT_RUN": 2})

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
                self.assertEqual(m.inspect(self.catalog, value, "observer")["totals"]["ERROR"], 49)
        # Same byte length still needs the full SHA, not just a size check.
        value = copy.deepcopy(self.raw)
        data = base64.b64decode(value["files"][0]["content_base64"])
        value["files"][0]["content_base64"] = base64.b64encode(b"x" * len(data)).decode()
        self.assertEqual(m.inspect(self.catalog, value, "observer")["totals"]["ERROR"], 49)

    def test_excerpt_boundaries(self):
        for change in ({"start_line": 0}, {"end_line": 3}, {"start_line": True},
                       {"end_line": "2"}, {"sha256": "0" * 64}, {"start_line": 2, "end_line": 1}):
            c = copy.deepcopy(self.catalog)
            next(r for r in c["rows"] if r["evidence"])["evidence"][0].update(change)
            self.assertEqual(m.inspect(c, self.raw, "observer")["totals"]["ERROR"], 49)

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
        exercise(lambda c: next(r for r in c["rows"] if r["status"] == "pending").update(status="reviewed-document", evidence=[{}]))
        exercise(lambda c: next(r for r in c["rows"] if r["status"] == "reviewed-document").update(status="pending"))
        exercise(lambda c: c.update(sha256="other"), "statement")

    def test_reviewed_pending_boundaries(self):
        result = m.inspect(self.catalog, self.raw, "observer")
        self.assertEqual(result["review_progress"], {"judged": 49, "reviewed_pending": 2, "unreviewed": 0})
        pending = [r for r in result["statements"] if "pending_review" in r]
        self.assertEqual({r["id"] for r in pending}, m.DEFERRED)
        for row in pending:
            self.assertEqual(row["verdict"], "NOT_RUN")
            self.assertEqual(row["pending_review"]["verdict"], "NOT_RUN")
            self.assertGreaterEqual(len(row["pending_review"]["completion_evidence"]), 3)
        # Missing current capture cannot turn a reviewed prerequisite into PASS,
        # NOT_APPLICABLE or a normative failure.
        absent = m.inspect(self.catalog, {}, "observer")
        self.assertEqual(absent["totals"], {"PASS": 0, "FAIL": 0, "ERROR": 49, "NOT_APPLICABLE": 0, "NOT_RUN": 2})
        self.assertTrue(all(r["verdict"] == "NOT_RUN" for r in absent["statements"] if r["id"] in m.DEFERRED))
        permitted = {"did11-cr20260305#method-syntax.10", "did11-cr20260305#method-syntax.11",
                     "did11-cr20260305#method-operations.2", "did11-cr20260305#method-operations.4"}
        self.assertTrue(permitted <= {r["id"] for r in result["statements"] if r["verdict"] == "PASS"})

    def test_unresolved_contract_drift_refused(self):
        original_read = Path.read_text
        def exercise(change):
            def read(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                if path.name == "sage-method-document-review.json":
                    c = json.loads(text);change(c);return json.dumps(c)
                return text
            with patch.object(Path, "read_text", read), self.assertRaises(m.EvidenceError):m.load_catalog()
        def pending(c):return next(row for row in c["rows"] if row["id"] in m.DEFERRED)
        exercise(lambda c: pending(c).pop("pending_review"))
        exercise(lambda c: pending(c).update(status="reviewed-document"))
        exercise(lambda c: pending(c).update(pending_review=None))
        for change in ({"verdict": "PASS"}, {"required_actor": ""}, {"required_actor": False},
                       {"reason": " "}, {"reason": None}, {"extra": "unreviewed"},
                       {"completion_evidence": []}, {"completion_evidence": None},
                       {"completion_evidence": "use source"}, {"completion_evidence": [False]},
                       {"completion_evidence": [""]}):
            exercise(lambda c, change=change: pending(c)["pending_review"].update(change))
        exercise(lambda c: c["rows"][0].update(pending_review={"verdict": "NOT_RUN"}))

    def test_conditional_author_scope_requires_complete_evidence(self):
        expected = {"cid10#Multikey.24"} | {"did11-cr20260305#" + suffix for suffix in (
            "extensibility.2", "extensibility.3", "extensibility.4",
            "production-and-consumption.1", "production-and-consumption.2",
            "production-and-consumption.3", "production-and-consumption.4",
            "production-and-consumption.5", "production-and-consumption.6",
            "security-requirements.12", "security-requirements.14")} | {"res10-crd20261001#" + suffix for suffix in (
            "dereferencing-algorithm-resource.45", "dereferencing-algorithm-resource.46",
            "dereferencing-algorithm-resource.47", "did-document-metadata.17",
            "did-document-metadata.22", "errors.6", "method-architectures.3")}
        result = m.inspect(self.catalog, self.raw, "observer")
        self.assertEqual({r["id"] for r in result["statements"] if r["verdict"] == "NOT_APPLICABLE"}, expected)
        for row in result["statements"]:
            if row["id"] in expected:
                self.assertTrue(row["evidence"])
                self.assertIn("NOT_APPLICABLE", row["detail"])
                self.assertIn("author", row["scope"])
        # The subject cannot choose a verdict, including applicability, in its capture.
        raw = copy.deepcopy(self.raw);raw["verdict"] = "NOT_APPLICABLE"
        self.assertEqual(m.inspect(self.catalog, raw, "observer"), result)
        # A missing, extra or different document invalidates NA along with PASS.
        for index in range(len(raw["files"])):
            changed = copy.deepcopy(raw);changed["files"].pop(index)
            report = m.inspect(self.catalog, changed, "observer")
            self.assertEqual(report["totals"], {"PASS": 0, "FAIL": 0, "ERROR": 49, "NOT_APPLICABLE": 0, "NOT_RUN": 2})
            self.assertTrue(all(r["verdict"] == "ERROR" for r in report["statements"] if r["id"] in expected))

    def test_applicability_cannot_promote_an_unreviewed_activity(self):
        original_read = Path.read_text
        def exercise(change):
            def read(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                if path.name == "sage-method-document-review.json":
                    c = json.loads(text);change(c);return json.dumps(c)
                return text
            with patch.object(Path, "read_text", read), self.assertRaises(m.EvidenceError):
                m.load_catalog()
        for identifier in m.NOT_APPLICABLE:
            def selected(c):return next(row for row in c["rows"] if row["id"] == identifier)
            exercise(lambda c: selected(c).pop("review_verdict"))
            exercise(lambda c: selected(c).update(status="pending"))
            exercise(lambda c: selected(c).update(evidence=[]))
            for verdict in (None, False, "PASS", "FAIL", "NOT_RUN", "ERROR", "other"):
                exercise(lambda c, verdict=verdict: selected(c).update(review_verdict=verdict))
        for identifier in (m.REVIEWED | m.DEFERRED | {"did11-cr20260305#security-requirements.1"}):
            for verdict in (None, "PASS", "NOT_APPLICABLE"):
                exercise(lambda c, identifier=identifier, verdict=verdict: next(row for row in c["rows"] if row["id"] == identifier).update(review_verdict=verdict))

    def test_documentary_failures_preserve_levels_and_unknown_evidence(self):
        expected = {"did11-cr20260305#" + suffix for suffix in (
            "security-requirements.1", "security-requirements.2",
            "security-requirements.13", "privacy-requirements.1",
            "security-requirements.5", "security-requirements.6")} | {"res10-crd20261001#vdr-forks.1"}
        report = m.inspect(self.catalog, self.raw, "observer")
        failures = [row for row in report["statements"] if row["verdict"] == "FAIL"]
        self.assertEqual({row["id"] for row in failures}, expected)
        self.assertEqual({row["id"] for row in failures if row["level"] == "recommendation"},
                         {"did11-cr20260305#security-requirements.13", "res10-crd20261001#vdr-forks.1"})
        self.assertTrue(all(row["evidence"] for row in failures))
        self.assertEqual(report["documentary_gate"], "FAIL")
        self.assertFalse(report["runtime_results_merged"])
        raw = copy.deepcopy(self.raw);raw["verdict"] = "PASS"
        self.assertEqual(m.inspect(self.catalog, raw, "observer"), report)
        absent = m.inspect(self.catalog, {}, "observer")
        self.assertEqual(absent["documentary_gate"], "ERROR")
        self.assertEqual(absent["totals"], {"PASS": 0, "FAIL": 0, "ERROR": 49,
                                          "NOT_APPLICABLE": 0, "NOT_RUN": 2})
        self.assertTrue(all(row["verdict"] == "ERROR" for row in absent["statements"] if row["id"] in expected))
        self.assertTrue(all(row["verdict"] == "NOT_RUN" for row in absent["statements"] if row["id"] in m.DEFERRED))
        # A report with unobserved clauses and no known negative is not full conformance.
        with patch.object(m, "FAILURES", set()):
            neutral = m.inspect({**self.catalog, "rows": [row for row in self.catalog["rows"] if row["id"] not in expected]}, self.raw, "observer")
        self.assertEqual(neutral["documentary_gate"], "PASS")

    def test_explicit_failures_cannot_be_changed_into_other_judgments(self):
        original_read = Path.read_text
        def exercise(change):
            def read(path, *args, **kwargs):
                text = original_read(path, *args, **kwargs)
                if path.name == "sage-method-document-review.json":
                    c = json.loads(text);change(c);return json.dumps(c)
                return text
            with patch.object(Path, "read_text", read), self.assertRaises(m.EvidenceError):m.load_catalog()
        for identifier in m.FAILURES:
            def selected(c):return next(row for row in c["rows"] if row["id"] == identifier)
            exercise(lambda c: selected(c).pop("review_verdict"))
            exercise(lambda c: selected(c).update(status="pending"))
            exercise(lambda c: selected(c).update(evidence=[]))
            for verdict in (None, False, "PASS", "NOT_APPLICABLE", "NOT_RUN", "ERROR", "other"):
                exercise(lambda c, verdict=verdict: selected(c).update(review_verdict=verdict))
        for identifier in m.REVIEWED | m.DEFERRED | m.NOT_APPLICABLE | {"res10-crd20261001#method-architectures.1"}:
            exercise(lambda c, identifier=identifier: next(row for row in c["rows"] if row["id"] == identifier).update(review_verdict="FAIL"))

    def test_resolution_author_roles_and_completed_semantic_inventory(self):
        report = m.inspect(self.catalog, self.raw, "observer")
        rows = {row["id"].split("#")[1]: row for row in report["statements"] if row["id"].startswith("res10-crd20261001#")}
        absent = {"dereferencing-algorithm-resource.45", "dereferencing-algorithm-resource.46",
                  "dereferencing-algorithm-resource.47", "did-document-metadata.17",
                  "did-document-metadata.22", "errors.6", "method-architectures.3"}
        self.assertTrue(all(rows[key]["verdict"] == "NOT_APPLICABLE" and rows[key]["evidence"] for key in absent))
        self.assertTrue(all(rows[key]["verdict"] == "PASS" and rows[key]["evidence"]
                            for key in ("method-architectures.1", "method-architectures.2")))
        self.assertEqual(rows["method-architectures.1"]["level"], "recommendation")
        self.assertEqual(rows["method-architectures.2"]["level"], "requirement")
        self.assertEqual(rows["vdr-forks.1"]["verdict"], "FAIL")
        self.assertEqual(rows["vdr-forks.1"]["level"], "recommendation")
        self.assertEqual(report["review_progress"], {"judged": 49, "reviewed_pending": 2, "unreviewed": 0})
        self.assertEqual({row["id"] for row in report["statements"] if row["verdict"] == "NOT_RUN"}, m.DEFERRED)
        self.assertEqual(report["documentary_gate"], "FAIL")
        self.assertFalse(report["runtime_results_merged"])

    def test_resolution_judgments_require_the_whole_reviewed_corpus(self):
        ids = {"res10-crd20261001#" + key for key in (
            "dereferencing-algorithm-resource.45", "dereferencing-algorithm-resource.46",
            "dereferencing-algorithm-resource.47", "did-document-metadata.17",
            "did-document-metadata.22", "errors.6", "method-architectures.1",
            "method-architectures.2", "method-architectures.3", "vdr-forks.1")}
        raw = copy.deepcopy(self.raw);raw["verdict"] = "PASS"
        self.assertEqual(m.inspect(self.catalog, raw, "observer")["totals"]["FAIL"], 7)
        for key in ("format", "repository", "revision"):
            changed = copy.deepcopy(raw);changed[key] = "unreviewed"
            report = m.inspect(self.catalog, changed, "observer")
            self.assertTrue(all(row["verdict"] == "ERROR" for row in report["statements"] if row["id"] in ids))
            self.assertTrue(all(row["verdict"] == "NOT_RUN" for row in report["statements"] if row["id"] in m.DEFERRED))
            self.assertEqual(report["totals"], {"PASS": 0, "FAIL": 0, "ERROR": 49, "NOT_APPLICABLE": 0, "NOT_RUN": 2})

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
                self.assertEqual(m.main(args), 1)
            self.assertEqual(json.loads(out.read_text())["totals"]["PASS"], 23)
            self.assertEqual(json.loads(raw.read_text()), self.raw)
            failed = json.loads(out.read_text())
            self.assertEqual(failed["totals"]["FAIL"], 7)
            self.assertEqual(failed["totals"]["ERROR"], 0)
            self.assertEqual(failed["documentary_gate"], "FAIL")
            # Exercise successful CLI plumbing with a stub, not a new author verdict.
            healthy = {"totals": {"PASS": 0, "FAIL": 0, "ERROR": 0,
                                  "NOT_APPLICABLE": 0, "NOT_RUN": 51}}
            with patch.object(m, "load_catalog", return_value=self.catalog), patch.object(m, "capture", return_value=self.raw), patch.object(m, "inspect", return_value=healthy), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.main(args), 0)
            with patch.object(m, "load_catalog", return_value=self.catalog), patch.object(m, "capture", side_effect=m.EvidenceError("unavailable")), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.main(args), 1)
            self.assertEqual(json.loads(out.read_text())["totals"]["ERROR"], 49)
            self.assertEqual(json.loads(raw.read_text()), {"capture_error": "unavailable"})
            bad = [*args];bad[bad.index("--out") + 1] = str(raw)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):m.main(bad)
            for target in (repo, repo / "file.json"):
                bad = [*args];bad[bad.index("--out") + 1] = str(target)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):m.main(bad)


if __name__ == "__main__":
    unittest.main()
