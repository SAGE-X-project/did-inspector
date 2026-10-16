"""Replay independently reviewed author judgments against a fixed Git document corpus.

This is evidence verification for an exact reviewed revision, not a semantic
classifier for arbitrary prose. Runtime reports and their pending ledger are
never inputs or outputs of this command.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REVISION = "06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b"
REPOSITORY = "SAGE-X-project/sage-spec"
REVIEWED = {"did11-cr20260305#" + s for s in (
    "method-syntax.1", "method-syntax.2", "method-syntax.3", "method-syntax.7",
    "method-syntax.8", "method-syntax.10", "method-syntax.11", "method-syntax.12",
    "method-operations.2", "method-operations.4", "method-operations.5", "media-types.1",
    "security-requirements.3", "security-requirements.4", "security-requirements.7",
    "security-requirements.8", "security-requirements.9", "security-requirements.11")} | {"res10-crd20261001#" + s for s in (
    "method-architectures.1",
    "method-architectures.2",)}
# These cases review absent author activities, not implementation capabilities.
NOT_APPLICABLE = {"cid10#Multikey.24"} | {"did11-cr20260305#" + s for s in (
    "extensibility.2", "extensibility.3", "extensibility.4",
    "production-and-consumption.1", "production-and-consumption.2",
    "production-and-consumption.3", "production-and-consumption.4",
    "production-and-consumption.5", "production-and-consumption.6",
    "security-requirements.12", "security-requirements.14")} | {"res10-crd20261001#" + s for s in (
    "dereferencing-algorithm-resource.45",
    "dereferencing-algorithm-resource.46",
    "dereferencing-algorithm-resource.47",
    "did-document-metadata.17",
    "did-document-metadata.22",
    "errors.6",
    "method-architectures.3",)}
FAILURES = {"did11-cr20260305#" + s for s in (
    "security-requirements.1", "security-requirements.2",
    "security-requirements.13", "privacy-requirements.1")} | {"res10-crd20261001#" + s for s in (
    "vdr-forks.1",)}
DEFERRED = {"did11-cr20260305#" + s for s in (
    "method-operations.1", "method-operations.3", "method-syntax.4", "method-syntax.5",
    "security-requirements.5", "security-requirements.6", "security-requirements.10")}


class EvidenceError(ValueError):
    """Missing or unreviewed evidence; never a normative failure."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_catalog(root=ROOT):
    """Bind every review row to independently frozen normative statement bytes."""
    c = json.loads((root / "docs/sage-method-document-review.json").read_text())
    if (c.get("format") != "did-inspector-method-document-review/1" or
            c.get("repository") != REPOSITORY or c.get("revision") != REVISION):
        raise EvidenceError("unreviewed catalog identity")
    originals = {}
    for filename in ("cid10.json", "did11-cr20260305.json", "res10-crd20261001.json"):
        source = json.loads((root / "statements" / filename).read_text())
        if digest((root / "statements" / source["source"]).read_bytes()) != source["sha256"]:
            raise EvidenceError("frozen publication drift")
        originals.update({s["id"]: s for s in source["statements"]})
    anchor = json.loads((root / "docs/sage-remaining-clause-review.json").read_text())
    expected = {s["id"] for s in anchor["clauses"] if s["review_disposition"] == "needs-method-spec"}
    ids = [s["id"] for s in c["rows"]]
    if len(ids) != 51 or len(set(ids)) != 51 or set(ids) != expected:
        raise EvidenceError("documentary inventory drift")
    paths = [f["path"] for f in c["files"]]
    if len(paths) != 16 or len(set(paths)) != 16:
        raise EvidenceError("source manifest drift")
    reviewed = set()
    reviewed_non_pass = set()
    for row in c["rows"]:
        original = originals[row["id"]]
        if row["text"] != original["text"] or row["text_sha256"] != digest(original["text"].encode()):
            raise EvidenceError("statement identity drift")
        row["level"] = original["level"]
        if row["status"] not in ("reviewed-document", "pending") or not row["review_basis"] or not row["scope"]:
            raise EvidenceError("review contract missing")
        pending = row.get("pending_review")
        if row["id"] in DEFERRED:
            if (row["status"] != "pending" or not isinstance(pending, dict) or
                    set(pending) != {"verdict", "required_actor", "reason", "completion_evidence"} or
                    pending["verdict"] != "NOT_RUN" or
                    any(not isinstance(pending[k], str) or not pending[k].strip() for k in ("required_actor", "reason")) or
                    not isinstance(pending["completion_evidence"], list) or not pending["completion_evidence"] or
                    any(not isinstance(x, str) or not x.strip() for x in pending["completion_evidence"])):
                raise EvidenceError("unresolved review boundary missing or changed")
        elif "pending_review" in row:
            raise EvidenceError("unreviewed pending assessment")
        expected_verdict = ("FAIL" if row["id"] in FAILURES else
                    "NOT_APPLICABLE" if row["id"] in NOT_APPLICABLE else None)
        if "review_verdict" in row:
            if (expected_verdict is None or row["status"] != "reviewed-document" or
                    row["review_verdict"] != expected_verdict):
                raise EvidenceError("unreviewed explicit judgment")
            reviewed_non_pass.add(row["id"])
        if row["status"] == "reviewed-document":
            if row["id"] not in NOT_APPLICABLE | FAILURES:
                reviewed.add(row["id"])
            if not row["evidence"]:
                raise EvidenceError("review evidence missing")
    if reviewed != REVIEWED or reviewed_non_pass != NOT_APPLICABLE | FAILURES:
        raise EvidenceError("unreviewed judgment added or removed")
    return c


def capture(repository, catalog):
    """Read committed blobs only: working files, replace refs and hooks cannot supply prose."""
    def git(*args):
        try:
            return subprocess.check_output(
                ["git", "--no-replace-objects", "-C", str(repository), *args],
                stderr=subprocess.PIPE, timeout=15)
        except (OSError, subprocess.SubprocessError) as error:
            raise EvidenceError("pinned Git object unavailable") from error
    if git("rev-parse", "--verify", REVISION + "^{commit}").decode().strip() != REVISION:
        raise EvidenceError("unreviewed Git revision")
    files = []
    for f in catalog["files"]:
        content = git("cat-file", "blob", REVISION + ":" + f["path"])
        files.append({"path": f["path"], "content_base64": base64.b64encode(content).decode("ascii")})
    return {"format": "did-inspector-method-document-capture/1", "repository": REPOSITORY,
            "revision": REVISION, "files": files}


def verify_capture(capture_data, catalog):
    """Require the exact full reviewed corpus before replaying any author judgment."""
    if not isinstance(capture_data, dict):
        raise EvidenceError("capture must be an object")
    if (capture_data.get("format") != "did-inspector-method-document-capture/1" or
            capture_data.get("repository") != REPOSITORY or capture_data.get("revision") != REVISION):
        raise EvidenceError("capture identity mismatch")
    files = capture_data["files"]
    if not isinstance(files, list):
        raise EvidenceError("capture files must be an array")
    actual = {}
    for f in files:
        if not isinstance(f, dict) or not isinstance(f.get("path"), str) or not isinstance(f.get("content_base64"), str):
            raise EvidenceError("invalid captured file shape")
        if f["path"] in actual:
            raise EvidenceError("duplicate captured file")
        try:
            content = base64.b64decode(f["content_base64"], validate=True)
            content.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise EvidenceError("invalid captured bytes") from error
        actual[f["path"]] = content
    if set(actual) != {f["path"] for f in catalog["files"]}:
        raise EvidenceError("incomplete or extra corpus")
    for f in catalog["files"]:
        data = actual[f["path"]]
        if len(data) != f["bytes"] or digest(data) != f["sha256"]:
            raise EvidenceError("unreviewed document bytes: " + f["path"])
    for row in catalog["rows"]:
        for evidence in row["evidence"]:
            lines = actual[evidence["path"]].decode().splitlines(keepends=True)
            a, b = evidence["start_line"], evidence["end_line"]
            if (type(a) is not int or type(b) is not int or not 1 <= a <= b <= len(lines) or
                    digest("".join(lines[a - 1:b]).encode()) != evidence["sha256"]):
                raise EvidenceError("reviewed excerpt mismatch")
    return actual


def inspect(catalog, capture_data, observer):
    """Return a separate 51-clause author report; absent cases stay NOT_RUN."""
    issue = None
    try:
        verify_capture(capture_data, catalog)
    except (EvidenceError, KeyError, TypeError) as error:
        issue = str(error)
    rows = []
    for source in catalog["rows"]:
        selected = source["id"] in REVIEWED | NOT_APPLICABLE | FAILURES
        verdict = ("ERROR" if issue else source.get("review_verdict", "PASS")) if selected else "NOT_RUN"
        rows.append({"id": source["id"], "level": source["level"], "text_sha256": source["text_sha256"],
                     "verdict": verdict, "scope": source["scope"],
                     "detail": issue if selected and issue else source["review_basis"],
                     "evidence": source["evidence"] if selected else [],
                     "follow_up": source["follow_up"]})
        if "pending_review" in source:
            rows[-1]["pending_review"] = source["pending_review"]
    totals = {k: sum(row["verdict"] == k for row in rows) for k in ("PASS", "FAIL", "ERROR", "NOT_APPLICABLE", "NOT_RUN")}
    return {"format": "did-inspector-method-document-report/1", "inspector_revision": observer,
            "actor": "SAGE method specification author", "repository": REPOSITORY,
            "revision": REVISION, "policy": catalog["policy"], "totals": totals,
            "statements": rows, "runtime_results_merged": False,
            "documentary_gate": "ERROR" if totals["ERROR"] else "FAIL" if totals["FAIL"] else "PASS",
            "review_progress": {"judged": len(REVIEWED | NOT_APPLICABLE | FAILURES), "reviewed_pending": len(DEFERRED),
                                "unreviewed": len(rows) - len(REVIEWED | NOT_APPLICABLE | FAILURES) - len(DEFERRED)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--raw-out", type=Path, required=True)
    parser.add_argument("--inspector-revision", required=True)
    args = parser.parse_args(argv)
    # Never overwrite a source file or silently replace one output with the other.
    outputs = [args.out.resolve(), args.raw_out.resolve()]
    repo = args.repository.resolve()
    if outputs[0] == outputs[1] or any(p == repo or repo in p.parents for p in outputs):
        parser.error("outputs must be distinct and outside the subject checkout")
    catalog = load_catalog()
    try:
        raw = capture(repo, catalog)
    except EvidenceError as error:
        raw = {"capture_error": str(error)}
    result = inspect(catalog, raw, args.inspector_revision)
    for p, value in [(args.out, result), (args.raw_out, raw)]:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps(result["totals"], sort_keys=True))
    return int(result["totals"]["ERROR"] != 0 or result["totals"]["FAIL"] != 0)


if __name__ == "__main__":
    sys.exit(main())
