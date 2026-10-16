#!/usr/bin/env python3
"""Bind pending evidence contracts to reviewed source ZIP and prior-call receipts.

This produces a separate diagnostic assessment, never a conformance verdict.
"""
import argparse
import base64
import collections
import hashlib
import io
import json
from pathlib import Path
import zipfile

from check_sage_extensions import verify_extensions
from check_sage_integer_source import archive_files
from check_sage_residual_evidence import verify_catalog

REPO = Path(__file__).resolve().parents[1]
MANIFEST_SHA = "421ec026463ee40c1210fd7c639186d8db995a5dd9171d406b3baa9f35cc2514"
TOTALS = {"statements": 486, "PASS": 375, "FAIL": 13, "NOT_SUPPORTED": 2,
          "NOT_APPLICABLE": 4, "ERROR": 0, "NOT_RUN": 92}
GROUPS = {"reader-interpretation": 3, "processing-applicability": 3,
          "selected-serializer": 1, "authority-lifecycle": 2,
          "dependent-tuple": 1, "normative-interpretation": 6}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load(text):
    return json.loads(text, object_pairs_hook=unique_object)


def digest(value):
    # Normalize JSON object order only. Numbers, booleans, null and arrays stay distinct.
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()
    return hashlib.sha256(data).hexdigest()


def index_unique(rows, key):
    indexed = {row[key]: row for row in rows}
    assert len(indexed) == len(rows), "duplicate " + key
    return indexed


def verify_source(source, manifest):
    for key, value in manifest["source"].items():
        assert source[key] == value, "source identity: " + key
    assert source["replaced"] is False
    prefix = source["module"] + "@" + source["version"]
    checksum, _ = archive_files(source["archive"], prefix)
    assert checksum == manifest["source"]["sum"], "source ZIP h1"
    selected = manifest["source_zip_files"]
    assert len(index_unique(selected, "path")) == 11
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(source["archive"], validate=True))) as archive:
        for row in selected:
            assert hashlib.sha256(archive.read(prefix + "/" + row["path"])).hexdigest() == row["sha256"], row["path"]
    return {"identity": manifest["source"], "selected_zip_files": selected,
            "archive_sha256": hashlib.sha256(base64.b64decode(source["archive"], validate=True)).hexdigest(),
            "scope": "selected original module ZIP bytes; not source-cache or binary attestation"}


def verify_receipts(raw, report, manifest):
    cases = index_unique(raw["cases"], "case")
    live = index_unique(report["statements"], "id")
    references = manifest["prior_observations"]
    assert len(index_unique(references, "case")) == 6
    for reference in references:
        case = cases[reference["case"]]
        observations = case["observations"]
        assert case["statements"] == reference["statements"]
        assert [o["statement"] for o in observations] == reference["statements"]
        for observation in observations:
            identifier = observation["statement"]
            assert observation["verdict"] == reference["verdicts"][identifier]
            assert observation["detail"] and observation["input"] and observation["observed"]
            assert digest(load(observation["input"])) == reference["input_sha256"]
            assert digest(load(observation["observed"])) == reference["observed_sha256"]
            assert live[identifier]["verdict"] == reference["verdicts"][identifier]
            assert reference["case"] in live[identifier]["cases"]
    # These are reviewed receipt identities, not an oracle derived from subject output.
    # The known producer recommendation FAIL deliberately remains FAIL.
    return references


def verify_pending(report, manifest, repo):
    review = load((repo / "docs/sage-residual-evidence-review.json").read_text())
    pending = {r["id"]: r for r in review["clauses"] if r["expected_live_verdict"] == "NOT_RUN"}
    rows = manifest["clauses"]
    assert len(index_unique(rows, "id")) == len(pending) == 16
    assert {r["id"] for r in rows} == set(pending)
    assert dict(collections.Counter(r["contract_group"] for r in rows)) == manifest["groups"] == GROUPS
    live = index_unique(report["statements"], "id")
    paths = {r["path"] for r in manifest["source_zip_files"]}
    receipts = {r["case"] for r in manifest["prior_observations"]}
    for row in rows:
        old = pending[row["id"]]
        for field in ["text_sha256", "level", "reason", "completion_condition", "depends_on"]:
            assert row[field] == old[field], row["id"] + ": " + field
        assert row["runtime_verdict"] == live[row["id"]]["verdict"] == "NOT_RUN"
        assert row["runtime_cases"] == live[row["id"]].get("cases", []) == []
        assert set(row["source_zip_references"]) <= paths
        assert set(row["prior_observation_references"]) <= receipts
    return rows


def build_assessment(raw, report, repo=REPO):
    contents = (repo / "docs/sage-evidence-prerequisites.json").read_bytes()
    assert hashlib.sha256(contents).hexdigest() == MANIFEST_SHA, "reviewed manifest bytes"
    manifest = load(contents)
    assert manifest["schema"] == "sage-evidence-prerequisites/1"
    assert manifest["profile"] == raw["profile"] == report["profile"] == "did-1.1"
    assert raw["subject"] == report["subject"]
    assert digest(report["totals"]) == digest(TOTALS), "runtime totals changed"
    counts = collections.Counter(r["verdict"] for r in report["statements"])
    assert digest({"statements": len(report["statements"]), **{k: counts[k] for k in TOTALS if k != "statements"}}) == digest(TOTALS)
    assert len(index_unique(raw["cases"], "case")) == len(report["cases"]) == 373
    assert set(index_unique(raw["cases"], "case")) == set(index_unique(report["cases"], "id"))
    verify_extensions(raw, report, repo)
    verify_catalog(report, repo)
    source_case = next(c for c in raw["cases"] if c["case"] == "did-1.1/sage-resolution/extension-codecs")
    source = load(source_case["observations"][0]["observed"])["source"]
    source_evidence = verify_source(source, manifest)
    references = verify_receipts(raw, report, manifest)
    rows = verify_pending(report, manifest, repo)
    return {"schema": "sage-prerequisite-assessment/1",
            "assessment_status": "verified-awaiting-prerequisites",
            "runtime_verdicts_merged": False, "runtime_totals": report["totals"],
            "subject": report["subject"], "inspector": report["inspector"],
            "manifest_sha256": MANIFEST_SHA, "scope": manifest["scope"],
            "source_evidence": source_evidence, "prior_observations": references,
            "groups": GROUPS, "pending_contracts": rows,
            "input_identity": {"raw_sha256": digest(raw), "report_sha256": digest(report)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verify", action="store_true", help="compare an existing sidecar; do not write")
    args = parser.parse_args(argv)
    raw = load((args.reports / "resolution-did-1.1-raw.json").read_text())
    report = load((args.reports / "resolution-did-1.1.json").read_text())
    assessment = build_assessment(raw, report)
    if args.verify:
        assert digest(load(args.out.read_text())) == digest(assessment), "assessment differs from verified evidence"
    else:
        # Exclusive creation prevents overwriting runtime inputs or an existing sidecar.
        with args.out.open("x") as stream:
            stream.write(json.dumps(assessment, indent=2, ensure_ascii=False) + "\n")
    print("Verified 16 pending contracts, 11 source ZIP files and six prior receipts; runtime verdicts unchanged")


if __name__ == "__main__":
    main()
