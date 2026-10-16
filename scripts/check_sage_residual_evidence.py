#!/usr/bin/env python3
"""Check selected original Client evidence and all retained per-clause contracts."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, urlsplit
from check_sage_batch import decode

REPO = Path(__file__).resolve().parents[1]
DID = "did:sage:web:registry.example:agent-1"
CONTEXT = "https://www.w3.org/ns/did/v1.1"
DOCUMENT = {"@context": CONTEXT, "id": DID}
HISTORY = ["res10-crd20261001#did-document-metadata.8", "res10-crd20261001#did-document-metadata.12"]
PROXY = "res10-crd20261001#resolver-architectures-proxied.3"
SELECTED = set(HISTORY + [PROXY])
GROUPS = {"optional": 12, "interpretation": 4, "internal": 5, "tuple": 1}


def expected_requests(kind):
    requests = []
    for index in range(3 if kind == "history-metadata" else 2):
        request = {"function": "resolve", "input": DID, "accept": "application/did"}
        md, dm = {"contentType": "application/did"}, {}
        if kind == "history-metadata":
            version = "8" if index == 1 else "7"
            request["options"] = {"versionId": version}
            dm = {"versionId": version}
            if index == 0:
                dm.update(nextVersionId="8", nextUpdate="2030-01-02T03:04:05Z")
        elif index == 0:
            md = {}
        requests.append((request, {"didDocument": DOCUMENT, "didResolutionMetadata": md, "didDocumentMetadata": dm}))
    return requests


def verify_catalog(report, repo=REPO):
    review = json.loads((repo / "docs/sage-residual-evidence-review.json").read_text())
    anchor = json.loads((repo / "docs/sage-remaining-clause-review.json").read_text())
    live = {r["id"]: r for r in report["statements"]}
    statements = {}
    for publication in ["cid10", "did11-cr20260305", "res10-crd20261001"]:
        statements.update({r["id"]: r for r in json.loads((repo / "statements" / (publication + ".json")).read_text())["statements"]})
    selected = {r["id"]: r for r in anchor["clauses"] if r["review_disposition"] in ["construction-or-permission", "normative-conflict", "needs-internal-observer", "needs-complete-contract"] and (r["expected_live_verdict"] == "NOT_RUN" or r["id"] in SELECTED)}
    assert review["schema"] == "sage-residual-evidence-review/1" and review["profile"] == "did-1.1"
    assert review["baseline_inspector_revision"] == "8f2a8a1eef8778e42268becfa709445fb83827ae"
    rows = review["clauses"]
    assert len(rows) == len({r["id"] for r in rows}) == review["reviewed"] == 22
    assert {r["id"] for r in rows} == set(selected)
    assert collections.Counter(r["group"] for r in rows) == review["groups"] == GROUPS
    assert review["observed"] == 3 and review["pending"] == 19
    for row in rows:
        old, original = selected[row["id"]], statements[row["id"]]
        assert row["text"] == original["text"] and row["level"] == original["level"]
        assert row["text_sha256"] == hashlib.sha256(original["text"].encode()).hexdigest()
        assert row["actor"] and row["reason"] and row["completion_condition"]
        verdict = "PASS" if row["id"] in SELECTED else "NOT_RUN"
        assert row["expected_live_verdict"] == old["expected_live_verdict"] == live[row["id"]]["verdict"] == verdict
        assert row["cases"] == old["cases"]
        if verdict == "NOT_RUN":
            assert not row["cases"] and row["reason"] == old["reason"] and row["completion_condition"] == old["follow_up_condition"]
        dependencies = ["cid10#Multikey.20"] if row["id"] == "cid10#Multikey.21" else ["res10-crd20261001#resolving-algorithm.35"] if row["id"] == "res10-crd20261001#resolving-algorithm.32" else []
        assert row["depends_on"] == dependencies
    return {r["id"] for r in rows}


def verify_client(kind, requests, values):
    fixtures = expected_requests(kind)
    assert len(requests) == len(values) == len(fixtures)
    for index, (q, v, (request, reply)) in enumerate(zip(requests, values, fixtures)):
        assert q["request"] == request and q["post"] is False and json.loads(decode(q["reply"])) == reply
        assert v["request"] == q and v["request"]["post"] is False and v["operation"] == "github.com/sage-x-project/did-go/resolution/universal.Client.resolve"
        endpoint = v["endpoint"]
        u = urlsplit(endpoint)
        assert u.scheme == "https" and u.hostname in ["127.0.0.1", "::1"] and u.port
        assert u.path == "/1.0/identifiers/" and "?" not in endpoint and not u.query and not u.fragment and not u.username and not u.password
        assert v["server_role"] == "controlled client response fixture; not SAGE server output" and v["server_tls"] is True and type(v["server_calls"]) is int and v["server_calls"] == 1
        assert len(v["wire"]) == len(v["consumer"]) == 1 and not v["native"]
        wire, consumer, result = v["wire"][0], v["consumer"][0], v["result"]
        url = endpoint + DID
        if kind == "history-metadata":
            url = endpoint + quote(DID, safe="-._~") + "?versionId=" + request["options"]["versionId"]
        assert wire["url"] == url and wire["method"] == "GET" and wire["accept"] == "application/did"
        assert not any(wire.get(k) for k in ["content_type", "body", "capture_error"])
        assert consumer["operation"] == "github.com/sage-x-project/did-go/consumer.Consumer.Consume" and json.loads(decode(consumer["input"])) == DOCUMENT
        media = "application/json" if kind == "proxy-metadata" and index == 0 else "application/did"
        assert consumer["media_type"] == media and consumer["require"] == consumer["expected"] == "unknown" and consumer["strict"] is False
        assert not consumer.get("error") and not consumer.get("capture_error") and consumer["version"] == "1.1" and consumer["json_ld"] is True
        assert json.loads(decode(consumer["model"])) == {"id": DID} and json.loads(decode(consumer["entries"])) == {"@context": CONTEXT}
        assert result["has_content"] is True and result["returned_id"] == DID
        assert isinstance(result["metadata"], dict) and isinstance(result["content_metadata"], dict) and "error" not in result["metadata"]
        if kind == "history-metadata":
            assert result["content_metadata"]["versionId"] == reply["didDocumentMetadata"]["versionId"]
            if index == 0:
                assert result["content_metadata"]["nextUpdate"] == "2030-01-02T03:04:05Z"
                assert result["content_metadata"]["nextVersionId"] == "8"
            # No absence obligation is invented for MAY omission/latest controls.
        else:
            assert result["metadata"]["contentType"] == "application/did"


def verify_residual(raw, report, repo=REPO):
    assert raw["profile"] == report["profile"] == "did-1.1" and raw["subject"] == report["subject"]
    verify_catalog(report, repo)
    selected = [c for c in raw["cases"] if "/residual-" in c["case"]]
    assert len(selected) == len({c["case"] for c in selected}) == 2
    assert {c["case"].split("/residual-")[1] for c in selected} == {"history-metadata", "proxy-metadata"}
    live = {r["id"]: r for r in report["statements"]}
    for case in selected:
        kind = case["case"].split("/residual-")[1]
        obs = case["observations"]
        ids = HISTORY if kind == "history-metadata" else [PROXY]
        assert [o["statement"] for o in obs] == ids
        assert all(o["verdict"] == "PASS" and o["detail"] and o["input"] and o["observed"] for o in obs)
        assert all(o["input"] == obs[0]["input"] and o["observed"] == obs[0]["observed"] for o in obs)
        verify_client(kind, json.loads(obs[0]["input"]), json.loads(obs[0]["observed"]))
        for identifier in ids:
            assert live[identifier]["verdict"] == "PASS" and case["case"] in live[identifier]["cases"]
    return SELECTED


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    raw = json.loads((args.reports / "resolution-did-1.1-raw.json").read_text())
    report = json.loads((args.reports / "resolution-did-1.1.json").read_text())
    print("Verified", len(verify_residual(raw, report)), "selected downstream observations and nineteen retained evidence boundaries")


if __name__ == "__main__":
    main()
