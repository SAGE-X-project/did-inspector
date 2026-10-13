#!/usr/bin/env python3
"""Verify the frozen review and actual batched library report evidence."""
import argparse
import base64
import collections
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit

REPO = Path(__file__).resolve().parents[1]
CONTEXT_SHA = "ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85"
CONTEXT_URL = "https://www.w3.org/ns/did/v1.1"
ROOT = "github.com/sage-x-project/did-go/"


def decode(value):
    return base64.b64decode(value or "", validate=True)


def jsonbytes(value):
    return json.loads(decode(value))


def verify_review(repo=REPO):
    audit = json.loads((repo / "docs/sage-resolution-batch-review.json").read_text())
    inventory = json.loads((repo / "docs/sage-resolution-gaps.json").read_text())
    assert audit["schema"] == "sage-resolution-batch-review/1"
    assert audit["scope"] == "resolution" and audit["profile"] == "did-1.1"
    assert audit["anchor"]["inspector_revision"] == "97981b8cd7f1ed84b5a8ed9d9c59f25b93de645d"
    rows = audit["clauses"]
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)) == audit["anchor"]["pending"] == 353
    assert hashlib.sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest() == audit["anchor"]["ids_sha256"]
    assert collections.Counter(r["level"] for r in rows) == {"requirement": 306, "recommendation": 47}
    assert dict(collections.Counter(r["review_group"] for r in rows)) == audit["groups"]
    original = {r["id"]: r for r in inventory["pending"] + inventory["observed_since_baseline"]}
    statements = {r["id"]: r for name in ["cid10", "did11-cr20260305", "res10-crd20261001"]
                  for r in json.loads((repo / f"statements/{name}.json").read_text())["statements"]}
    for r in rows:
        assert r["status"] == "reviewed-no-verdict" and "verdict" not in r
        assert r["actor"] and r["evidence_required"]
        assert r["text"] == statements[r["id"]]["text"]
        assert r["level"] == original[r["id"]]["level"]
        assert r["historical_route"] == original[r["id"]]["route"]
        assert r["text_sha256"] == original[r["id"]]["text_sha256"] == hashlib.sha256(r["text"].encode()).hexdigest()
    assert {r["id"] for r in inventory["pending"]}.issubset(set(ids))
    newly_observed = [r for r in inventory["observed_since_baseline"] if r["id"] in set(ids) and r["case_prefix"].startswith("/library-")]
    assert len(newly_observed) == 61
    assert collections.Counter(r["expected_live_verdict"] for r in newly_observed) == {"PASS": 60, "FAIL": 1}
    assert hashlib.sha256((repo / "profiles/sageresolution/did-v1.1-context.jsonld").read_bytes()).hexdigest() == CONTEXT_SHA
    return set(ids)


def btc(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    leading = len(data) - len(data.lstrip(b"\0"))
    return "z" + "1" * leading + encoded


def verify_syntax(q, out):
    assert len(out) == len(q["items"])
    actors = {"did": ROOT + "did.Parse", "url": ROOT + "did.ParseURL",
              "reference": ROOT + "did.ParseReference+DIDURL.Resolve"}
    for item, call in zip(q["items"], out):
        assert call["request"] == item["request"] and call["operation"] == actors[item["request"]["kind"]]
        if item["accepted"]:
            assert not call.get("error") and call["value"] == item["value"]
        else:
            assert call.get("error")


def verify_codec(q, out):
    f = q["fixture"]
    table = {("P-256", False): ("8024", 33), ("P-384", False): ("8124", 49),
             ("Ed25519", False): ("ed01", 32), ("BLS12-381-G2", False): ("eb01", 96),
             ("SM2", False): ("8624", 33), ("P-256", True): ("8626", 32),
             ("P-384", True): ("8726", 48), ("Ed25519", True): ("8026", 32),
             ("SM2", True): ("9026", 32)}
    prefix, length = table[f["name"], f["secret"]]
    assert decode(f["prefix"]) == bytes.fromhex(prefix) and f["length"] == length
    assert len(out) == len(q["requests"]) == 2
    for request, call in zip(q["requests"], out):
        key = decode(request["key"])
        assert len(key) == length and request["name"] == f["name"] and request["secret"] == f["secret"]
        assert request["encoded"] == btc(bytes.fromhex(prefix) + key)
        assert call["request"] == request and call["operation"] == ROOT + "vm.EncodeMultikey+DecodeMultikey"
        assert not call.get("encode_error") and not call.get("decode_error")
        assert call["name"] == call["decode_name"] == f["name"]
        assert decode(call["prefix"]) == decode(call["decode_prefix"]) == bytes.fromhex(prefix)
        assert call["length"] == call["decode_length"] == length
        assert call["secret"] == call["decode_secret"] == f["secret"]
        assert call["encoded"] == request["encoded"] and decode(call["decoded"]) == key


def verify_client(q, out):
    fixture = q["request"]
    request = fixture["request"]
    assert out["request"] == fixture and out["operation"] == ROOT + "resolution/universal.Client." + request["function"]
    assert len(out["wire"]) == out["server_calls"] == 1 and out["server_tls"]
    wire = out["wire"][0]
    endpoint, target = urlsplit(out["endpoint"]), urlsplit(wire["url"])
    assert endpoint.scheme == target.scheme == "https" and endpoint.hostname == target.hostname == "127.0.0.1"
    assert endpoint.netloc == target.netloc and not endpoint.username and not target.username
    assert endpoint.path == "/1.0/identifiers/" and not endpoint.query and not endpoint.fragment and not target.fragment
    assert not wire.get("capture_error")
    assert wire["method"] == ("POST" if fixture["post"] else "GET")
    options = request.get("options", {})
    accept = request.get("accept") or ("application/did-resolution" if request["function"] == "resolve" else "application/did-url-dereferencing")
    assert wire["accept"] == accept
    identifier = request["input"]
    if (not fixture["post"] and options) or any(c in identifier for c in "?#%"):
        identifier = quote(identifier, safe="-._~")
    assert target.path == endpoint.path + identifier
    if fixture["post"]:
        assert not target.query
        if options:
            assert jsonbytes(wire["body"]) == options and wire["content_type"] == "application/json"
        else:
            assert not decode(wire["body"]) and not wire["content_type"]
    else:
        assert not decode(wire["body"]) and not wire["content_type"]
        assert ";" not in target.query
        pairs = parse_qsl(target.query, keep_blank_values=True, strict_parsing=True, errors="strict") if target.query else []
        assert len(pairs) == len(dict(pairs)) == len(options)
        assert dict(pairs) == {k: ("true" if v is True else str(v)) for k, v in options.items()}
    if fixture.get("reply"):
        assert out["server_role"] == "controlled client response fixture; not SAGE server output" and not out["native"]
        reply = jsonbytes(fixture["reply"])
        assert len(out["consumer"]) == 1
        c = out["consumer"][0]
        media = reply["didResolutionMetadata"]["contentType"]
        assert c["operation"] == ROOT + "consumer.Consumer.Consume" and c["media_type"] == media
        assert c["version"] == ("1.1" if media == "application/did" else "1.0")
        assert jsonbytes(c["input"]) == reply["didDocument"] and not c.get("error") and not c.get("capture_error")
    else:
        assert out["server_role"] == "universal handler with SAGE resolver and explicit fixture Source" and len(out["native"]) == 1
        c = out["native"][0]
        expected = dict(options)
        if request.get("accept"):
            expected["accept"] = request["accept"]
        assert c["function"] == request["function"] and c["input"] == request["input"] and jsonbytes(c["options"]) == expected
        assert not c.get("capture_error") and c["result"]["has_content"] and c["result"]["returned_id"] == request["input"]
    assert out["result"]["has_content"] and out["result"]["returned_id"] == request["input"]


def verify_retrieval(q, out, obs):
    request = q["request"]
    assert out["operation"] == ROOT + "relyingparty.RelyingParty.VerificationMethod" and out["clock"] == 1800000000
    assert out["reference"] == request["reference"] and out["purpose"] == request["purpose"] and not out.get("capture_error")
    if request["zero"]:
        assert not out["calls"]
    else:
        assert len(out["calls"]) == 1
        c = out["calls"][0]
        assert c["input"] == q["record"]["did"] and jsonbytes(c["options"]) == request.get("options", {})
        assert c["result"]["has_content"] and c["result"]["content_kind"] == "document"
    if q.get("problem"):
        assert out.get("error") and not decode(out["method"])
        assert out["problem_serializer"] == "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
        p = jsonbytes(out["problem"])
        assert p["type"] == "https://w3id.org/security#" + q["problem"]
        titles = {"INVALID_VERIFICATION_METHOD_URL": "Invalid verification method URL",
                  "INVALID_VERIFICATION_METHOD": "Invalid verification method",
                  "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD": "Invalid relationship for verification method"}
        assert p["title"] == titles[q["problem"]] and p["detail"]
        assert all(o["verdict"] == "PASS" for o in obs)
    else:
        assert not out.get("error") and not decode(out["problem"])
        method = jsonbytes(out["method"])
        doc = out["calls"][0]["result"]["snapshot"]
        assert method["id"] == request["reference"] and method["controller"] == q["record"]["did"]
        assert method in doc["verificationMethod"] and method["id"] in doc["authentication"]


def verify_document(q, out):
    for key in ["positive", "negative"]:
        request, c = q[key], out[key]
        assert request["data"] == c["input"] and request["media_type"] == c["media_type"] == "application/did"
        assert c["operation"] == ROOT + "consumer.Consumer.Consume"
        assert c["require"] == c["expected"] == "unknown" and not c["strict"]
    positive, negative = out["positive"], out["negative"]
    assert not positive.get("error") and not positive.get("capture_error") and positive["version"] == "1.1"
    assert jsonbytes(positive["model"]) == jsonbytes(q["positive"]["data"]) and jsonbytes(positive["entries"]) == {}
    assert negative.get("error") and not decode(negative["model"]) and not decode(negative["entries"])


def verify_context(case, q, out, obs):
    if case.endswith("-cache"):
        assert out["operation"] == ROOT + "jsonld.BaseContext" and out["version"] == "1.1" and out["url"] == CONTEXT_URL
        assert not out.get("error") and hashlib.sha256(decode(out["data"])).hexdigest() == CONTEXT_SHA
        assert obs[0]["verdict"] == "PASS"
    elif "-consumer-" in case:
        assert out["operation"] == ROOT + "consumer.Consumer.Consume" and out["input"] == q["data"] and out["media_type"] == q["media_type"]
        assert not out.get("error") and not out.get("capture_error") and out["version"] == "1.1" and out["json_ld"]
        source = jsonbytes(q["data"])
        assert source.pop("@context") == CONTEXT_URL and source.pop("inspectionNote") == "public test term"
        assert jsonbytes(out["model"]) == source and jsonbytes(out["entries"]) == {"@context": CONTEXT_URL}
        assert out["dropped_terms"] == ["inspectionNote"] and obs[0]["verdict"] == "PASS"
    else:
        for key in ["positive", "negative"]:
            result = out[key]
            request = q[key]
            assert not result.get("build_error") and not result.get("capture_error") and len(result["calls"]) == 1
            c = result["calls"][0]
            assert c["operation"] == ROOT + "producer.Producer.Produce" and c["version"] == "1.1" and c["json_ld"] and not c["include_secret"]
            assert not c.get("error") and not c.get("capture_error") and c["media_type"] == "application/did"
            expected = {"id": request["id"], "controller": request["controllers"]}
            if key == "negative":
                expected["inspectionNote"] = "public test term"
            assert jsonbytes(c["model"]) == expected and jsonbytes(c["entries"]) == {}
            expected["@context"] = CONTEXT_URL
            assert jsonbytes(c["output"]) == expected
        assert obs[0]["verdict"] == "FAIL" and obs[0]["statement"] == "did11-cr20260305#json-ld-processors.6"


def verify_batch(raw, report):
    assert raw["profile"] == report["profile"] == "did-1.1" and raw["subject"] == report["subject"]
    # RunResult has no inspector identity; CI separately binds the report,
    # compiled binary and source/merge tree to GITHUB_SHA.
    selected = [c for c in raw["cases"] if "/library-" in c["case"]]
    counts = collections.Counter(c["case"].split("/library-")[1].split("-")[0] for c in selected)
    assert counts == {"syntax": 4, "codec": 9, "client": 18, "retrieval": 5, "document": 6, "context": 3}
    checked = set()
    for c in selected:
        obs = c["observations"]
        assert obs and len({o["statement"] for o in obs}) == len(obs)
        for o in obs:
            assert o["input"] and o["observed"] and o["detail"]
            checked.add(o["statement"])
        q, out = json.loads(obs[0]["input"]), json.loads(obs[0]["observed"])
        assert all(o["input"] == obs[0]["input"] and o["observed"] == obs[0]["observed"] for o in obs)
        if "/library-syntax-" in c["case"]:
            verify_syntax(q, out)
        elif "/library-codec-" in c["case"]:
            verify_codec(q, out)
        elif "/library-client-" in c["case"]:
            verify_client(q, out)
        elif "/library-retrieval-" in c["case"]:
            verify_retrieval(q, out, obs)
        elif "/library-document-" in c["case"]:
            verify_document(q, out)
        else:
            verify_context(c["case"], q, out, obs)
        expected = "FAIL" if "context-producer-" in c["case"] else "PASS"
        assert all(o["verdict"] == expected for o in obs)
    assert len(checked) == 61
    live = {r["id"]: r["verdict"] for r in report["statements"]}
    assert set(checked) == {r["id"] for r in json.loads((REPO / "docs/sage-resolution-batch-review.json").read_text())["clauses"] if r["id"] in {row["id"] for row in json.loads((REPO / "docs/sage-resolution-gaps.json").read_text())["observed_since_baseline"] if row["case_prefix"].startswith("/library-")}}
    assert collections.Counter(live[i] for i in checked) == {"PASS": 60, "FAIL": 1}
    return checked


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    verify_review()
    raw = json.loads((args.reports / "resolution-did-1.1-raw.json").read_text())
    report = json.loads((args.reports / "resolution-did-1.1.json").read_text())
    verify_batch(raw, report)
    print("Verified all 353 reviewed clauses and 61 new observations across 45 actual library cases")


if __name__ == "__main__":
    main()
