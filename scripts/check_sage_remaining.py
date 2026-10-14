#!/usr/bin/env python3
"""Verify all anchored clause reviews and fresh grouped operation evidence."""
import argparse
import collections
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from check_sage_batch import decode, jsonbytes
from check_sage_contracts import semantic_equal

REPO = Path(__file__).resolve().parents[1]
DID = "did:sage:web:registry.example:agent-1"
ANCHOR_IDS = "310ad0e0403bd6bc83d361dc180d57d8c5b822c13db6211544e34c5181f1a978"
FORWARD = "res10-crd20261001#dereferencing-algorithm-resource.5"
KID = "cid10#JsonWebKey.5"
PROXY = "res10-crd20261001#resolver-architectures-proxied.2"
ROLE = "root resolver/dereferencer library with literal example driver; not SAGE Source"


def owned(endpoint):
    u = urlsplit(endpoint)
    assert u.scheme == "https" and u.hostname in ["127.0.0.1", "::1"] and u.port
    assert not u.username and not u.password and not u.fragment


def verify_review(report, repo=REPO):
    audit = json.loads((repo / "docs/sage-remaining-clause-review.json").read_text())
    ledger = json.loads((repo / "docs/sage-resolution-gaps.json").read_text())
    frozen = {r["id"]: r for r in json.loads((repo / "docs/sage-resolution-batch-review.json").read_text())["clauses"]}
    rows = audit["clauses"]
    ids = [r["id"] for r in rows]
    assert audit["schema"] == "sage-remaining-clause-review/1" and audit["profile"] == "did-1.1"
    assert audit["anchor_inspector_revision"] == "1efc9f0d4818414ca87c65deedcedb64eca7f2f6"
    assert len(ids) == len(set(ids)) == audit["anchor_pending_count"] == 246
    assert hashlib.sha256(json.dumps(sorted(ids), separators=(",", ":")).encode()).hexdigest() == audit["anchor_pending_ids_sha256"] == ANCHOR_IDS
    live = {r["id"]: r for r in report["statements"]}
    historical = {r["id"]: r for r in ledger["pending"] + ledger["observed_since_baseline"]}
    for r in rows:
        previous, actual = frozen[r["id"]], live[r["id"]]
        assert r["text"] == previous["text"] and r["text_sha256"] == previous["text_sha256"] == hashlib.sha256(r["text"].encode()).hexdigest()
        for key in ["level", "keywords", "baseline_verdict", "route", "generic_scope"]:
            assert r[key] == historical[r["id"]][key]
        assert r["actor"] and r["applicable_evidence"] and r["reason"] and r["follow_up_condition"]
        assert r["expected_live_verdict"] == actual["verdict"]
        if actual["verdict"] == "NOT_RUN":
            assert r["status"] == "reviewed-awaiting-evidence" and not r["cases"]
        else:
            assert r["status"] == "observed-selected-branch" and r["cases"]
    assert collections.Counter(r["review_disposition"] for r in rows) == audit["review_counts"]
    assert collections.Counter(r["expected_live_verdict"] for r in rows) == audit["execution_counts"] == {"PASS": 80, "FAIL": 3, "NOT_APPLICABLE": 2, "NOT_RUN": 161}
    return {r["id"] for r in rows if r["status"] == "observed-selected-branch" and any("/remaining-" in c for c in r["cases"])}


def verify_values(q, values, repo):
    f = next(f for f in json.loads((repo / "profiles/sageresolution/value_cases.json").read_text()) if f["name"] == q["name"])
    assert all(q[k] == f[k] for k in ["name", "kind", "statements", "permission", "values"])
    assert q["field"] == q["name"].split("-")[0] or q["field"] in ["proof", "error", "noCache", "equivalentId", "canonicalId"]
    prefix = "document.Metadata" if q["kind"] == "document-metadata" else "resolution.ResolutionOptions" if q["kind"] == "resolution-options" else "resolution.ResolutionMetadata"
    prefix = "github.com/sage-x-project/did-go/" + prefix
    assert len(values) == len(f["values"])
    for vector, v in zip(f["values"], values):
        assert v["request"]["kind"] == q["kind"] and v["request"]["subject"] == DID
        assert jsonbytes(v["request"]["input"]) == vector["input"] and v["reader"] == prefix + ".UnmarshalJSON"
        failure = v.get("read_error") or v.get("validation_error") or v.get("write_error")
        if failure:
            assert not vector["valid"] and not decode(v["output"])
            continue
        assert v["writer"] == prefix + ".MarshalJSON" and v["validator"] == prefix + (".Check" if q["kind"] == "document-metadata" else ".Validate")
        result = jsonbytes(v["output"])
        assert isinstance(result, dict)
        field = q["field"]
        if field not in result:
            assert q["permission"]
            continue
        value = result[field]
        if field in ["created", "updated", "nextUpdate"]:
            assert isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value)
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        elif field == "nextVersionId":
            assert isinstance(value, str) and value.isascii()
        elif field == "equivalentId":
            assert isinstance(value, list) and all(isinstance(x, str) and x.startswith("did:") for x in value)
        elif field == "canonicalId":
            assert isinstance(value, str) and value.startswith("did:")
        elif field == "proof":
            assert isinstance(value, list) and all(isinstance(x, dict) for x in value)
        if vector["valid"]:
            for name, expected in vector["input"].items():
                if name in result:
                    assert semantic_equal(result[name], expected, "metadata")


def consumed(q, v, refused=False):
    assert v["operation"] == "github.com/sage-x-project/did-go/consumer.Consumer.Consume"
    assert v["input"] == q["data"] and v["media_type"] == q["media_type"] == "application/did"
    assert (not v.get("capture_error") or refused and v.get("capture_error")=="no actual document accessor maps") and v["require"] == v["expected"] == "unknown" and not v["strict"]
    if refused:
        assert v.get("error") and not decode(v["model"]) and not decode(v["entries"])
    else:
        assert not v.get("error") and v["version"] == "1.1" and not v["json_ld"] and not v["dropped_terms"]
        assert jsonbytes(v["entries"]) == {} and semantic_equal(jsonbytes(v["input"]), jsonbytes(v["model"]), "document")


def typed_json(v, normalized=False):
    kind = v["kind"]
    if kind == "string":
        return v.get("text", "")
    if kind in ["integer", "double"]:
        return int(v["text"]) if kind == "integer" else float(v["text"])
    if kind == "boolean":
        return v.get("flag", False)
    if kind == "null":
        return None
    if kind == "list":
        return [typed_json(x, normalized) for x in v.get("items", [])]
    if kind == "map":
        return {x["name"]: typed_json(x["value"], normalized) for x in v.get("members", [])}
    assert kind == "datetime"
    return datetime.fromisoformat(re.sub(r"(\d{2}:\d{2}:\d{2})\.\d+", r"\1", v["text"])).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if normalized else v["text"]


def verify_fields(name, q, v):
    if name.endswith("-shape"):
        consumed(q["positive"], v["positive"])
        consumed(q["negative"], v["negative"], True)
    elif name == "substructures":
        assert q["id"] == v["id"] == DID and q["fields"] == v["fields"] and q["entries"] == v["entries"]
        assert len(v["calls"]) == 1
        producer = v["calls"][0]
        assert producer["operation"] == "github.com/sage-x-project/did-go/producer.Producer.Produce"
        assert not producer.get("capture_error") and not producer.get("error") and producer["version"] == "1.1" and not producer["json_ld"]
        model = {"id": DID, "controller": q["controllers"]}
        model.update({f["name"]: typed_json(f["value"]) for f in q["fields"]})
        entries = {f["name"]: typed_json(f["value"]) for f in q["entries"]}
        expected = {"id": DID, "controller": q["controllers"], **entries}
        expected.update({f["name"]: typed_json(f["value"], True) for f in q["fields"]})
        assert semantic_equal(jsonbytes(producer["model"]), model, "metadata") and jsonbytes(producer["entries"]) == entries
        assert semantic_equal(jsonbytes(producer["output"]), expected, "metadata")
    else:
        consumed(q["control"], v["control"])
        assert len(q["variants"]) == len(v["variants"]) == 2
        for request, capture in zip(q["variants"], v["variants"]):
            consumed(request, capture)


def verify_routing(q, v, obs, repo):
    f = next(f for f in json.loads((repo / "profiles/sageresolution/routing_cases.json").read_text()) if f["name"] == q["name"])
    assert q == f and v["role"] == ROLE and not v.get("capture_error")
    assert v["request"]["request"] == f["request"] and jsonbytes(v["request"]["document"]["data"]) == f["document"]
    assert v["operation"] == "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference"
    assert v["resolve_inputs"] == ["did:example:123"] and len(v["resolve_options"]) == 1
    if f["name"].startswith("forward-"):
        actual = jsonbytes(v["resolve_options"][0])
        expected = dict(f["forwarded_options"])
        if f["name"] == "forward-uri-options":
            assert actual != expected and expected.pop("accept") == "text/uri-list"
        assert actual == expected
        return
    md, cm = v["result"]["metadata"], v["result"]["content_metadata"]
    if f["error_type"]:
        typ = md["error"]["type"]
        assert urlsplit(typ).scheme in ["https", "http"] and urlsplit(typ).netloc
        if f["error_type"] != "ANY":
            assert typ == "https://www.w3.org/ns/did#" + f["error_type"]
        assert not v["result"]["has_content"] and jsonbytes(v["result"]["raw"]) is None and cm == {}
    else:
        assert v["result"]["has_content"] and "error" not in md and md["contentType"] == f["request"]["accept"]
        actual = jsonbytes(v["data_model"]) if v["result"].get("content_kind") == "document" else jsonbytes(v["result"]["raw"])
        assert semantic_equal(actual, f["expected_content"], "set" if isinstance(actual, list) else "document")


def verify_operations(q, values):
    assert len(q) == len(values)
    for request, v in zip(q, values):
        assert v["request"] == request
        if request["kind"] == "parameters":
            assert v["parse_operation"] == "github.com/sage-x-project/did-go/did.ParseURL"
            if not v.get("error"):
                assert v["operation"] == "github.com/sage-x-project/did-go/did.DIDURL.Parameters" and v["wire"] == request["input"]
                assert v["wire"].isascii()
                if "versionTime" in v["values"]:
                    assert v["version_time"] == v["values"]["versionTime"] == "2030-01-02T03:04:05Z"
                else:
                    assert v["values"] == {"service": "one", "relativeRef": "../send", "extension": "✓"}
            else:
                assert not v["values"] and not v["version_time"]
        else:
            assert v["operation"] == "github.com/sage-x-project/did-go/resolution/cache.Resolver.Resolve" and len(v["results"]) == 3
            assert v["calls"] == (1 if request["refuse"] else 2)
            for i, result in enumerate(v["results"]):
                if request["refuse"] and i == 1:
                    assert result["metadata"]["error"]["type"] == "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED"
                    assert result["metadata"]["error"]["detail"] == "bypassing the cache (noCache) is not permitted by this resolver; resolve again without noCache"
                    assert not decode(result.get("raw"))
                else:
                    assert "error" not in result["metadata"] and jsonbytes(result["raw"]) == {"id": "did:example:123"}


def verify_transports(name, q, v, repo):
    if name == "trust-mutual-tls":
        assert len(v) == 2 and not v[0]["client_missing"] and v[1]["client_missing"]
        for x in v:
            owned(x["endpoint"])
            assert x["role"] == "actual universal Client with owned self-hosted SAGE handler and explicit fixture Source; no operational trust claim"
            assert not x.get("capture_error") and decode(x["client_certificate"]) and decode(x["server_certificate"])
        good, bad = v
        assert good["client_verified"] and good["server_verified"] and good["tls_version"] >= 0x0303 and good["http_calls"] == 1
        assert good["client_peer"] == good["client_certificate"] and good["server_peer"] == good["server_certificate"]
        assert good["client_result"]["has_content"] and good["client_result"]["returned_id"] == DID
        assert bad["http_calls"] == 0 and not bad["client_verified"] and not bad["client_result"]["has_content"] and bad["client_result"]["metadata"]["error"]["type"]
    elif name.startswith("binding-uri-list-"):
        x = v["exchange"]
        owned(x["url"])
        assert x["tls"] and x["method"] == v["method"] == q["Method"] and v["request"] == q["Request"]
        assert not v.get("capture_error") and len(v["native"]) == 1
        n = v["native"][0]
        assert n["function"] == "dereference" and n["input"] == q["Request"]["request"]["input"] and not n.get("capture_error")
        assert jsonbytes(n["options"]) == {"accept": "text/uri-list"} and n["result"]["metadata"] == {"contentType": "text/uri-list"}
        endpoints = jsonbytes(n["result"]["raw"])
        assert endpoints == ["https://agent.example/base/", "https://agent.example/two", "https://agent.example/alt"]
        assert x["status"] == 303 and x["header"]["Location"][0] in endpoints and not decode(x.get("body"))
    elif name == "proxy-metadata":
        owned(v["endpoint"])
        assert v["request"] == q["Request"] and v["server_role"] == "controlled client response fixture; not SAGE server output"
        assert v["server_tls"] and v["server_calls"] == 1 and len(v["wire"]) == len(v["consumer"]) == 1 and not v["native"]
        reply = jsonbytes(v["request"]["reply"])
        assert reply["didDocumentMetadata"]["deactivated"] is False and "deactivated" not in v["result"]["content_metadata"]
        expected = dict(reply["didDocumentMetadata"])
        del expected["deactivated"]
        assert v["result"]["metadata"] == reply["didResolutionMetadata"] and v["result"]["content_metadata"] == expected
    else:
        assert name == "expansion-output" and len(v) == len(q) == 2
        for i, x in enumerate(v):
            assert x["role"] == ROLE and x["request"] == q[i] and not x.get("capture_error")
            assert x["operation"] == "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve"
            assert x["driver_inputs"] == ["did:example:123"] and len(x["driver_results"]) == 1
            source = jsonbytes(x["driver_results"][0])
            assert source["ContentType"] == "application/did" and jsonbytes(source["Data"]) == json.loads((repo / "profiles/sageresolution/expansion_document.json").read_text())
            assert x["result"]["returned_id"] == "did:example:123" and x["result"]["has_content"]
            if i == 1:
                assert jsonbytes(x["options"]) == jsonbytes(x["resolve_options"][0]) == {"accept": "application/did", "expandRelativeUrls": True}
                expected = json.loads((repo / "profiles/sageresolution/expansion_expected.json").read_text())
                assert semantic_equal(jsonbytes(x["data_model"]), expected, "metadata")


def verify_remaining(raw, report, repo=REPO):
    assert raw["profile"] == report["profile"] == "did-1.1" and raw["subject"] == report["subject"]
    assert len(raw["cases"])==len(report["cases"])==335
    assert {c["case"] for c in raw["cases"]}=={c["id"] for c in report["cases"]} and len({c["case"] for c in raw["cases"]})==335
    expected_ids = verify_review(report, repo)
    selected = [c for c in raw["cases"] if "/remaining-" in c["case"]]
    assert len(selected) == 51 and len({c["case"] for c in selected}) == 51
    checked = set()
    for c in selected:
        name = c["case"].split("/remaining-")[1]
        obs = c["observations"]
        assert obs and len({o["statement"] for o in obs}) == len(obs)
        assert all(o["input"] == obs[0]["input"] and o["observed"] == obs[0]["observed"] and o["detail"] for o in obs)
        q, v = json.loads(obs[0]["input"]), json.loads(obs[0]["observed"])
        for o in obs:
            wanted = "FAIL" if o["statement"] in [FORWARD, KID, PROXY] and name in ["routing-forward-uri-options", "native-keys", "proxy-metadata"] else "NOT_APPLICABLE" if name == "native-keys" and o["statement"] in ["cid10#JsonWebKey.6", "cid10#JsonWebKey.9"] else "PASS"
            assert o["verdict"] == wanted
            checked.add(o["statement"])
        if name.startswith("value-"):
            verify_values(q, v, repo)
        elif name.startswith("fields-"):
            verify_fields(name[7:], q, v)
        elif name.startswith("routing-"):
            verify_routing(q, v, obs, repo)
        elif name.startswith("operation-"):
            verify_operations(q, v)
        elif name == "native-keys":
            assert v["returned_id"] == q["record"]["did"] == DID and v["has_content"] and v["content_kind"] == "document"
            doc = jsonbytes(v["raw"])
            assert doc["id"] == DID and len(doc["verificationMethod"]) == 2
            for m in doc["verificationMethod"]:
                assert m["type"] == "JsonWebKey" and m["controller"] == DID and "kid" not in m["publicKeyJwk"]
                assert m["publicKeyJwk"]["kty"] == "OKP" and m["publicKeyJwk"]["crv"] in ["Ed25519", "X25519"]
                purpose = "authentication" if m["publicKeyJwk"]["crv"] == "Ed25519" else "keyAgreement"
                assert m["id"] in doc[purpose]
        elif name.startswith("cid-http-"):
            assert len(v)==len(q["Requests"])==2
            for request,capture in zip(q["Requests"],v):
                owned(capture["exchange"]["url"])
                assert capture["request"]==request and capture["method"]==capture["exchange"]["method"]==q["Method"]
                assert len(capture["native"])==1 and capture["native"][0]["input"]==request["request"]["input"] and not capture.get("capture_error")
                assert jsonbytes(capture["native"][0]["options"])=={"accept":"application/did","verificationRelationship":"authentication"}
            assert v[0]["exchange"]["status"]==200 and v[0]["native"][0]["result"]["has_content"]
            bad=v[1];native=bad["native"][0]["result"]["metadata"]["error"];problem=jsonbytes(bad["exchange"]["body"])
            assert problem["type"]==native["type"]=="https://w3id.org/security#INVALID_VERIFICATION_METHOD"
            assert problem["detail"]==native["detail"] and problem["status"]==bad["exchange"]["status"] and 400<=problem["status"]<=599
            assert bad["exchange"]["header"]["Content-Type"]==["application/problem+json"] and not bad["native"][0]["result"]["has_content"]
        elif name=="minimal-representation":
            resolved,converted=v["Resolved"],v["Converted"]
            assert resolved["request"]==q["Request"] and q["Production"]=={"id":"did:example:123","version":"1.0","controller_shape":"absent","controllers":None,"fields":None,"entries":None,"json_ld":False}
            assert resolved["role"]==ROLE and resolved["result"]["has_content"] and resolved["result"]["returned_id"]=="did:example:123"
            assert len(converted["calls"])==1 and not converted.get("build_error") and not converted.get("capture_error")
            call=converted["calls"][0];assert call["operation"]=="github.com/sage-x-project/did-go/producer.Producer.Produce" and call["version"]=="1.0" and call["media_type"]=="application/did+json" and not call["json_ld"] and not call["include_secret"]
            assert jsonbytes(call["entries"])=={} and jsonbytes(call["model"])==jsonbytes(call["output"])==jsonbytes(resolved["data_model"])=={"id":"did:example:123"}
        elif name.startswith("preference-"):
            assert len(v) == len(q["Requests"]) == 2 and not q["Requests"][0].get("accept") and q["Requests"][1]["accept"] == "application/did"
            assert all(x["has_content"] and x["returned_id"] == DID and x["content_kind"] == "document" and "error" not in x["metadata"] for x in v)
            assert v[1]["metadata"]["contentType"] == "application/did"
        else:
            verify_transports(name, q, v, repo)
    assert checked == expected_ids and len(checked) == 77
    return checked


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    checked = verify_remaining(json.loads(a.raw.read_text()), json.loads(a.report.read_text()))
    print(f"Verified all 246 anchored reviews, {len(checked)} fresh selected-branch verdicts, and 161 explicitly unobserved clauses")


if __name__ == "__main__":
    main()
