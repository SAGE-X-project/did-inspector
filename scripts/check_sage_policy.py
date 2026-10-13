#!/usr/bin/env python3
"""Verify literal-library date findings and actual relying-party admission evidence."""
import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from check_sage_batch import jsonbytes, decode
from check_sage_contracts import semantic_equal

DID = "did:sage:web:registry.example:agent-1"
ROLE = "literal library fixture; not SAGE registry Source"
DATE_IDS = {"cid10#verification-methods.9", "cid10#verification-methods.11"}
FAIL_IDS = DATE_IDS | {"cid10#conformance.2", "did11-cr20260305#production-and-consumption.18"}
RETRIEVAL_IDS = {"cid10#retrieve-verification-method." + str(i) for i in [5, 6, 9, 10]}
PUBLIC_METHOD = {"id": DID + "#sign", "type": "JsonWebKey", "controller": DID,
                 "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}
DATE_VECTORS = [("utc", "2030-01-01T00:00:00Z", True),
                ("fraction-offset", "2030-01-01T09:00:00.500000001+09:00", True),
                ("negative-offset", "2029-12-31T19:00:00.5-05:00", True),
                ("positive-limit", "2030-01-01T14:00:00+14:00", True),
                ("negative-limit", "2029-12-31T10:00:00-14:00", True),
                ("zero-offset", "2030-01-01T00:00:00+00:00", True),
                ("boolean", False, False), ("number", 42, False), ("null", None, False),
                ("missing-zone", "2030-01-01T00:00:00", False), ("date-only", "2030-01-01", False),
                ("bad-calendar", "2030-02-30T00:00:00Z", False), ("comma", "2030-01-01T00:00:00,5Z", False),
                ("positive-outside", "2030-01-01T00:00:00+14:01", False),
                ("negative-outside", "2030-01-01T00:00:00-14:01", False)]


def instant(text):
    # Decimal commas are normalized here only to compare the *observed invalid*
    # subject input with its typed output. They remain invalid in DATE_VECTORS.
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:[.,](\d{1,9}))?(Z|[+-]\d{2}:\d{2})", text)
    assert m
    value = datetime.fromisoformat(m[1] + ("+00:00" if m[3] == "Z" else m[3]))
    return int(value.timestamp()), int((m[2] or "").ljust(9, "0"))


def public_document(field=None, value=None):
    method = dict(PUBLIC_METHOD)
    if field:
        method[field] = value
    return {"id": DID, "verificationMethod": [method], "authentication": [DID + "#sign"]}


def verify_consumer(q, out):
    c = out["consumer"]
    assert out["role"] == ROLE and not out.get("capture_error")
    assert c["operation"] == "github.com/sage-x-project/did-go/consumer.Consumer.Consume"
    assert c["input"] == q["document"]["data"] and c["media_type"] == q["document"]["media_type"] == "application/did"
    assert c["require"] == c["expected"] == "unknown" and not c["strict"]
    if c.get("error"):
        assert not decode(c["model"]) and not decode(c["entries"]) and not out["methods"]
        assert not out["retrieval"]["operation"] and not out["retrieval"]["calls"] and not out["clock_values"]
        return None
    assert not c.get("capture_error") and c["version"] == "1.1" and not c["json_ld"] and not c["dropped_terms"]
    assert jsonbytes(c["entries"]) == {} and len(out["methods"]) == 1
    source, model = jsonbytes(q["document"]["data"]), jsonbytes(c["model"])
    witness = out["methods"][0]
    assert witness["id"] == source["verificationMethod"][0]["id"]
    for field in ["expires", "revoked"]:
        method = source["verificationMethod"][0]
        if field in method:
            assert witness[field]["kind"] == "datetime"
            assert instant(witness[field]["text"]) == instant(model["verificationMethod"][0][field]) == instant(method[field])
            model["verificationMethod"][0][field] = method[field]
        else:
            assert field not in witness and field not in model["verificationMethod"][0]
    assert semantic_equal(source, model, "document")
    return source


def verify_retrieval(q, out, expected_refusal, early=False):
    source = verify_consumer(q, out)
    assert source and q["mode"] == "retrieve" and q["reference"] == DID + "#sign" and q["purpose"] == "authentication"
    r = out["retrieval"]
    assert r["operation"] == "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod"
    assert r["reference"] == q["reference"] and r["purpose"] == q["purpose"] and not r.get("capture_error") and r["clock"] == 0 and len(r["calls"]) == 1
    call = r["calls"][0]
    assert call["input"] == DID and jsonbytes(call["options"]) == q.get("options", {})
    result = call["result"]
    assert not result.get("native") and not result.get("exchange") and result["has_content"] and result["content_metadata"] == {}
    if q["non_document"]:
        assert not result.get("returned_id") and not result.get("content_kind") and not result.get("snapshot")
        assert jsonbytes(result["raw"]) == "literal non-document fixture" and result["metadata"] == {"contentType": "text/plain"}
    else:
        assert result["returned_id"] == source["id"] and result["content_kind"] == "document" and result["metadata"] == {"contentType": "application/did"}
        expected = jsonbytes(out["consumer"]["model"])
        assert semantic_equal(result["snapshot"], expected, "document")
    assert len(out["clock_values"]) == (0 if early else 1)
    assert all(instant(value) == instant(q["now"]) for value in out["clock_values"])
    if expected_refusal:
        assert r.get("error") and not decode(r["method"])
    else:
        assert not r.get("error") and not decode(r["problem"]) and not r.get("problem_serializer")
        method = jsonbytes(r["method"])
        assert semantic_equal(method, jsonbytes(out["consumer"]["model"])["verificationMethod"][0], "method")
    return r


def verify_policy(raw, report):
    assert raw["profile"] == report["profile"] == "did-1.1" and raw["subject"] == report["subject"]
    selected = [c for c in raw["cases"] if "/key-policy-" in c["case"]]
    names = {f"{field}-{wire}-{i}" for field in ["expires", "revoked"] for wire in ["utc", "offset"] for i in range(3)}
    names |= {"format-expires", "format-revoked", "non-document", "document-id", "method-id", "controller"}
    assert len(selected) == len(names) == 18 and {c["case"].split("/key-policy-")[1] for c in selected} == names
    checked = set()
    for case in selected:
        name, obs = case["case"].split("/key-policy-")[1], case["observations"]
        assert obs and all(o["input"] and o["observed"] and o["detail"] for o in obs)
        assert all(o["input"] == obs[0]["input"] and o["observed"] == obs[0]["observed"] for o in obs)
        f, values = json.loads(obs[0]["input"]), json.loads(obs[0]["observed"])
        ids = {o["statement"] for o in obs}
        assert len(ids) == len(obs) and len(values) == len(f["requests"])
        if name.startswith("format-"):
            field = name.split("-")[1]
            own_id = "cid10#verification-methods." + ("9" if field == "expires" else "11")
            assert f["field"] == field and f["statement"] == own_id and ids == {own_id, "cid10#conformance.2", "did11-cr20260305#production-and-consumption.18"}
            assert f["vectors"] == [{"name": n, "value": v, "valid": valid} for n, v, valid in DATE_VECTORS]
            assert len(values) == 15 and all(o["verdict"] == "FAIL" for o in obs)
            for (vector, value, valid), q, out in zip(DATE_VECTORS, f["requests"], values):
                assert q["mode"] == "consume" and jsonbytes(q["document"]["data"]) == public_document(field, value)
                assert q["reference"] == DID + "#sign" and q["purpose"] == "authentication" and q["now"] == "2029-01-01T00:00:00Z" and not q["non_document"] and not q.get("options")
                accepted = verify_consumer(q, out) is not None
                assert accepted == (valid or vector in ["comma", "positive-outside", "negative-outside"])
                assert not out["retrieval"]["operation"] and not out["retrieval"]["calls"] and not out["clock_values"]
        elif name.startswith(("expires-", "revoked-")):
            field, wire, index = name.split("-")
            i = int(index)
            own_id = "cid10#verification-methods." + ("9" if field == "expires" else "11")
            assert len(values) == 1 and ids == {own_id} and f["field"] == field and f["statement"] == own_id and f["name"] == name and f["refuse"] == (i > 0) and obs[0]["verdict"] == "PASS"
            q, out = f["requests"][0], values[0]
            value = "2030-01-01T00:00:00.5Z" if wire == "utc" else "2030-01-01T09:00:00.5+09:00"
            assert jsonbytes(q["document"]["data"]) == public_document(field, value) and not q["non_document"] and not q.get("options")
            assert q["now"] == ["2030-01-01T00:00:00.499999999Z", "2030-01-01T00:00:00.5Z", "2030-01-01T00:00:00.500000001Z"][i]
            r = verify_retrieval(q, out, i > 0)
            assert not decode(r["problem"]) and not r.get("problem_serializer")
            if field == "expires" and i > 0:
                assert "Advisory expiry refusal observed: true" in obs[0]["detail"]
        else:
            number = {"non-document": 5, "document-id": 6, "method-id": 9, "controller": 10}[name]
            own_id = "cid10#retrieve-verification-method." + str(number)
            assert len(values) == 2 and ids == {own_id} and f["statement"] == own_id and f["name"] == name and f["refuse"] and not f.get("field") and obs[0]["verdict"] == "PASS"
            good = public_document()
            bad = public_document()
            if name == "document-id":
                bad["id"] = "did:sage:web:registry.example:other-agent"
            elif name == "method-id":
                bad["verificationMethod"][0]["id"] = "did:sage:web:registry.example:other-agent#sign"
                bad["authentication"] = ["did:sage:web:registry.example:other-agent#sign"]
            elif name == "controller":
                bad["verificationMethod"][0]["controller"] = "did:sage:web:registry.example:other-agent"
            for i, (q, out) in enumerate(zip(f["requests"], values)):
                assert jsonbytes(q["document"]["data"]) == (bad if i else good) and q["non_document"] == (i == 1 and name == "non-document")
                assert q["now"] == "2029-01-01T00:00:00Z" and not q.get("options")
                r = verify_retrieval(q, out, i == 1, early=i == 1)
                if i == 1:
                    typ = {5: "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT", 6: "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID", 9: "INVALID_VERIFICATION_METHOD", 10: "INVALID_VERIFICATION_METHOD"}[number]
                    assert jsonbytes(r["problem"])["type"] == "https://w3id.org/security#" + typ
                    assert r["problem_serializer"] == "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
        checked |= ids
    assert checked == FAIL_IDS | RETRIEVAL_IDS
    live = {s["id"]: s["verdict"] for s in report["statements"]}
    assert all(live[i] == "FAIL" for i in FAIL_IDS) and all(live[i] == "PASS" for i in RETRIEVAL_IDS)
    assert {s["id"] for s in report["statements"] if s["level"] == "requirement" and s["verdict"] in ["FAIL", "ERROR"]} == FAIL_IDS
    return checked


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    root = parser.parse_args().reports
    verify_policy(json.loads((root / "resolution-did-1.1-raw.json").read_text()), json.loads((root / "resolution-did-1.1.json").read_text()))
    print("Verified 18 literal-library cases, six new clauses and four required findings with unchanged previous evidence")


if __name__ == "__main__":
    main()
