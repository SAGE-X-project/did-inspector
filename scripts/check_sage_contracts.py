#!/usr/bin/env python3
"""Independently verify selected typed native contract evidence, not verdict labels alone."""
import argparse
import json
from pathlib import Path

from check_sage_batch import decode, jsonbytes, REPO

PREFIX = "res10-crd20261001#"
IDS = {PREFIX + name for name in ["resolving.2", "resolving.3", "dereferencing.1", "dereferencing.2",
       "dereferencing.3", "dereferencing.4", "dereferencing.5", "dereferencing.6", "dereferencing.7",
       "dereferencing.11", "dereferencing-algorithm-resource.1", "dereferencing-algorithm-resource.2",
       "dereferencing-algorithm-resource.3", "dereferencing-algorithm-resource.4",
       "dereferencing-algorithm-resource.12", "dereferencing-algorithm-resource.13",
       "dereferencing-algorithm-resource.14", "dereferencing-algorithm-resource.15",
       "did-url-dereferencing-options.5", "errors.1", "errors.4", "errors.5", "errors.7"]}


def semantic_equal(a, b, kind="unknown"):
    set_kind = {"method-set": "method", "relationship-set": "method", "service-set": "service", "set": "unknown", "single-or-set": "unknown"}.get(kind)
    if set_kind:
        if kind != "single-or-set" and (not isinstance(a, list) or not isinstance(b, list)):
            return False
        left, right = a if isinstance(a, list) else [a], list(b) if isinstance(b, list) else [b]
        if len(left) != len(right):
            return False
        for value in left:
            match = next((i for i, candidate in enumerate(right) if semantic_equal(value, candidate, set_kind)), None)
            if match is None:
                return False
            right.pop(match)
        return True
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        if a.keys() != b.keys():
            return False
        fields = {}
        if kind == "document":
            fields = {"controller": "single-or-set", "alsoKnownAs": "set", "verificationMethod": "method-set", "service": "service-set",
                      **{k: "relationship-set" for k in ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"]}}
        elif kind == "metadata":
            fields = {"equivalentId": "set", "proof": "set"}
        elif kind == "service":
            fields = {"type": "single-or-set", "serviceEndpoint": "single-or-set"}
        return all(semantic_equal(value, b[key], fields.get(key, "unknown")) for key, value in a.items())
    if isinstance(a, list):
        return len(a) == len(b) and all(semantic_equal(left, right) for left, right in zip(a, b))
    return a == b


def verify_contracts(raw, report):
    assert raw["profile"] == report["profile"] == "did-1.1" and raw["subject"] == report["subject"]
    records = json.loads((REPO / "profiles/sageprojection/records.json").read_text())
    selected = [c for c in raw["cases"] if "/native-contract-" in c["case"]]
    names = {f"document-{i}-{flag}" for i in [0, 1, 2, 3, 5] for flag in ["true", "false"]}
    names |= {"resolve-true", "resolve-false", "resolve-options", "fragment-sign", "fragment-agree", "authorized-sign",
              "zero-resolve", "zero-dereference", "missing-fragment", "wrong-purpose", "no-method", "unsupported-media", "unsupported-deref-media"}
    assert len(selected) == len(names) == 23
    assert {c["case"].split("/native-contract-")[1] for c in selected} == names
    checked = set()
    for c in selected:
        name = c["case"].split("/native-contract-")[1]
        obs = c["observations"]
        assert obs and len({o["statement"] for o in obs}) == len(obs)
        assert all(o["verdict"] == "PASS" and o["input"] and o["observed"] and o["detail"] for o in obs)
        assert all(o["input"] == obs[0]["input"] and o["observed"] == obs[0]["observed"] for o in obs)
        f, out = json.loads(obs[0]["input"]), json.loads(obs[0]["observed"])
        assert f["name"] == name and f["statements"] == [o["statement"] for o in obs]
        q = f["request"]["request"]
        record = records[int(name.split("-")[1])] if name.startswith("document-") else records[0]
        assert f["record"] == record
        fn = "resolve" if name.startswith("resolve-") or name in ["zero-resolve", "unsupported-media"] else "dereference"
        assert q["function"] == fn and out["operation"] == "github.com/sage-x-project/did-go/advanced/sage.Resolver." + ("ResolveWithCode" if fn == "resolve" else "DereferenceWithCode")
        zero = name in ["zero-resolve", "zero-dereference"]
        identifier = "" if zero else record["did"]
        if name in ["fragment-sign", "authorized-sign"]:
            identifier += "#sign"
        elif name in ["fragment-agree", "wrong-purpose"]:
            identifier += "#agree"
        elif name == "missing-fragment":
            identifier += "#unknown"
        assert f["request"]["zero"] == zero and q["input"] == jsonbytes(out["identifier"]) == identifier
        options = {}
        if name.endswith("-true"):
            options["accept"] = "application/did"
        if name in ["unsupported-media", "unsupported-deref-media"]:
            options["accept"] = "text/html"
        if name in ["authorized-sign", "wrong-purpose", "no-method"]:
            options["verificationRelationship"] = "authentication"
        if name == "resolve-options":
            options["noCache"] = True
        assert jsonbytes(out["options"]) == options
        request_options = dict(q.get("options", {}))
        if q.get("accept"):
            request_options["accept"] = q["accept"]
        if q.get("relationship"):
            request_options["verificationRelationship"] = q["relationship"]
        assert request_options == options and not out.get("capture_error")
        result = out["result"]
        assert not result.get("native") and not result.get("exchange")
        for role, key, actor in [("resolution", "metadata", "resolution.ResolutionMetadata"), ("document", "content_metadata", "document.Metadata")]:
            capture = out["metadata"][role]
            assert capture["serializer"] == "github.com/sage-x-project/did-go/" + actor + ".MarshalJSON"
            assert not capture.get("error") and jsonbytes(capture["bytes"]) == result[key] and isinstance(result[key], dict)
        error_types = {"zero-resolve": "INVALID_DID", "zero-dereference": "INVALID_DID_URL", "missing-fragment": "NOT_FOUND",
                       "wrong-purpose": "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD", "no-method": "INVALID_VERIFICATION_METHOD",
                       "unsupported-media": "FEATURE_NOT_SUPPORTED", "unsupported-deref-media": "REPRESENTATION_NOT_SUPPORTED"}
        if name in error_types:
            typ = ("https://w3id.org/security#" if name in ["wrong-purpose", "no-method"] else "https://www.w3.org/ns/did#") + error_types[name]
            assert f["error_type"] == typ and result["metadata"]["error"]["type"] == typ
            assert not result["has_content"] and not result.get("returned_id") and not result.get("content_kind") and not result.get("snapshot")
            assert result["content_metadata"] == {} and "reference" not in out
            if fn == "dereference":
                assert jsonbytes(result["raw"]) is None
            problem = jsonbytes(out["problem"])
            assert problem == result["metadata"]["error"] and out["problem_serializer"] == "encoding/json.Marshal(actual *github.com/sage-x-project/did-go/resolution.Error)"
            titles = {"zero-resolve": "Invalid DID", "zero-dereference": "Invalid DID URL", "missing-fragment": "Not found", "wrong-purpose": "Invalid relationship for verification method", "no-method": "Invalid verification method", "unsupported-media": "Feature not supported", "unsupported-deref-media": "Representation not supported"}
            details = {"zero-resolve": "the DID is empty", "zero-dereference": "a DID URL to dereference is absolute", "missing-fragment": "no part of the DID document has the id " + identifier, "wrong-purpose": identifier + " is not in authentication", "no-method": "the DID URL has no fragment, so it does not dereference to a verification method", "unsupported-media": 'no representation acceptable to "text/html" can be produced', "unsupported-deref-media": "no DID document representation is acceptable to text/html"}
            assert problem["title"] == titles[name] and problem["detail"] == details[name]
            if "status" in problem:
                assert type(problem["status"]) is int and 100 <= problem["status"] <= 599
        else:
            assert not f.get("error_type") and result["has_content"] and result["returned_id"] == identifier and "error" not in result["metadata"]
            assert not decode(out.get("problem")) and not out.get("problem_serializer")
            if fn == "resolve":
                assert "reference" not in out and result["content_kind"] == "document" and result["snapshot"]["id"] == identifier
            else:
                ref = out["reference"]
                assert ref["has_content"] and ref["content_kind"] == "document" and ref["returned_id"] == ref["snapshot"]["id"] == record["did"] and "error" not in ref["metadata"]
                assert not ref.get("native") and not ref.get("exchange")
                if "#" in identifier:
                    assert result["content_kind"] == "verification-method" and result["snapshot"]["id"] == identifier
                    assert any(semantic_equal(result["snapshot"], m, "method") for m in ref["snapshot"]["verificationMethod"])
                    if name == "authorized-sign":
                        assert identifier in ref["snapshot"]["authentication"]
                else:
                    assert result["content_kind"] == "document" and semantic_equal(result["snapshot"], ref["snapshot"], "document") and semantic_equal(result["content_metadata"], ref["content_metadata"], "metadata")
        expected = {"errors.1", "errors.4", "errors.5"} if name in error_types else set()
        if fn == "resolve":
            expected |= {"resolving.2", "resolving.3"}
        elif name == "authorized-sign":
            expected |= {"dereferencing.3", "did-url-dereferencing-options.5"}
        else:
            expected |= {"dereferencing.2", "dereferencing.4", "dereferencing.5", "dereferencing.6"}
            if name in error_types:
                expected.add("dereferencing.7")
            else:
                expected.add("dereferencing.11")
                if name.startswith("document-"):
                    expected |= {"dereferencing.1", *("dereferencing-algorithm-resource." + str(i) for i in [12, 13, 14, 15])}
                else:
                    expected.add("dereferencing.3")
        if name == "zero-dereference":
            expected |= {"dereferencing-algorithm-resource." + str(i) for i in [1, 2, 3, 4]}
        if name in ["wrong-purpose", "no-method"]:
            expected.add("did-url-dereferencing-options.5")
        if name == "missing-fragment":
            expected.add("dereferencing.3")
        if name == "unsupported-media":
            expected.add("errors.7")
        assert {o["statement"] for o in obs} == {PREFIX + i for i in expected}
        checked |= {o["statement"] for o in obs}
    assert checked == IDS
    live = {s["id"]: s["verdict"] for s in report["statements"]}
    assert all(live[i] == "PASS" for i in IDS)
    return checked


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    root = parser.parse_args().reports
    raw = json.loads((root / "resolution-did-1.1-raw.json").read_text())
    report = json.loads((root / "resolution-did-1.1.json").read_text())
    verify_contracts(raw, report)
    print("Verified 23 native contract clauses across 23 actual typed-entry cases")


if __name__ == "__main__":
    main()
