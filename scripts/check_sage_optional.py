#!/usr/bin/env python3
"""Check actual selected consumer evidence for optional fields and relationships."""
import argparse
import copy
import json
from pathlib import Path
from check_sage_batch import jsonbytes
from check_sage_contracts import semantic_equal
from check_sage_policy import DID, PUBLIC_METHOD, instant

RELATIONSHIPS = {"authentication": "authentication", "assertionMethod": "assertion",
                 "keyAgreement": "key-agreement", "capabilityInvocation": "capability-invocation",
                 "capabilityDelegation": "capability-delegation"}
FIELDS = {"controller": ("cid10#controllers.1", [DID], False),
          "alsoKnownAs": ("cid10#also-known-as.1", ["https://agent.example/profile"], False),
          "service": ("cid10#services.1", [{"id": DID + "#service", "type": "ExampleService", "serviceEndpoint": "https://agent.example/service"}], False),
          "verificationMethod": ("cid10#verification-methods.1", None, False),
          "expires": ("cid10#verification-methods.8", "2030-01-01T00:00:00Z", True),
          "revoked": ("cid10#verification-methods.10", "2030-01-01T00:00:00Z", True),
          "exampleExtra": ("cid10#verification-methods.4", {"label": "public fixture", "sequence": [True, None, "ordered", 2]}, True)}


def base():
    return {"id": DID, "verificationMethod": [copy.deepcopy(PUBLIC_METHOD)], "authentication": [DID + "#sign"]}


def fixtures(name):
    if name in RELATIONSHIPS:
        section = RELATIONSHIPS[name]
        absent = base()
        del absent["authentication"]
        reference, embedded, mixed = [copy.deepcopy(absent) for _ in range(3)]
        reference[name] = [DID + "#sign"]
        embedded[name] = embedded.pop("verificationMethod")
        other = copy.deepcopy(PUBLIC_METHOD)
        other["id"] = DID + "#embedded"
        mixed[name] = [DID + "#sign", other]
        return ["cid10#" + section + ".1", "cid10#" + section + ".3"], [absent, reference, embedded, mixed]
    identifier, value, method = FIELDS[name]
    absent, present = base(), base()
    if method:
        present["verificationMethod"][0][name] = copy.deepcopy(value)
    elif name == "verificationMethod":
        del absent["authentication"]
        del present["authentication"]
        del absent["verificationMethod"]
    else:
        present[name] = copy.deepcopy(value)
    return [identifier], [absent, present]


def verify_call(request, capture, expected):
    assert request["media_type"] == capture["media_type"] == "application/did"
    assert request["data"] == capture["input"] and semantic_equal(jsonbytes(request["data"]), expected, "document")
    assert capture["operation"] == "github.com/sage-x-project/did-go/consumer.Consumer.Consume"
    assert capture["require"] == capture["expected"] == "unknown" and not capture["strict"]
    assert capture["version"] == "1.1" and not capture["json_ld"] and not capture["dropped_terms"]
    assert not capture.get("error") and not capture.get("capture_error") and jsonbytes(capture["entries"]) == {}
    model = jsonbytes(capture["model"])
    source_methods, actual_methods = expected.get("verificationMethod", []), model.get("verificationMethod", [])
    if len(source_methods) == len(actual_methods) == 1:
        for field in ["expires", "revoked"]:
            if field in source_methods[0]:
                assert instant(source_methods[0][field]) == instant(actual_methods[0][field])
                actual_methods[0][field] = source_methods[0][field]
    assert semantic_equal(model, expected, "document")


def verify_optional(raw, report):
    assert raw["profile"] == report["profile"] == "did-1.1" and raw["subject"] == report["subject"]
    selected = [c for c in raw["cases"] if "/optional-" in c["case"]]
    assert len(selected) == 12 and {c["case"].split("/optional-")[1] for c in selected} == set(RELATIONSHIPS) | set(FIELDS)
    checked, calls = set(), 0
    for case in selected:
        name = case["case"].split("/optional-")[1]
        ids, expected = fixtures(name)
        obs = case["observations"]
        assert len(obs) == len(ids) and {o["statement"] for o in obs} == set(ids)
        assert all(o["verdict"] == "PASS" and o["detail"] and o["input"] and o["observed"] for o in obs)
        assert all(o["input"] == obs[0]["input"] and o["observed"] == obs[0]["observed"] for o in obs)
        f, out = json.loads(obs[0]["input"]), json.loads(obs[0]["observed"])
        assert f["name"] == name and f["statements"] == ids and len(f["variants"]) == len(out["variants"]) == len(expected)
        verify_call(f["control"], out["control"], base())
        for request, capture, document in zip(f["variants"], out["variants"], expected):
            verify_call(request, capture, document)
        calls += 1 + len(expected)
        checked.update(ids)
    live = {s["id"]: s["verdict"] for s in report["statements"]}
    assert len(checked) == 17 and calls == 46 and all(live[i] == "PASS" for i in checked)
    return checked


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports", type=Path, required=True)
    root = parser.parse_args().reports
    verify_optional(json.loads((root / "resolution-did-1.1-raw.json").read_text()), json.loads((root / "resolution-did-1.1.json").read_text()))
    print("Verified 17 optional/library clauses across 12 cases and 46 actual consumer calls")


if __name__ == "__main__":
    main()
