#!/usr/bin/env python3
"""Verify separate forwarding/service observations, never merge old verdicts."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROLE = "root resolver/dereferencer library with literal example driver; not SAGE Source"
PREFIX = "did-1.1/sage-resolution/remaining-routing-"
SCOPE = "Selected literal dereferencing options and service results only; full SAGE conformance and operational authority are not established."


def require(condition, message):
    if not condition:
        raise ValueError(message)


def same(a, b):
    return json.dumps(a, sort_keys=True, separators=(",", ":")) == json.dumps(b, sort_keys=True, separators=(",", ":"))


def decoded(value):
    require(isinstance(value, str), "missing encoded observation")
    return json.loads(base64.b64decode(value, validate=True))


def documents(source):
    """Read authored raw JSON document bytes, independently of the observer."""
    decoder, position, result = json.JSONDecoder(), 0, {}
    position = source.index("[") + 1
    while True:
        while source[position].isspace() or source[position] == ",":
            position += 1
        if source[position] == "]":
            return result
        item, end = decoder.raw_decode(source, position)
        text = source[position:end]
        matches = list(re.finditer(r'"document"\s*:\s*', text))
        require(len(matches) == 1, "ambiguous authored document")
        start = matches[0].end()
        value, stop = decoder.raw_decode(text, start)
        require(same(value, item["document"]), "authored document mismatch")
        result[item["name"]] = text[start:stop].encode()
        position = end


def no_capture_error(out):
    require(out.get("capture_error", "") == "", "capture failure")
    for name in ["application_handler", "production", "resource_handler"]:
        require(same(out.get(name, []), []), "unexpected observer operation")


def strict_control(out, document):
    no_capture_error(out)
    require(out["role"] == ROLE and out["operation"] == "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve", "strict operation")
    q = out["request"]
    require(same(q, {"document":{"data":base64.b64encode(document).decode(),"media_type":"application/did"},"request":{"function":"resolve","input":"did:example:123","accept":"text/uri-list"}}), "strict request")
    require(same(decoded(out["options"]), {"accept":"text/uri-list"}) and same(out["resolve_inputs"], ["did:example:123"]), "strict incoming options")
    require(len(out["resolve_options"]) == 1 and same(decoded(out["resolve_options"][0]), {"accept":"text/uri-list"}), "strict actual call")
    require(same(out["driver_options"], []) and same(out.get("consumption", []), []), "strict refusal reached driver")
    for key in ["driver_inputs", "driver_results"]:
        require(out.get(key) is None or same(out[key], []), "strict driver output")
    for key in ["data_model", "entries", "resolved_data_model", "resolved_entries"]:
        require(out.get(key) is None, "strict partial document")
    result = out["result"]
    require(same(decoded(out["resolved_metadata"]), result["metadata"]), "strict preserved metadata")
    error = result["metadata"].get("error", {})
    require(error.get("type") == "https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED" and isinstance(error.get("detail"), str) and "text/uri-list" in error["detail"], "strict refusal")
    require(same(result["content_metadata"], {}) and result["has_content"] is False and result.get("raw") is None and result.get("native") is None and result.get("exchange") is None, "strict content")


def routing_call(out, fixture, document):
    no_capture_error(out)
    q = fixture["request"]
    require(out["role"] == ROLE and out["operation"] == "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference", "routing operation")
    require(same(out["request"], {"document":{"data":base64.b64encode(document).decode(),"media_type":"application/did"},"request":q}), "actual request changed")
    incoming = {"accept":q["accept"]}
    if q.get("relationship"):
        incoming["verificationRelationship"] = q["relationship"]
    require(same(decoded(out["options"]), incoming), "incoming options")
    nested = dict(parse_qsl(urlsplit(q["input"]).query, keep_blank_values=True))
    nested.update(incoming)
    require(same(out["resolve_inputs"], ["did:example:123"]) and len(out["resolve_options"]) == 1 and same(decoded(out["resolve_options"][0]), nested), "original nested options not forwarded")
    require(same(out["driver_inputs"], ["did:example:123"]) and len(out["driver_options"]) == len(out["driver_results"]) == 1, "driver calls")
    driver_media = "application/did" if q["accept"] == "application/did" else ""
    require(same(decoded(out["driver_options"][0]), {"VersionID":"","VersionTime":None,"MediaType":driver_media,"NoCache":False}), "driver selection")
    read = decoded(out["driver_results"][0])
    require(same(read, {"Data":base64.b64encode(document).decode(),"ContentType":"application/did","Metadata":{}}), "driver returned bytes")
    require(len(out["consumption"]) == 1, "consumer calls")
    consumer = out["consumption"][0]
    require(consumer["operation"] == "github.com/sage-x-project/did-go/consumer.Consumer.Consume" and consumer["input"] == read["Data"] and consumer["media_type"] == "application/did", "consumer input")
    require(consumer["strict"] is False and consumer["require"] == consumer["expected"] == "unknown" and consumer["version"] == "1.1" and consumer["json_ld"] is False and consumer["dropped_terms"] is None, "consumer configuration")
    require(consumer.get("error", "") == consumer.get("capture_error", "") == "", "consumer failure")
    require(same(decoded(consumer["model"]), fixture["document"]) and same(decoded(consumer["entries"]), {}), "consumed model")
    require(same(decoded(out["resolved_data_model"]), fixture["document"]) and same(decoded(out["resolved_entries"]), {}) and same(decoded(out["resolved_metadata"]), {"contentType":"application/did"}), "intermediate document")
    result, expected = out["result"], fixture["expected_content"]
    require(result.get("native") is None and result.get("exchange") is None, "unexpected transport")
    if fixture["error_type"]:
        types = {"non-method-fragment":"https://w3id.org/security#INVALID_VERIFICATION_METHOD", "conflicting-fragment":"https://www.w3.org/ns/did#INVALID_DID_URL"}
        kind = types.get(fixture["name"], "https://www.w3.org/ns/did#" + fixture["error_type"])
        error = result["metadata"].get("error", {})
        require(error.get("type") == kind and isinstance(error.get("detail"), str) and bool(error["detail"]), "final refusal")
        require(result["has_content"] is False and decoded(result.get("raw")) is None and same(result["content_metadata"], {}), "refusal content")
        model = fixture["document"]
    else:
        require(result["has_content"] is True and same(result["metadata"], {"contentType":q["accept"]}), "final content type")
        actual = decoded(result["raw"])
        if isinstance(expected, list):
            require(same(sorted(actual), sorted(expected)) and result["content_kind"] == "uri-list" and same(result["content_metadata"], {"contentType":"text/uri-list"}), "service URL list")
            model = fixture["document"]
        else:
            require(same(actual, expected) and result["content_kind"] == "document" and result["returned_id"] == "did:example:123" and same(result["content_metadata"], {}), "selected document")
            model = expected
    require(same(decoded(out["data_model"]), model) and same(decoded(out["entries"]), {}), "returned accessor model")


def verify(evidence, manifest, observer):
    require(bool(observer) and evidence["scope"] == SCOPE and evidence["runtime_results_merged"] is False, "scope")
    source = (ROOT / "profiles/sageresolution/routing_cases.json").read_bytes()
    require(hashlib.sha256(source).hexdigest() == manifest["fixture_sha256"], "frozen fixtures")
    fixtures = {f["name"]:f for f in json.loads(source)}
    authored = documents(source.decode())
    report, raw = evidence["report"], evidence["raw"]
    subject = {k:manifest["subject"][k] for k in ["name", "version", "revision"]}
    require(same(report["subject"], subject) and same(raw["subject"], subject) and report["inspector"]["revision"] == observer, "identity")
    require(raw["profile"] == report["profile"] == "did-1.1" and same(report["specs"], manifest["specs"]), "pinned publications")
    require(same(report["totals"], {"statements":486,"PASS":29,"FAIL":0,"NOT_SUPPORTED":0,"NOT_APPLICABLE":0,"ERROR":0,"NOT_RUN":457}), "totals")
    require(len(raw["cases"]) == 12 and {c["case"] for c in raw["cases"]} == {PREFIX+n for n in fixtures}, "case inventory")
    selected = set()
    for case in raw["cases"]:
        name = case["case"][len(PREFIX):]
        fixture, fixed = fixtures[name], manifest["cases"][name]
        require(same(case["statements"], fixture["statements"]) and len(case["observations"]) == len(fixture["statements"]), "case statements")
        first = case["observations"][0]
        require(hashlib.sha256(first["input"].encode()).hexdigest() == fixed["input_sha256"] and same(json.loads(first["input"]), {**fixture,"forwarded_options":fixture.get("forwarded_options")}), "frozen case input")
        require({o["statement"] for o in case["observations"]} == set(fixture["statements"]), "observed statements")
        require(all(o["verdict"] == "PASS" and o["input"] == first["input"] and o["observed"] == first["observed"] for o in case["observations"]), "case verdict")
        routing_call(json.loads(first["observed"]), fixture, authored[name])
        selected.update(fixture["statements"])
    ids = set()
    for name in ["did11-cr20260305", "cid10", "res10-crd20261001"]:
        ids.update(s["id"] for s in json.loads((ROOT / "statements" / (name+".json")).read_text())["statements"])
    require(len(report["statements"]) == 486 and {r["id"] for r in report["statements"]} == ids and len(selected) == 29, "statement inventory")
    for row in report["statements"]:
        require(row["verdict"] == ("PASS" if row["id"] in selected else "NOT_RUN"), "unobserved verdict")
        expected_cases = sorted(PREFIX+n for n,f in fixtures.items() if row["id"] in f["statements"])
        require(same(sorted(row.get("cases", [])), expected_cases), "statement case attribution")
    require(len(report["cases"]) == 12 and {r["id"] for r in report["cases"]} == {PREFIX+n for n in fixtures}, "report cases")
    for row in report["cases"]:
        name = row["id"][len(PREFIX):]
        require(same(row["statements"], fixtures[name]["statements"]) and row["verdict"] == "PASS" and type(row["observations"]) is int and row["observations"] == len(fixtures[name]["statements"]), "report case attribution")
    require(len(evidence["controls"]) == 2, "strict controls")
    document = (ROOT / "adapters/sagerouting/control-document.json").read_bytes()
    require(hashlib.sha256(document).hexdigest() == manifest["control_document_sha256"], "strict document")
    for control in evidence["controls"]:
        strict_control(control, document)
    return {"scope":manifest["scope"],"subject":subject,"observer":observer,"cases":12,"actual_routing_calls":12,"actual_strict_controls":2,"PASS":29,"NOT_RUN":457,"runtime_results_merged":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--observer", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text()), json.loads((ROOT / "docs/sage-routing-repair.json").read_text()), args.observer)
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
