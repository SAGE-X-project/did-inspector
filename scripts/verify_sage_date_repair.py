#!/usr/bin/env python3
"""Verify the separate timestamp-consumer receipt; never merge old verdicts."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLE = "literal library fixture; not SAGE registry Source"
NORMAL = ["2030-01-01T00:00:00Z", "2030-01-01T09:00:00.500000001+09:00",
          "2029-12-31T19:00:00.5-05:00", "2030-01-01T14:00:00+14:00",
          "2029-12-31T10:00:00-14:00", "2030-01-01T00:00:00Z"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def same(first, second):
    return json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(second, sort_keys=True, separators=(",", ":"))


def decoded(value):
    return json.loads(base64.b64decode(value, validate=True))


def verify(evidence, manifest, revision):
    require(bool(revision) and evidence["runtime_results_merged"] is False, "observer or scope")
    require("complete XML Schema and SAGE conformance are not established" in evidence["scope"], "unbounded scope")
    report, raw = evidence["report"], evidence["raw"]
    subject = {key: manifest["subject"][key] for key in ["name", "version", "revision"]}
    require(same(report["subject"], subject) and same(raw["subject"], subject), "subject identity")
    require(report["inspector"]["revision"] == revision and raw["profile"] == report["profile"] == "did-1.1", "observer identity")
    require(same(report["totals"], {"statements":486,"PASS":4,"FAIL":0,"NOT_SUPPORTED":0,"NOT_APPLICABLE":0,"ERROR":0,"NOT_RUN":482}), "report totals")
    require(len(raw["cases"]) == 2 and {c["case"] for c in raw["cases"]} == {c["case"] for c in manifest["cases"].values()}, "case set")
    selected = set()
    for case in raw["cases"]:
        field = case["case"].rsplit("-", 1)[1]
        fixed = manifest["cases"][field]
        require(same(case["statements"], fixed["statements"]) and len(case["observations"]) == 3, "case statements")
        require({o["statement"] for o in case["observations"]} == set(fixed["statements"]), "observation set")
        first = case["observations"][0]
        require(all(o["verdict"] == "PASS" and o["input"] == first["input"] and o["observed"] == first["observed"] for o in case["observations"]), "observation mismatch")
        require(hashlib.sha256(first["input"].encode()).hexdigest() == fixed["input_sha256"], "frozen input changed")
        fixture, outputs = json.loads(first["input"]), json.loads(first["observed"])
        require(len(outputs) == len(fixture["requests"]) == len(fixture["vectors"]) == 15, "call count")
        for index, (q, vector, out) in enumerate(zip(fixture["requests"], fixture["vectors"], outputs)):
            consumer = out["consumer"]
            require(q["mode"] == "consume" and out["role"] == ROLE and not out.get("capture_error"), "observation role")
            require(consumer["input"] == q["document"]["data"] and consumer["media_type"] == q["document"]["media_type"] == "application/did", "actual input mismatch")
            require(consumer["operation"] == "github.com/sage-x-project/did-go/consumer.Consumer.Consume", "consumer operation")
            require(consumer["require"] == consumer["expected"] == "unknown" and consumer["strict"] is False, "consumer options")
            require(same(out["clock_values"], []) and same(out["retrieval"], {"clock":0,"operation":"","reference":"","purpose":"","calls":[],"method":None,"problem":None}), "unexpected relying-party call")
            if vector["valid"] is True:
                require(index < 6 and consumer.get("error", "") == "" and consumer.get("capture_error", "") == "", "valid input rejected")
                expected = decoded(q["document"]["data"])
                expected["verificationMethod"][0][field] = NORMAL[index]
                require(consumer["version"] == "1.1" and consumer["json_ld"] is False and (consumer["dropped_terms"] is None or same(consumer["dropped_terms"], [])), "consumer metadata")
                require(same(decoded(consumer["model"]), expected) and decoded(consumer["entries"]) == {}, "model changed")
                require(same(out["methods"], [{"id":expected["verificationMethod"][0]["id"],field:{"kind":"datetime","text":NORMAL[index]}}]), "typed timestamp changed")
            else:
                statement = "cid10#verification-methods." + ("9" if field == "expires" else "11")
                require(index >= 6 and vector["valid"] is False and statement in consumer.get("error", "") and consumer["error"].startswith("consumer: verificationMethod[0]." + field + ":"), "malformed timestamp accepted")
                require(consumer.get("capture_error") == "no actual document accessor maps", "invalid refusal capture diagnostic")
                require(consumer["model"] is None and consumer["entries"] is None and out["methods"] is None, "partial document returned")
        selected.update(fixed["statements"])
    expected_ids = set()
    for key in ["cid10", "did11-cr20260305", "res10-crd20261001"]:
        expected_ids.update(r["id"] for r in json.loads((ROOT / "statements" / (key + ".json")).read_text())["statements"])
    require(len(report["statements"]) == 486 and {r["id"] for r in report["statements"]} == expected_ids, "statement inventory")
    require(len(report["cases"]) == 2 and {r["id"] for r in report["cases"]} == {r["case"] for r in raw["cases"]}, "report cases")
    for row in report["statements"]:
        require(row["verdict"] == ("PASS" if row["id"] in selected else "NOT_RUN"), "verdict outside observed scope")
    require({r["id"] for r in report["statements"] if r["verdict"] == "PASS"} == selected, "missing statement")
    return {"scope":manifest["scope"], "subject":subject, "observer":revision,
            "cases":2, "actual_consumer_calls":30, "PASS":4, "NOT_RUN":482,
            "runtime_results_merged":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--observer", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = verify(json.loads(args.evidence.read_text()), json.loads((ROOT / "docs/sage-date-repair.json").read_text()), args.observer)
    with args.out.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
