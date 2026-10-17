# Separate dereferencing option verification

This observer identifies a repaired root did-go module by its compiled module
version and sum, and rejects replacements, missing or duplicate identities.
The exact identity and original authored input hashes are in
`sage-routing-repair.json`. The original ed54 SAGE subject and the bff timestamp
subject remain separately pinned and reported. Their results are never combined.

The observer runs the twelve unchanged routing cases from the pinned DID 1.1
profile. The original options reach the actual nested Resolve call. A separately
constructed resolver explicitly enables `resolver.ForDereferencing()` to obtain
a conforming intermediate DID document; original final-content preferences still
select documents or URI lists, or cause a final refusal. The shared observer
returns actual calls and data, never a validation verdict. The old subject calls
it without configuration, preserving its original behavior.

Two additional actual direct Resolve observations, each with its own default
strict resolver, occur before and after the profile run. They must refuse
`text/uri-list` before reaching the driver. They do not prove same-instance
concurrency; core race tests separately cover strict/intermediate isolation and
separate caches. No endpoint URL is contacted or operational registry selected.

The independent Python verifier checks the authored fixture and input hashes,
all incoming and nested options, driver and consumer calls, intermediate models
and metadata, literal selected documents/URL lists, qualified refusals, strict
controls, pinned publications, and report attribution. Its authored unit fixtures
are not native runtime evidence. CI builds the actual CLI and checks its fresh
receipts, module/build/source identity, binary hashes and test coverage.

The separate report is expected to contain 29 selected PASS and 457 NOT_RUN
statements, with no FAIL, ERROR, unsupported or inapplicable verdicts. Those 29
include the repaired forwarding clause and existing service controls; they do
not represent 29 newly repaired defects. Scope is limited to these literal
library calls. No complete DID/SAGE conformance, real Source authority, external
SAGE/Rust/ADK adoption, or complete HTTP/URI negotiation is asserted.

```sh
cd adapters/sagerouting
GOWORK=off GOTOOLCHAIN=local INSPECTOR_REVISION=<observer-commit> \
  go run ./cmd/did-inspector-sagerouting > evidence.json
cd ../..
python3 scripts/verify_sage_routing_repair.py \
  --evidence adapters/sagerouting/evidence.json --observer <observer-commit> \
  --out verified.json
```

A zero CLI exit status means observation collection completed, not general
conformance. The independent checker must succeed, and output files are created
exclusively so a prior result cannot be silently replaced. Follow the host's
resource policy: this project's heavy Go builds and tests run in remote CI.
