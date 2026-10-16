# Pending evidence prerequisites

`inspect_sage_prerequisites.py` writes a separate `prerequisites.json` assessment.
It binds sixteen pending evidence contracts to the frozen normative text identities,
eleven selected files from the original pinned module ZIP and six previously
reviewed actual-call receipts. It checks the full ZIP's canonical Go module h1,
the selected file hashes and existing source/observer checks. It does not attest
these eleven files in the source cache or in compiled binary bytes.

| Contract group | Pending clauses | Evidence still needed |
|---|---:|---|
| Reader interpretation | 3 | Preserve publication-specific BCP 14 interpretation; judge each actual obligation separately |
| Processing applicability | 3 | Actual JSON-LD/RDF processing actor, applicable mode and an independent complete oracle for the selected scope |
| Selected serializer | 1 | Original alternate-format entry and actual output, with an independent format oracle |
| Authority and lifecycle | 2 | Governing-method equivalence guarantees and an actual update/version operation |
| Normative interpretation | 6 | Authoritative clarification or a separately approved complete interpretation contract for the frozen wording |
| Dependent tuple | 1 | Resolve the metadata placement dependency and check the entire original return tuple |

The manifest records each clause's exact missing evidence, completion condition,
dependencies and relevant source/receipt references. Definitions and unresolved
interpretation rows have no artificial runtime observation. Source presence,
comments, JSON-LD flags, context parsing and JSON metadata serialization cannot
prove full processing support or absence of every possible API. The receipt
bindings preserve the existing producer recommendation failure as a failure.

The assessment status `verified-awaiting-prerequisites` means that the reviewed
identities and retained boundaries match. It is not a conformance verdict or a
claim that the prerequisites are satisfied. `runtime_verdicts_merged` is false.
The runtime report remains 373 cases, 375 PASS, 13 FAIL, 2 NOT_SUPPORTED,
4 NOT_APPLICABLE and 92 NOT_RUN, with zero ERROR. The separate document actor
is not copied into those runtime results. No core, specification or dependency
pin changes are made to resolve the outstanding contracts.

The canonical JSON hashes normalize object key order while retaining JSON types,
array order and embedded byte strings. They identify reviewed receipts; they
are not independently derived normative expected outputs. A changed receipt
requires explicit review of this frozen assessment rather than silent acceptance.
The assessment also binds its complete input reports and observer revision.

Run after the existing actual runtime and source checks:

```sh
python3 scripts/inspect_sage_prerequisites.py --reports /path/to/reports --out /path/to/reports/prerequisites.json
python3 scripts/inspect_sage_prerequisites.py --reports /path/to/reports --out /path/to/reports/prerequisites.json --verify
```

Generation exclusively creates a new file and refuses to overwrite any existing
path, including the runtime inputs. Verification compares an existing assessment
without writing. CI archives the sidecar alongside the unchanged runtime reports.
Unit controls only mutate local synthetic or archived evidence data and never
exercise an attack against another process or service.
