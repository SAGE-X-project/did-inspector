# SAGE resolution observation gaps

This inventory classifies every NOT_RUN statement in the DID 1.1 SAGE resolution
report from CI run [38353322386](https://github.com/SAGE-X-project/did-inspector/actions/runs/38353322386).
The machine-readable [inventory](sage-resolution-gaps.json) preserves all 416 historical
statement ids, normative levels and keywords, exact text digests, evidence paths,
and a next evidence route for each statement. Pending routes are planning evidence, not verdicts or implementation defects.
Schema 2 keeps 361 pending entries and 55 entries observed since the baseline;
it never assigns new observations to the historical inspector revision.

The baseline inspector revision is `aefdcf9228ec8dcf85fd4aaf08b6e0511af11c36`.
The CI observer was `3c498fa2ea4ebc86eaf90be4e47846e62dc92c40`; its tree equals
the baseline source and squash tree. The observed subject is
`did-go/advanced/sage-resolution` at `2ef282b40ccfe243c6cf3b1c05594e02171126cc`,
with root did-go `ed54c505eafe1c9d3d2decd862d6a9f7fcd2cd23`.
The publication hashes, exact original report digest and artifact location are
recorded in the JSON inventory. Publication bytes and statement extraction are
unchanged.

The baseline remains 76 cases, 67 requirement and two recommendation passes,
one inapplicable statement, and 416 unobserved statements. No verdict is changed
by classifying a gap. The 416 consist of 368 requirement-level and 48
recommendation-level statements. Requirement-level extraction also includes
permissions, definitions and algorithm steps; it does not mean every row is a
standalone MUST with an independently observable violation.

The current report has 150 cases, 120 requirement and two recommendation passes,
one recommendation failure, two inapplicable statements and 361 unobserved statements. Ten fresh native
result cases add 13 requirement passes and one conditional NOT_APPLICABLE.
Twenty-four direct metadata serialization cases add four requirement passes.
Three native error/state cases and ten owned TLS response cases add 22
requirement passes. Five fresh key/document cases add two requirement passes
and the missing alg recommendation FAIL. Every historical entry and its original
provenance remains; a failure is retained rather than removed from the inventory.
Five fresh serialized-document cases add four requirement passes for context
and media-type fields. Five additional passive pipeline captures add five
requirement passes at actual producer/consumer boundaries. They compare all
selected pre-input entries and separately returned consumer maps; arbitrary
value conversion rules and full JSON-LD semantics remain pending. Five further
producer calls observe root entry placement, while seven direct selected-consumer
calls observe declared media selection and five literal non-object rejections.
These add three requirements. Direct consumer calls are library actor evidence,
not SAGE resolver/ingress evidence.
The following routing counts describe the remaining 361, not the baseline 416.

| Primary next evidence route | Statements | Meaning |
|---|---:|---|
| Existing observation | 36 | Candidate assertions on actual native results, methods or server responses |
| Existing operation, new scenario | 0 | Candidate branches requiring fresh requests or controlled Source failures |
| Additional observer operation | 99 | A different actor, entry point or instrumentation is needed |
| Additional data or feature | 117 | Applicable optional fields, representations or method branches are absent |
| Document or applicability review | 105 | Author obligations, permissions, definitions, contracts or conflicts |
| Operational or authority evidence | 4 | Canonical storage or controller authority cannot be proved by fixtures |

These are primary routing counts, not estimates of implementation tasks, new
passes or the full amount of operational work. A route can have further
prerequisites. In particular, proof, history, method security and deployed trust
also affect rows whose primary route is data, documentation or another actor.
The four authority rows do not mean only four operational obligations remain.

## Actual observation boundary

The current adapter reaches `InspectResolution` with `resolve`, `dereference`,
Core 1.0 compatibility functions, and `http`/`http-comparison`. It captures
actual accessor snapshots, native metadata and representation bytes. HTTP uses
an owned loopback TLS handler; `http-comparison` also invokes a separate native
function. A fixed Source supplies public current-record fixtures. No operational
registry, mutable history, proxy, authoritative contract or deployed agent is
bound by those fixtures.

The SAGE adapter deliberately returns false for the generic capability
interfaces. This is an observation-interface limitation, not evidence that the
underlying library lacks every such feature. A future parser, consumer,
retriever or codec adapter must call the actual pinned implementation and
preserve its own identity and inputs. InspectPipeline now wraps the actual
pinned producer and consumer supplied to a fresh SAGE resolver, delegating their
unchanged arguments and returns. Pre-producer data and representation-entry maps
are captured before serialization, separately from post-consumption maps. The
selected ASCII/safe-integer JSON entry-preservation observations do not establish
all data types, term processing or arbitrary representations. The existing generic inspector's 256
`checked` and 160 `not-checkable` scope entries among the 416 historical statements
are retained as context only. Generic cases and verdicts are not copied into a
SAGE report. Previously uncheckable reasons must be reassessed for this actor;
in particular, metadata-structure.1 through .4 are MUST clauses, not
permissions. The original nativeResult adapter captures typed metadata through json.Marshal.
The separate InspectMetadata operation now directly invokes each pinned native
1.1 custom MarshalJSON method and retains both bytes and call errors. Its four
metadata-structure clauses are observed on the fresh output maps. JSON parsing
alone, generic fallback and an absent serializer identity cannot earn PASS.
Input metadata and arbitrary pre-serialization values remain unestablished.
For example, the producer-selected JWK alg recommendation can be inspected
freshly even though the generic scope treats it as document-author policy.

Client and server duties remain distinct. Binding requests are currently built
by the inspector, so the server cannot receive PASS for the client's request
construction or response-consumption obligations. A native dereference request
is parsed by the adapter before calling the typed subject API; a rejected
adapter input does not demonstrate the subject algorithm's invalid-input
branch. This requires an attributed subject entry point, not a fabricated
resolver error. CID retrieval's security error vocabulary is also distinct from
DID Resolution error types.

## Recommended continuation within the existing scope

1. The direct native output metadata boundary is now observed on selected
   resolve/dereference results, separately for each metadata structure. Continue
   remaining native result assertions and server response clauses. Input
   metadata, arbitrary extension/proof values and internal steps still need
   their own actor and entry point; output checks cannot establish them.
2. The eleven previously routed native error clauses and eleven server-wire
   clauses are now observed on selected actual branches. This does not exhaust
   all errors, HTTP options or representations. Keep Source failures, adapter
   rejection and handler parsing distinct when extending any other branch.
   Continue actual selected-key/document checks and applicable optional fields
   below; remaining actor/data/document/authority routes are still pending.
3. Expand actual selected-key and document checks, then applicable optional-field
   controls. Do not treat another key class as JsonWebKey. A new alg observation
   may report the same recommendation failure as projection, but must earn its
   own verdict. Existing projection verdicts remain separate.
4. Expose missing parser/reference, producer/consumer, CID retrieval and client
   operations only after their exact observation boundary is defined. Codec
   arithmetic or context/network behavior may need instrumentation; output
   equality cannot establish all internal steps. Alternative codecs can be
   permitted by the pinned text.
5. Prepare applicable history, relative-expansion, service-selection, proof,
   proxy and JSON-LD inputs where the pinned subject supports them. did:sage
   currently restricts path/query and observes the current record; requests to
   unsupported branches cannot be counted as successful service/history
   execution. Missing optional values, unsupported functionality and missing
   evidence must remain distinct. Never replace created/updated with observation
   time or manufacture proof/authority fields.
6. Review specification-author obligations and normative conflicts separately.
   The pinned CID text includes service-id optionality and Multikey material
   optionality conflicts recorded in `statements/scope.json`. Preserve both ids
   and the conflicting text before resolving expectations. Definitions and
   permission-only rows are not silently removed, marked inapplicable or passed.
   External registration stays deferred; no registration is required to run
   these local checks.
7. Keep authoritative Source, controller update authorization and deployment
   verification in their existing separately approved integration work. No
   transaction, key custody, host bypass, attacker reproduction or operational
   trust choice is introduced by this audit.

This sequence refines the remaining observation work without changing the
pinned protocol, subject implementation or previously deferred integration.
The two known SAGE-specific metadata failures still require separate
implementation correction and inspector re-verification. An inventory audit
neither resolves them nor establishes full standard conformance.

DID Core 1.0 remains a separate profile with 16 cases, 33 requirement passes and
173 NOT_RUN statements. Its pending work is preserved; it is not silently
included in the 416 DID 1.1 rows or marked complete. Production/consumption,
operational implementation conformance and organizationally independent audit
are also not completed by this classification.

## Drift and completeness checks

CI compares the inventory's exact pending ids to a fresh actual SAGE resolution
report. It rejects duplicate/missing/extra ids, changed subject/publication
identity or live totals, mismatched normative levels/keywords/text digests,
missing evidence paths, and incorrect category counts. A hash of the sorted
baseline ids anchors lossless membership across pending and observed entries.
Each observed entry names fresh native cases and its expected live verdict; CI
checks actual retained inputs/output and current report verdicts. Expectations
are validated at the current CI observer revision, not the historical baseline.
No route is itself a verdict. Future observations must move their full original
entry into the observation ledger, keeping all historical ids and provenance.

The current key/document observations cover services.3, verification-material.1
and JsonWebKey.7 only. The last-Update versionId recommendation and composite
DID verification-method conformance remain pending: fixture Version presence and
id/controller syntax alone cannot establish those complete clauses. Further
optional fields require their own applicable input and actor evidence.
