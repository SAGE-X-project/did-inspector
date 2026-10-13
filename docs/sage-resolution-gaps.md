# SAGE resolution observation gaps

This inventory classifies every NOT_RUN statement in the DID 1.1 SAGE resolution
report from CI run [38353322386](https://github.com/SAGE-X-project/did-inspector/actions/runs/38353322386).
The machine-readable [inventory](sage-resolution-gaps.json) preserves all 416 historical
statement ids, normative levels and keywords, exact text digests, evidence paths,
and a next evidence route for each statement. Pending routes are planning evidence, not verdicts or implementation defects.
Schema 2 keeps 269 pending entries and 147 entries observed since the baseline;
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

The current report has 238 cases, 204 requirement and nine recommendation passes,
two recommendation failures, two inapplicable statements and 269 unobserved statements. Ten fresh native
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
not SAGE resolver/ingress evidence. Nine additional paired cases execute 18
actual consumer calls: accepted public controls versus independently specified
single-field violations. They add two selected nonconforming-input rejection
requirements without establishing a complete document validator. Two new direct
typed-production cases inspect every row of the pinned JSON production table on
selected values, adding production.1 and json-ld-processors.2. Actual pre-producer
type witnesses distinguish value conversion from post-consumption JSON equality.
Two literal-input typed-consumer cases now inspect the nine JSON consumption
table rows, including recognized datetime properties and date-looking unknown
strings, adding consumption.1 on these selected values. Root/map insertion order
is not required. All numeric ranges, forced double properties without a fraction,
other property contexts and full JSON-LD processing remain unestablished.
The following routing counts describe the remaining 269, not the baseline 416.

| Primary next evidence route | Statements | Meaning |
|---|---:|---|
| Existing observation | 17 | Candidate assertions on actual native results, methods or server responses |
| Existing operation, new scenario | 0 | Candidate branches requiring fresh requests or controlled Source failures |
| Additional observer operation | 52 | A different actor, entry point or instrumentation is needed |
| Additional data or feature | 97 | Applicable optional fields, representations or method branches are absent |
| Document or applicability review | 99 | Author obligations, permissions, definitions, contracts or conflicts |
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
underlying library lacks every such feature. The new explicit parser, consumer,
retriever, codec and client operations call the actual pinned implementation and
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

Client and server duties remain distinct. The earlier server scenarios use inspector-built
requests and cannot prove client behavior. The separate actual universal.Client
batch now constructs its own requests, delegates through an owned universal
handler to the SAGE resolver, and passively captures the exact native invocation.
Controlled response fixtures establish only client metadata-directed parsing. A native dereference request
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

Four fresh representation-input cases now inspect production-and-consumption.8
and .13: the actual producer receives both document and representation maps;
the actual consumer receives the literal bytes and declared media string.
These are selected library actor input contracts, not output or rejection
conformance. Timestamp parsing alone still establishes no expiration/revocation
non-use policy, and builder rejection is not actual producer rejection.

Three paired producer context cases now observe production-and-consumption.12
on selected scalar Boolean/Integer and Boolean list-suffix context inputs.
The valid control must produce the reviewed minimal public document. Negative
inputs must reach the actual producer after successful model construction.
Refusal without output or independently checked base-only repaired output can
pass; error with partial bytes remains ERROR. This does not establish all
non-conforming DID/schema rejection, full JSON-LD semantics or publication.

## Consolidated library verification

The [353-clause batch audit](sage-resolution-batch-review.md) reads and individually records every anchored remaining clause. Related implementations are committed together on one PR; this changes delivery cadence, not the existing stage order. It supplies no automatic verdict.

The batch adds 45 cases and observes 61 anchored clauses: five syntax/reference clauses, eighteen key/multibase encoding clauses, nineteen actual-client binding/metadata clauses, ten relying-party/error clauses, six conditional document clauses and three local context/undefined-term clauses. Sixty PASS and one recommendation FAIL are preserved. All 416 historical ids remain as 292 pending and 124 observed (121 PASS, one NOT_APPLICABLE, two FAIL).

The newly observed recommendation failure is json-ld-processors.6: the actual default producer returns the undefined root term. The independent pinned-context oracle and paired accepted control prevent a strict-option substitute from hiding it. The default consumer removes the same term as json-ld-processors.8 recommends. No core implementation is changed in this PR.

Public point fixtures and public deterministic scalar/seed bytes check transport encoding only. CID secret BLS prefix/varint ambiguity, internal arithmetic steps, optional permissions, full JSON-LD/RDF processing, author obligations, operational authority and missing history/service features remain separately unestablished. The stage-eight contract/core work and deferred W3C registration are retained.


## Typed native input and result contracts

A second consolidated batch adds 23 fresh cases for 23 previously unobserved
clauses (19 requirements and four recommendations). Actual SAGE
`ResolveWithCode` and `DereferenceWithCode` calls receive typed identifiers and
empty or explicit options. The adapter captures their textual identifier and
actual options serialization before invocation, preserving original native
metadata serializer bytes, errors and the actual problem object. Invalid
text rejected by an adapter parser is never evidence of native rejection;
zero DID/DIDURL values reach the actual entry directly.

Ten plain-document dereferences over five public records compare the complete
snapshot and content metadata with a separately executed same-record resolve.
This comparison proves the selected externally observable outcomes only; it
does not trace an internal algorithm step or establish complete document
conformance. Complete `#sign` and `#agree` inputs select the exact methods from
the independently captured document. Missing fragments, an unauthorized
relationship, and an input without a verification method are refusal controls.
No service-path/query or historical feature is inferred from these results.

JSON serializability covers the selected identifier text, actual typed options
and two native metadata outputs, excluding contentStream. Successful document
and fragment metadata, typed-zero failure metadata and absent error content are
checked independently. Input-required and DID-grammar statements are observed
only for these typed API inputs and explicit zero refusal, not every malformed
string, extension value or DID method. Successful method support is restricted
to the actual `did:sage` implementation and pinned revision.

RFC9457 evidence checks the unchanged native problem data structure; it does
not claim HTTP problem transmission or all RFC9457 semantics. Input/options capture mismatch is an observer ERROR. JSON object member order
and known DID-set order do not change semantic equality, while unknown extension
lists remain ordered. Mandatory refusal requires an actual descriptive error
object; an empty or null error cannot earn PASS. Canonical error type checks
apply only where the clause prescribes that type. Short titles and
longer details are separately compared with reviewed human-readable fixture
explanations. Missing explanations fail their recommendation; unreviewed
nonempty prose remains NOT_SUPPORTED. They never change mandatory refusal
verdicts. The `FEATURE_NOT_SUPPORTED` detail recommendation uses an actual
resolve request for unsupported `text/html`; the dereferencing
`REPRESENTATION_NOT_SUPPORTED` response is not substituted for it.

The current ledger preserves all 416 historical rows as 269 pending plus 147
observed (144 PASS, one NOT_APPLICABLE and two FAIL). The frozen 353-clause
review and its original 61 observations are retained with their own attribution.
New native cases do not alter that audit anchor or copy its verdicts.
`scripts/check_sage_contracts.py` independently verifies every new case and its
raw inputs, options, serializers, result comparisons and statement attribution.
