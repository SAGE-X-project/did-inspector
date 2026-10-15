# SAGE resolution observation gaps

This inventory classifies every NOT_RUN statement in the DID 1.1 SAGE resolution
report from CI run [38353322386](https://github.com/SAGE-X-project/did-inspector/actions/runs/38353322386).
The machine-readable [inventory](sage-resolution-gaps.json) preserves all 416 historical
statement ids, normative levels and keywords, exact text digests, evidence paths,
and a next evidence route for each statement. Pending routes are planning evidence, not verdicts or implementation defects.
Schema 2 keeps 156 pending entries and 260 entries observed since the baseline;
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

The current report has 359 cases, 341 requirement and fourteen recommendation passes,
six requirement failures, four recommendation failures, four inapplicable statements and 117 unobserved statements. Ten fresh native
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
The earlier routing table below describes the 246-clause anchor, not the baseline 416.
The [current full review](sage-remaining-clause-review.md) records all anchor clauses individually and identifies the 117 still unobserved.

| Primary next evidence route | Statements | Meaning |
|---|---:|---|
| Existing observation | 17 | Candidate assertions on actual native results, methods or server responses |
| Existing operation, new scenario | 0 | Candidate branches requiring fresh requests or controlled Source failures |
| Additional observer operation | 48 | A different actor, entry point or instrumentation is needed |
| Additional data or feature | 78 | Applicable optional fields, representations or method branches are absent |
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


## Key admission times and literal document retrieval

Eighteen fresh cases execute the pinned consumer and relying party with literal
public documents, including 30 independent date syntax inputs, 12 before/at/after
clock calls and four positive/refusal pairs. The fixture dereferencer is explicitly
identified as a literal library fixture, not a SAGE registry or authoritative
Source. Actual consumer bytes/options/results, typed date witnesses, supplied
retrieval options, returned document, clock reads and selected method/errors are
preserved. No typed document is mutated to bypass validation. Consumer failure
is not substituted for a relying-party refusal.

The selected [XSD 1.1 dateTimeStamp](https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp)
syntax controls allow offsets and fractional seconds. They distinguish decimal
points from commas and enforce the [time-zone range](https://www.w3.org/TR/xmlschema11-2/#rf-timezone)
through +/-14:00. The actual pinned consumer accepts comma fractional timestamps
and +/-14:01 for both expires and revoked. This yields FAIL for
`cid10#verification-methods.9`, `cid10#verification-methods.11`,
`cid10#conformance.2` and `did11-cr20260305#production-and-consumption.18`.
These four normative findings share the same permissive date-reader cause;
they are not four independent defects. Earlier nine-pair PASS observations
remain, but new counterexamples change the two aggregate consumer clauses to
FAIL. CI verifies these exact ids and raw counterexamples without weakening
Inspector's gate. CLI exit0 still means a completed inspection, never compliance.

Actual method admission is refused at/after revocation, and the selected relying
party also refuses expiry at/after its boundary. Expiry non-use is a SHOULD and
its refusal is diagnostic, not a second mandatory condition. Before-time method
admission is not required by either time clause; its result is diagnostic. The
mandatory time syntax and revocation non-use checks remain distinct. UTC and
+09:00 inputs describe the same half-second instant; one-nanosecond before/after
clocks distinguish rounding or inclusive-boundary mistakes. These are selected
method-admission observations, not every application's cryptographic key use,
irreversible revocation, deployment history or authority proof.

Literal retrieval pairs check non-document content, another document id,
another absolute method id with the same fragment, and another valid controller.
Each actual refusal is independent of its recommended canonical problem type.
An ordinary revoked/expired error is preserved without inventing a problem
object. The internal fragment extraction clause stays NOT_RUN; a separate getter
or final method selection is not evidence of an internal algorithm step.

All 416 historical rows remain as 263 pending plus 153 observed (146 PASS,
one NOT_APPLICABLE and six FAIL). Two original consumer rows retain their
baseline and old case_prefix/cases, with optional case_prefixes listing the
additional format case family. CI verifies the union of actual cases across
those prefixes, the complete historical set and each original field/digest.
The previously frozen review, 61 library clauses and 23 native contract clauses
keep their own independent attribution and evidence checks. New failures are
recorded for later implementation correction and reinspection under the
existing plan; neither the core nor the pinned subject is silently repaired.


## Optional fields and verification relationship forms

Twelve fresh cases make 46 actual calls to the pinned consumer, exercising 17
previously unobserved CID clauses. Five relationship families independently
compare absence with reference, embedded-only and mixed reference/embedded
forms. The embedded-only document has no top-level verificationMethod; the
mixed form uses distinct method ids. Seven other cases compare absent/present
controller, alsoKnownAs, service, verificationMethod, expires, revoked and a
nested verification-method extension. Missing verificationMethod is tested
without a dangling authentication reference. All key material is public test
material, and every case retains a separately accepted baseline control.

Each PASS records selected library acceptance and semantic value preservation.
OPTIONAL/MAY permissions do not require every consumer to implement each feature
or every producer to emit the property. An attributable permitted-input refusal
or lost capability is NOT_SUPPORTED, not an invented mandatory-rule FAIL;
incomplete captures or a failed baseline control are ERROR. A separate applicable
mandatory preservation rule would need its own verdict. Absence and relationship
forms are judged independently, so an absence failure cannot invalidate supported
embedded/reference forms. Known DID sets ignore order; unknown extension Lists
retain order and value kinds. Date controls compare equivalent instants, allowing
a different offset representation without treating it as value loss.

The selected library supports all 17 exercised permissions, yielding 268 cases,
223 requirement passes, nine recommendation passes, four requirement failures,
two recommendation failures, two inapplicable statements and 246 NOT_RUN. The
same four required timestamp findings and failing Inspector gate remain. This
is not SAGE registry Source optional-field support, relationship authorization,
cryptographic key suitability, every extension/representation, or full standard
conformance. Core1.0 and the separate projection scope are unchanged.

Schema2 retains every one of the original416 ids and baseline fields as
246 pending plus170 observed (163 PASS, one NOT_APPLICABLE and six FAIL).
The frozen353 review and previous library/native/policy evidence remain intact.
CI independently verifies all46 original calls and expected literal variants,
with regression controls for missing cases, observer misattribution, missing
values, extension order and equivalent date instants.

Sixteen selected-choice cases now add eight requirement-level observations: public codec output equivalence, local optional Multikey consumption, actual proxy invocation, IP-address certificate choice, and public-key conversion with external Multikey preservation. These are bounded actual observations, not proof of every internal algorithm step, all input values or operational registry authority.

### Additional options and resolver proof inclusion

Five fresh cases cover three previously unobserved MAY clauses: production-and-consumption.9/.14 and resolver-architectures.3. The selected direct producer receives JSONLD false/true; the selected consumer receives Require=1.1 with Strict false/true on explicit-context literal input. Call-boundary input and options are captured before delegation. These observations prove selected option acceptance, not universal option effects or full JSON-LD processing.

The actual universal Client.Resolve returns a proof-shaped resolution metadata map from an owned TLS upstream, with a proof-absent diagnostic control. This does not establish SAGE method proof creation, signature validity, result correctness verification or operational authority. An optional refusal or unavailable capability is NOT_SUPPORTED, not FAIL; missing or mismatched observation provenance is ERROR. Unrelated document metadata and additional proofs in the absent control do not impose new requirements on this MAY.

The original 416-clause baseline is preserved: 260 observed and 156 pending. Of the 246 reviewed anchor clauses, 90 have selected execution verdicts and 156 remain NOT_RUN. Existing nine failures and the failing conformance gate are retained.

### Selected resource kinds and DID parameters

Nine fresh cases archive eighteen actual root dereferencer calls with a literal example driver. Document native archives and accessor models are checked separately for capture consistency; neither replaces missing evidence from the other. Neutral archives are not subject-produced representations. Six cases return a document, listed or embedded verification method, service, or nested full/relative-id map with their actual native resource kind and media type. Three cases exercise service, serviceType and relativeRef selection. URI-list output establishes URL calculation and return only; no external endpoint content is retrieved.

Missing-fragment and unfiltered-document controls are diagnostic and cannot create extra MAY/OPTIONAL obligations. Optional refusal is NOT_SUPPORTED; missing or misattributed call evidence is ERROR. The existing required accept-forwarding failure, internal algorithm NOT_RUN entries and all original clause identities are preserved. This is selected library capability evidence, not arbitrary resource format support, all parameters, historical resolution, full JSON-LD processing or SAGE operational authority.

At the preceding resource-choice checkpoint DID1.1 resolution had 349 cases, 317 PASS, nine FAIL, four NOT_APPLICABLE and 156 NOT_RUN. Original baseline: 260 observed (248 PASS, three NOT_APPLICABLE, nine FAIL) and 156 pending. Of the 246 anchor clauses, 90 have execution verdicts and 156 remain NOT_RUN.

### Selected service routing roles

Four additional typed source-role clauses are now observed, corroborated by seven fresh ordinary URI-list/service calls. See [the scope and preserved limits](sage-remaining-clause-review.md#selected-service-routing-source-roles). Current DID1.1 resolution is 359 cases, 355 PASS, ten FAIL, four NOT_APPLICABLE and 117 NOT_RUN. Core1.0 and separate projection are unchanged; the failing conformance gate and planned core fixes remain. All 416 historical ids and baseline bytes are preserved.
