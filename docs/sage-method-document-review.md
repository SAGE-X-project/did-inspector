# Pinned SAGE method-document review

This is a separate documentary actor, `SAGE-X-project/sage-spec` at
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`. It is not the pinned did-go
runtime subject. Neither its judgments nor its totals are merged into the
resolution/projection reports or historical runtime pending ledgers.

The historical 51-clause documentary inventory preserves the exact W3C
text, text digest, level and follow-up references. Independent semantic
review has 44 judged entries: twenty PASS, nineteen NOT_APPLICABLE and five
FAIL. All 51 entries have received semantic review, but seven retain
unresolved prerequisites and therefore NOT_RUN. Its `review_progress`
separates judged entries from reviewed prerequisites and reports zero
unreviewed entries. The five FAIL are documentary gaps, separate from the
runtime actor's thirteen failures. Semantic review coverage is not whole
method conformance or completion of all prerequisite evidence.

The original eleven PASS cover method-syntax .1/.2/.3/.7/.8/.10/.11/.12
and method-operations .2/.4/.5. Their evidence and judgments are unchanged.

The baseline inventory also contains the actual generated-DID uniqueness
obligations (method-syntax .4/.5). These are retained under their original
IDs, with their issuer actor and required evidence explicitly recorded in
`pending_review`. A declaration of uniqueness in prose does not discharge
that actual property. This review does not remove the historical runtime
NOT_RUN entries or merge the two actors' verdicts or counts.

The first seven cover one method name, identifier selection/composition,
sensitivity/normalization, chosen multiple identifier formats, colon use,
restricted fragment ABNF and the abstract deactivation procedure. The
three MAY clauses record permitted documentary choices, even though their
extracted level is `requirement`. They impose no new implementation feature.
Deactivation includes controller/scoped operator authorization, expected
version, the terminal readable state and its inactive resolution treatment.
Its deployment transaction and authenticated-principal binding are not
certified by this abstract description.

The two additional MAY observations concern the explicit path and query
restrictions in the closed chapter 06 DID-URL grammar. They establish a
permitted documentary choice, not runtime path/query rejection or optional
DID parameter support.

The additional creation and update judgments use the same abstract
method-document criterion as the earlier deactivation judgment. Creation
connects controller-selected identifiers, proof fields and atomic initial
records to the associated projections, with account-bound commitment/reveal
for eip155 and authenticated web administration. Updates identify allowed
mutations, immutable fields, scoped controller/operator authority, expected
versions, atomic history and the resulting document changes. W3C does not
require a concrete API or ABI for these procedures. These judgments do not
certify a deployment, transfer all-operations authorization or response
identity checks into PASS, or change the existing deactivation judgment.

The other four entries retain NOT_RUN with individual `pending_review`
records naming their required actor, reason and completion evidence:

- Method operations .1/.3 retain semantic gaps in the reviewed corpus:
  all-operations authenticated principal/credential binding and whole-method
  response-authenticity/source-readiness binding, including eip155. Abstract
  authorization checks and a complete TLS-origin web branch do not close
  those particular remaining contracts. No concrete ABI or successful
  deployment is an extra W3C author requirement.
- Method syntax .4/.5 constrain generated identifier uniqueness. They need
  an independently justified construction and applicable issuer/registry
  evidence, including namespace, non-reassignment and fork/DNS assumptions.
  A few distinct fixture strings or a textual guarantee are insufficient.

Reviewing these four prerequisites is not observing the required property.
They do not become PASS, FAIL, NOT_SUPPORTED or NOT_APPLICABLE because this
review found incomplete evidence. Concrete core/contract/spec changes and
operational verification retain their approved later order.

The additional representation review distinguishes using a standard from
authoring a new representation. SAGE defines record projections using
existing DID JSON representations. It defines no new representation-level
extension mechanism, Multikey header or alternative lexical serialization.
Resolution metadata under `sage` and the A2A `AgentExtension` live in separate
objects; they do not make this author a new DID representation author.

| Clauses | Author case and bounded judgment |
|---|---|
| DID 1.1 media-types .1 | PASS for explicitly identifying the DID 1.1 projection with `application/did` and separating that document from the resolution envelope. |
| CID Multikey .24 | NOT_APPLICABLE: SAGE defines no Multibase key header values; its projection explicitly excludes Multikey. |
| DID 1.1 extensibility .2/.3/.4 | NOT_APPLICABLE: the additional representation-level mechanism is not defined, so its optional choice, lossless conversion and type-mapping recommendations have no selected author activity here. |
| DID 1.1 production-and-consumption .1/.2/.3/.4/.5/.6 | NOT_APPLICABLE to SAGE authoring a new representation. It adopts existing representations and their standard context entry, without defining new type/lexical rules, generic media fragment rules or representation entries. |

These ten applicability judgments do not discharge the original W3C
representation author's obligations or excuse any implementation from the
adopted rules. Deterministic type mappings, unique IANA association, fragment
processing, lexical rules and entries-map handling remain independently
assessable for the adopted representation and its producer/consumer. Two
projections that change verification-method type are not evidence of lossless
reserialization. Absence of an optional author choice is not a PASS for
implementing that feature or refusing its input.

The media-types .1 PASS is a DID 1.1 documentary media-identification judgment.
It does not certify every media convention, negotiation, serializer behavior,
or the IANA registration or alias status of the legacy Core 1.0
`application/did+json` name. In particular, the .2 author applicability result
must never be read as registration approval. Registration and the standard
representation's obligations need their own evidence, rather than inference
from a label in SAGE prose. The existing runtime actor remains separate.

The applicability cases use the same full sixteen-file corpus and cited
ranges as positive judgments. The fixed reviewed ID set and explicit
`review_verdict` reject unreviewed applicability claims. Missing, modified or
malformed evidence turns all 44 judged cases, including all applicability
judgments, into ERROR: it cannot produce NOT_APPLICABLE without its reviewed corpus.

The security review covers fifteen cases for DID 1.1 security-requirements .1 through .14
and privacy-requirements .1 against the complete fixed author corpus.
They use the actual [RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.txt)
sections 4.6 and 5 and [RFC 6973](https://www.rfc-editor.org/rfc/rfc6973.txt)
section 5 as independent review sources. SAGE need not use those reference
names, a particular section title or a review matrix to satisfy substantive
requirements. The RFCs are not inserted into SAGE's sixteen subject blobs.

| Clauses | Documentary judgment |
|---|---|
| Security .3/.4 | PASS for the additional attacks and residual trust/compromise risks actually discussed. This does not prove that mitigations work. |
| Security .7 | PASS for discussing registry identity, atomic reservation, non-reassignment and commitment policy. Actual issuer uniqueness in method-syntax .4/.5 remains unresolved. |
| Security .8/.9 | PASS for the endpoint-authentication discussion and the selected self-validated-node or explicitly trusted-resolver modes, including finality/readiness and excluded malicious trusted sources. Arbitrary light-client modes and actual source bindings are not certified. |
| Security .11 | PASS for identifying private/ephemeral keys and shared/expired traffic secrets as confined material excluded from logs. |
| Security .12/.14 | NOT_APPLICABLE to absent document-signature and new DID authentication-service-type definitions. PoP, Card/message signatures and an A2A discovery service are not those activities. |
| Security .5/.6/.10 | NOT_RUN with individual actor, reason and completion evidence: remaining principal/credential, whole-method read-authenticity and protected-data bindings are not closed. No deployment, ABI or operational authority is invented. |

Four security and privacy documentary failures remain visible:

| Clause | Level | Missing discussion |
|---|---|---|
| Security .1 | Requirement | Method-specific residual DoS susceptibility and why avoidance is unreasonable or out of scope, required by RFC 3552 itself. This is not failure for omitting a citation or promotion of .13's SHOULD. |
| Security .2 | Requirement | Amplification exposure or inapplicability for DID operations. Generic messaging replay checks and size bounds do not supply it. |
| Security .13 | Recommendation | Expected DLT peer computation, storage/history and read/transaction burdens in relation to DoS, or a justified departure. This is not a demand for completed benchmarks. |
| Privacy .1 | Requirement | Applicable method-specific RFC 6973 risks of persistent/public DIDs, controller/key/service records, retained history and resolver observations. Encryption and secret handling do not replace privacy analysis. |

The mixed MUST/SHOULD in security .10 is not failed merely for an absent
susceptibility matrix. The three unresolved cases align with existing
method-operations .1/.3; their complete selected binding semantics can close
an author case without a successful deployment. The seven prerequisites
include those three and the four earlier unresolved entries. Reviewing
fifteen clauses does not mean all fifteen passed or all gaps were repaired.
Specification repairs retain their approved later order.

The final ten previously unreviewed entries concern resolution author roles.
Their independent review adds two bounded PASS, seven NOT_APPLICABLE and one
recommendation-level FAIL. It preserves the other 41 rows, including all
seven unresolved prerequisites and four earlier documentary failures.

| Clauses | Documentary judgment |
|---|---|
| Resolution resource .45/.46/.47 | NOT_APPLICABLE: SAGE rejects paths and queries and selects no method or extension mechanism for dereferencing them. This is a different MAY from the earlier permitted syntax restrictions. Absent functionality is not a runtime PASS or NOT_SUPPORTED. |
| Document metadata .17/.22 | NOT_APPLICABLE: no `equivalentId` or `canonicalId` is emitted or given authority. Normalizing the document `id` does not select optional alias metadata. No literal alias equivalence, global uniqueness or cross-method linkage is certified. |
| Errors .6 | NOT_APPLICABLE: SAGE error mapping and `sageCode` do not declare that a new DID error type `refines` a standard error. The optional declaration is not selected. |
| Method architectures .1 | PASS within the frozen informative implementation-details note and its recorded recommendation level, for documented self-validation or an explicitly trusted authenticated resolver, fresh consistent observations and record projection. The frozen publication recognizes trusted secure-channel access as verifiable guidance; it does not mandate a new light-client topology or deployment. |
| Method architectures .2 | PASS for specifying how selected signing-key PoP and KEM endorsements are verified before projection: exact challenge, suites, signer relationships and verification order. The text does not require a portable or whole-result proof. PoP alone proves no mutation authority, current state, freshness or completeness; KEM endorsement proves no KEM private-key possession. Separate source and credential prerequisites remain unresolved. |
| Method architectures .3 | NOT_APPLICABLE: neither projection nor metadata selects placement of a Resolve-result proof. The proof-use judgment in .2 does not imply embedding those proofs in the public document. |
| VDR forks .1 | Recommendation-level FAIL: chain ID, registry address, deployed code, future network/readiness configuration, returned block hash and version monotonicity do not specify how competing forks sharing those identifiers are distinguished or rejected. No particular genesis/checkpoint format, deployment or operational trust decision is imposed. |

The new fork finding is a fifth documentary gap. Its specification repair
retains the approved later review order and does not add a runtime failure
or change the existing thirteen failures and nine core repair causes.
All ten entries have now been reviewed; seven other author prerequisites
remain NOT_RUN with their existing individual completion evidence. Optional
non-selection and reviewed prerequisites must not be exchanged to improve
the totals. The full sixteen-file capture remains necessary for every new
PASS, applicability judgment and failure, including the fork discussion.

`documentary_gate` is FAIL for this reviewed corpus. The CLI exits 1 for a
normative FAIL or evidence ERROR, and 0 only when neither is reported. Its
PASS gate alone would not establish unobserved clauses or whole conformance.
Unavailable evidence yields 44 ERROR and 7 NOT_RUN, with no normative FAIL
or applicability conclusion. CI expects exit 1 and independently requires
the exact five FAIL (three requirements, two recommendations), zero ERROR,
complete source/replay identity and separate runtime results. A green CI
means the inspector reported those known gaps correctly; it does not mean
the method document conforms or that known failures were suppressed.

This is **reviewed-document replay**, not automatic semantic analysis of
arbitrary prose. The inspector's review JSON supplies independent reasoning
and full cited chapter ranges, not subject-authored verdicts. The executable
checks all sixteen Git blobs against their byte lengths and SHA-256 values,
every cited range, and the independently frozen W3C publication and clause
identity. Only that exact reviewed corpus can reproduce these 44 author
judgments. Different, missing, extra, malformed or modified evidence yields
ERROR, not a normative FAIL. It cannot confer PASS on an unreviewed revision.
It must not be presented as a general-purpose documentation conformance
checker or a substitute for fresh semantic review after a specification edit.

Run from the inspector root, choosing report files outside the subject:

```sh
python3 scripts/inspect_method_document.py \
  --repository /path/to/sage-spec \
  --out /path/to/reports/method-document.json \
  --raw-out /path/to/reports/method-document-raw.json \
  --inspector-revision INSPECTOR_COMMIT
```

The command reads committed objects with replacement refs disabled. It never
reads the subject's working files, checks out branches, invokes hooks, edits
the subject, registers a DID or makes a transaction. Raw blobs and the report
are separate artifacts. The CI job checks out the exact public specification
revision, exercises unit and real Git runtime checks and publishes
`method-document-reports`, separately from `sage-projection-reports`.

The current runtime resolution remains 369 cases, 371 PASS, 13 FAIL,
4 NOT_APPLICABLE and 98 NOT_RUN. Its thirteen failures and nine repair causes
remain in the approved later core/contract repair work. Five internal
clauses, seven author prerequisites, five documentary repairs, operational
bindings and deferred registration remain incomplete.
