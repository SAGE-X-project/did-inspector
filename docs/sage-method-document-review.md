# Pinned SAGE method-document review

This is a separate documentary actor, `SAGE-X-project/sage-spec` at
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`. It is not the pinned did-go
runtime subject. Neither its judgments nor its totals are merged into the
resolution/projection reports or historical runtime pending ledgers.

The historical 51-clause documentary inventory preserves the exact W3C
text, text digest, level and follow-up references. Independent semantic
review has 22 judged entries: twelve PASS and ten NOT_APPLICABLE. Four
entries have reviewed but unresolved prerequisites, and 25 have not yet
received a semantic review case. The report therefore has 29 NOT_RUN.
Its `review_progress` distinguishes judged, reviewed-pending and unreviewed
entries; judged includes both PASS and evidence-backed NOT_APPLICABLE.

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
malformed evidence turns all 22 judged cases, including the ten conditional
ones, into ERROR: it cannot produce NOT_APPLICABLE without its reviewed corpus.

This is **reviewed-document replay**, not automatic semantic analysis of
arbitrary prose. The inspector's review JSON supplies independent reasoning
and full cited chapter ranges, not subject-authored verdicts. The executable
checks all sixteen Git blobs against their byte lengths and SHA-256 values,
every cited range, and the independently frozen W3C publication and clause
identity. Only that exact reviewed corpus can reproduce these 22 author
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
clauses, 25 unreviewed author entries, four author prerequisites, operational
bindings and deferred registration are not silently completed by this tool.
