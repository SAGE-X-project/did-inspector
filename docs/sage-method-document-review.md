# Pinned SAGE method-document review

This is a separate documentary actor, `SAGE-X-project/sage-spec` at
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`. It is not the pinned did-go
runtime subject. Neither its judgments nor its totals are merged into the
resolution/projection reports or historical runtime pending ledgers.

The historical 51-clause documentary inventory preserves the exact W3C
text, text digest, level and follow-up references. Independent semantic
review has nine judged entries: method-syntax .1/.2/.3/.7/.8/.10/.11/.12
and method-operations .5. Six more entries have reviewed but unresolved
prerequisites, and 36 have not yet received a semantic review case. The
report therefore has nine PASS and 42 NOT_RUN, not fifteen PASS. Its
`review_progress` records these three different states.

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

The other six entries retain NOT_RUN with individual `pending_review`
records naming their required actor, reason and completion evidence:

- Method operations .1-.4 have abstract authorization, creation, resolution
  and update rules, but their complete selected profile/binding documents
  still need review. Authentication of a principal, command encoding and
  authoritative-source selection cannot be supplied by an invented ABI or
  endpoint. A complete documentary review can close author obligations;
  successful deployment execution is not an extra W3C author requirement.
- Method syntax .4/.5 constrain generated identifier uniqueness. They need
  an independently justified construction and applicable issuer/registry
  evidence, including namespace, non-reassignment and fork/DNS assumptions.
  A few distinct fixture strings or a textual guarantee are insufficient.

Reviewing these six prerequisites is not observing the required property.
They do not become PASS, FAIL, NOT_SUPPORTED or NOT_APPLICABLE because this
review found incomplete evidence. Concrete core/contract/spec changes and
operational verification retain their approved later order.

This is **reviewed-document replay**, not automatic semantic analysis of
arbitrary prose. The inspector's review JSON supplies independent reasoning
and full cited chapter ranges, not subject-authored verdicts. The executable
checks all sixteen Git blobs against their byte lengths and SHA-256 values,
every cited range, and the independently frozen W3C publication and clause
identity. Only that exact reviewed corpus can reproduce these nine author
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
clauses, security/privacy/topology/representation author review, operational
bindings and deferred registration are not silently completed by this tool.
