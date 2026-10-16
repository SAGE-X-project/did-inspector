# Pinned SAGE method-document review

This is a separate documentary actor, `SAGE-X-project/sage-spec` at
`06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`. It is not the pinned did-go
runtime subject. Neither its judgments nor its totals are merged into the
resolution/projection reports or historical runtime pending ledgers.

The existing 51 author obligations are preserved, with their exact extracted
W3C text, text digest, level and follow-up references. Independent semantic
review currently covers seven: method-syntax .1/.2/.3/.7/.8/.12 and
method-operations .5. The remaining 44 have no review case and stay NOT_RUN.
This does not remove the 51 runtime NOT_RUN entries: that actor cannot
discharge a specification author's obligations. Each actor's work is tracked
separately, without summing their PASS or NOT_RUN counts.

The first seven cover one method name, identifier selection/composition,
sensitivity/normalization, chosen multiple identifier formats, colon use,
restricted fragment ABNF and the abstract deactivation procedure. The
three MAY clauses record permitted documentary choices, even though their
extracted level is `requirement`. They impose no new implementation feature.
Deactivation includes controller/scoped operator authorization, expected
version, the terminal readable state and its inactive resolution treatment.
Its deployment transaction and authenticated-principal binding are not
certified by this abstract description.

This is **reviewed-document replay**, not automatic semantic analysis of
arbitrary prose. The inspector's review JSON supplies independent reasoning
and full cited chapter ranges, not subject-authored verdicts. The executable
checks all sixteen Git blobs against their byte lengths and SHA-256 values,
every cited range, and the independently frozen W3C publication and clause
identity. Only that exact reviewed corpus can reproduce these seven author
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
