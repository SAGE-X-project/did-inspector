# Fresh method-security document review

This separate subject is `SAGE-X-project/sage-spec` at
`6d611b19764cfae50936ab4c63dbe4e1f9f78487`. An independent LLM re-read the
canonical 51 author/issuer statements and the complete sixteen-document
corpus. Its exact [report](sage-method-security-author-review.md) and
[review catalog](sage-method-security-recheck.json) are pinned independently
of the subject's own validation code. The new script checks committed Git
blobs, including their exact lengths and SHA-256, before replaying those
reviewed judgments. It is not an automatic semantic classifier.

The fresh documentary findings are **26 PASS, 19 NOT_APPLICABLE, 4 FAIL and
2 NOT_RUN**. Method-specific privacy, operation-level attack/amplification
analysis and DLT resource-burden discussion now satisfy their selected
document-author obligations. They do not demonstrate runtime defenses.

The composite RFC 3552 obligation remains FAIL: although the previously
identified denial-of-service discussion was added, actual management
authentication characteristics and complete authenticated-command binding
remain unspecified. The separate all-operations integrity/authentication and
fork-disambiguation findings also remain FAIL. The two actual issuer
uniqueness obligations remain NOT_RUN; text and a few fixtures cannot prove
operational allocation or global uniqueness.

This result does not replace or add to the historical
[23 PASS / 19 NA / 7 FAIL / 2 NR subject](sage-method-document-review.md),
the runtime reports, or their pending ledgers. All three historical review
files and their original source pin remain unchanged. A new protocol version,
management transport, chain ABI, operational authority or fork policy is not
adopted by replaying this review.

For a valid complete capture the documentary gate is FAIL and the command
returns 1, preserving all four actual findings. Missing or modified source
causes 49 ERROR and 2 issuer NOT_RUN and returns 2; no prior PASS/NA/FAIL is
replayed without the complete reviewed corpus. An unreviewed catalog or
review report is an evidence error. The command refuses existing output
files, dangling output links, and outputs inside either actual source checkout
or its Git metadata, including when the input names a checkout subdirectory.
Both new outputs are opened exclusively before their contents are written.
An output collision or I/O error returns 2; it can leave a newly created
empty or partial output, which is not complete evidence. Existing files
are never deliberately replaced. This is not an atomic two-file transaction.

The safe runtime check executes this Python CLI against the pinned Git
document source. It performs no message exchange, contract operation,
arbitrary endpoint access or subject implementation execution. Attack-like
capture substitutions are data-only unit tests. CI preserves the raw corpus,
full fresh report, CLI output, unit/coverage logs and source/output hashes in
`fresh-method-security-reports`. All existing CI and historical report gates
remain active. Green CI means the checker reports these reviewed findings
correctly; the method still has four documentary failures.

To run the focused tests, set `SAGE_METHOD_SECURITY_SPEC_ROOT` to a local
sage-spec Git repository containing the exact subject commit, then run
`python3 -B scripts/test_inspect_method_security_document.py`. A missing
source checkout is an error, never a skipped test. Local unit fixtures may
use a synthetic observer ID; published evidence must additionally bind its
actual Inspector checkout, workflow run and reviewed source hashes.
