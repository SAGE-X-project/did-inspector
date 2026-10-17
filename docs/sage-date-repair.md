# Separate key timestamp consumer inspection

The repaired root module is identified separately from the existing frozen SAGE
projection and resolution subjects. The original module pins, reports, known
failures and pending statement inventory remain unchanged.

The `adapters/sagedate` module runs exactly the two existing date-format cases
through the same independent profile and passive consumer observer. It checks
twelve valid calls and eighteen malformed calls, preserving the original input
hashes. The new report covers four statements and leaves the other 482 NOT_RUN.
This is selected mandatory syntax, not complete XML Schema support, relying-party
key non-use, registry authority, full SAGE integration or full conformance.

The adapter checks the actual compiled root module version and sum and rejects
module replacement. It advertises no generic or registry capabilities. Reusing
`ObservePolicy` does not inherit the frozen SAGE subject identity; that observer
returns actual call data and never supplies a verdict. The separate native
executable must identify the repaired module successfully. Unit-test build-info
fixtures are not native evidence.

`scripts/verify_sage_date_repair.py` checks the native raw receipt against frozen
case-input hashes, exact delegated input/options and independent literal normal
values. It requires malformed input to return a qualified consumer error and no
document. CI retains the native report, module metadata, compiler/source/binary
identity and coverage. These hashes identify the evidence, not registry authority
or a complete binary attestation. No new result is merged into historical reports.

Run the native command from `adapters/sagedate` with `INSPECTOR_REVISION` set to
the inspector commit. Its zero exit status means a receipt was emitted, not that
all observations passed. Run the independent Python verifier with `--evidence`,
`--observer` and a new `--out` path to require the four selected PASS results.
