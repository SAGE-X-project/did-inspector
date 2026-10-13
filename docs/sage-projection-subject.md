# SAGE projection inspection subject

`adapters/sage` is a separate subject module for
`github.com/sage-x-project/did-go/advanced/sage` at
`2ef282b40ccfe243c6cf3b1c05594e02171126cc`, with the root did-go module at
`ed54c505eafe1c9d3d2decd862d6a9f7fcd2cd23`. It does not reuse the generic
did-go adapter's conformance results or change that adapter's pin.

The inspector core imports no subject implementation. The new
`profiles/sageprojection` package selects the existing pinned publications
and extracts their statement identities through the existing report path.
It substitutes cases for the record-projection operation only. The adapter
translates neutral public fixture records and calls actual `sage.Respond`;
the inspector's own checks judge the produced bytes. No subject validator,
registry or claimed verdict is an oracle.

## Running separate profiles

From `adapters/sage`, with Go 1.26.8 and `GOWORK=off`:

```sh
go mod verify
go build -mod=readonly -o /tmp/did-inspector-sage ./cmd/did-inspector-sage
/tmp/did-inspector-sage --profile did-core-1.0 --deterministic --out /tmp/sage-core10.json --raw-out /tmp/sage-core10-cases.json
/tmp/did-inspector-sage --profile did-1.1 --deterministic --out /tmp/sage-did11.json --raw-out /tmp/sage-did11-cases.json
```

The binary rejects unknown, unpinned or replaced subject module identities.
The Inspector dependency's local replacement refers to the same checkout,
as in the generic adapter. Neither subject module can be locally replaced.
Both reports retain separate profile, publication hashes and subject identity.
The raw files preserve all case inputs and observed document bytes, including
PASS observations that the ordinary statement report does not retain.
Different output paths are required; existing aliases of one file are rejected.
The CLI prints its narrow inspection scope before the ordinary report summary.

Six independently specified public records exercise active signing/agreement
keys, signing only, P-256, a revoked entry, deactivation and expiration. Their
embedded SHA-256 is
`f87fbff1d38c749e41cd3173c78b72c461fdc8227ebe2353f1dfdfe6c75b774d`.
The Ed25519 test public key, X25519 basepoint and P-256 generator require no
private keys. The Source, controller and observation time are explicit local
fixtures; they do not establish authority, proofs, freshness or deployment.

## Observed statements and remaining coverage

The pinned subject yields:

| Profile | Requirement PASS | Recommendation FAIL | NOT_RUN |
|---|---:|---:|---:|
| DID Core 1.0 | 16 | 0 | 190 |
| DID 1.1 with CID and DID Resolution publications | 20 | 1 | 465 |

The cases check the produced JSON root, media type, identifier, method member
shape and references, relationship cardinality, service member shape and
set uniqueness. DID 1.1 additionally checks the base context, JsonWebKey type,
private JWK member exclusion and curve member presence. These are observations
of returned fixture documents, not tests of arbitrary input acceptance or the
full algorithms behind each publication statement. A PASS is limited to those
observed clauses and outputs. The root check cannot certify preservation of
arbitrary data-model extensions; the public JWK checks do not establish full
curve arithmetic or arbitrary JOSE algorithm support.

The recommendation FAIL is `cid10#JsonWebKey.7`: include JWK `alg`. SAGE's
adopted chapter 10 intentionally omits that optional member because the
registered key fixes the algorithm. The independent DID recommendation remains
FAIL; this inspection does not alter the approved SAGE projection policy.
This is distinct from a requirement-level failure.

All other publication statements remain NOT_RUN. The projection subject
advertises none of the generic core capabilities: it is not a generic document
producer, consumer, validator or the generic fixture-method implementation.
General resolution, dereferencing, HTTP binding, remote contexts and operational
key authority require their own inspection connections. No whole-standard
conformance or deployed-message protection is established by a successful gate.
The ordinary generic did-go profiles and stored historical evidence remain intact.

SAGE-specific inspection in sage-inspector remains a separate result at its
adopted specification revision. Its two requirement findings are still FAIL:
active JSON envelopes omit `deactivated: false`, and unsupported DID Resolution
Accept errors omit `sageCode`. They remain implementation fixes and reinspection
work in the approved core migration order. Neither the W3C recommendation result
nor these projection PASS observations resolve or supersede those findings.

A separate [resolution scope](sage-resolution-subject.md) connects native SAGE
resolution, dereferencing and loopback HTTP observations. It preserves a separate
subject identity and does not extend the PASS claims of this projection scope.
