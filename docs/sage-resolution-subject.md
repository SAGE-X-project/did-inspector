# SAGE resolution inspection scope

Use `--scope resolution` in the separate `adapters/sage` CLI to inspect the
actual pinned SAGE resolver, DID Core 1.0 compatibility functions, dereferencer
and HTTP handler. The default `--scope projection` remains unchanged and retains
its own results. The resolution subject name is `did-go/advanced/sage-resolution`;
its module revision is `2ef282b40ccfe243c6cf3b1c05594e02171126cc`, with root did-go
at `ed54c505eafe1c9d3d2decd862d6a9f7fcd2cd23`. The binary verifies those pins
from actual build information and refuses unknown or replaced subject modules.

From `adapters/sage`, with Go 1.26.8 and `GOWORK=off`:

```sh
go build -mod=readonly -o /tmp/did-inspector-sage ./cmd/did-inspector-sage
/tmp/did-inspector-sage --scope resolution --profile did-core-1.0 --out /tmp/sage-resolution-core10.json --raw-out /tmp/sage-resolution-core10-cases.json
/tmp/did-inspector-sage --scope resolution --profile did-1.1 --out /tmp/sage-resolution-did11.json --raw-out /tmp/sage-resolution-did11-cases.json
```

The inspector owns the expectations and HTTP request construction. The adapter
calls actual `advanced/sage` players with explicitly local public record fixtures,
including source errors; it does not substitute the generic example method,
reuse old verdicts or repair the returned metadata. HTTP cases reach the actual
SAGE handler through an inspector-owned TLS loopback server and trusted test
certificate. They contact no agent, MCP, RPC or deployed registry.

## Observed coverage

| Profile | Cases | Requirement PASS | Recommendation PASS | NOT_RUN |
|---|---:|---:|---:|---:|
| DID Core 1.0 | 16 | 33 | 0 | 173 |
| DID 1.1 with CID and Resolution publications | 71 | 61 | 2 | 423 |

There are no FAIL or ERROR statements in these observations. The recommendation
PASS statements cover the selected resolution Accept option and the returned
contentType for the actual selected JSON key in an HTTP dereferencing result.
This does not replace the
projection scope's JWK alg recommendation FAIL or its separately observed
statements. Results from different scopes are not merged by copying verdicts.

Native cases observe returned identity, content presence, representation bytes,
metadata structure and error shape, deactivation, missing records, stale records,
key fragments, revoked and expired keys, and allowed or denied relationships.
Fixture version preservation has an adapter regression test; it is not a W3C
requirement that a metadata structure must include a particular versionId.
Empty metadata structures are accepted where the standard allows them.

HTTP cases observe GET and POST complete results, a requested representation,
key dereferencing, missing and stale records, malformed identifiers, unsupported
Accept and deactivation. Status checks compare the expected status with the
actual problem type and the pinned standard's status table. Server response
checks do not claim to prove a client's request-construction obligations.

Native document snapshots now capture every exposed data model property and
representation entry through public accessors, including keys, relationships,
services, extensions and explicit empty sets. Native method snapshots preserve
all returned fields under their standard property names. Dates retain the
returned offset and sub-second precision. No producer or validator is used to
repair this observation. The snapshot is an accessor translation, not a produced
DID representation; native representation bytes remain separate.

Fourteen additional cases compare actual GET/POST complete HTTP results with a
separate actual native call on the same fixed public record: six document fixture
shapes through each method and one key through each method. The comparison covers
all captured content, resolution/dereferencing metadata and document/content
metadata, including absent versus present members. It checks deactivated null
content, retains every extension, ignores map order and the order of recognized
DID sets, and permits singleton/set alternatives only where allowed. Unknown
extension arrays remain ordered. Changed keys, relationships, services, metadata,
missing content and duplicate members have independent negative unit checks.

The actual native request and result are retained beside the wire exchange in
`--raw-out`. The ordinary report omits PASS details. Raw HTTP records include
ephemeral loopback URLs, so raw output is not byte-deterministic even when report
timestamps are omitted. The fourteen comparison cases strengthen existing HTTPS clauses. The separate
native field cases below add newly observed clauses.

A PASS is limited to the observed clause and fixture. These comparisons establish
full captured-content equality for the selected default representations and
fixed records, not every representation, option or method algorithm. Error
result equality remains unobserved: HTTP may add SAGE-specific error extensions,
and those fields are neither silently removed nor inserted into native output.
Historical resolution, caching, remote contexts, endpoint operation, optional
metadata not returned by these records and operational Source authority remain
unestablished. Statements without a case remain NOT_RUN. Generic fixture-method
conformance is not advertised by this subject. These cases do not certify full
conformance or protected deployment.

SAGE-specific results in sage-inspector remain separate: active envelopes omit
`deactivated: false`, and unsupported Accept problems omit `sageCode`. Those two
requirement findings remain FAIL and retain their planned implementation fixes
and reinspection. This W3C observation scope neither repairs nor supersedes them.

## Request option observations

The resolution scope also includes 16 native request-option cases and four
loopback HTTP parsing-error cases. They cover malformed Accept values, wrong
modeled types, non-ASCII version identifiers and verification relationships,
invalid timestamp syntax, non-UTC timestamps, sub-second precision and an
unconfigured extension. Native refusals observe the actual subject's
INVALID_OPTIONS or FEATURE_NOT_SUPPORTED result; the adapter never invents that
result or invokes the subject's validator as the inspection oracle.

`Request.Options` takes precedence over the earlier Accept and relationship
shorthand. Valid types are copied to the subject API; wrong types and unknown
names are retained in Extra. Timestamp offsets and represented precision are
preserved when translated. A comma separator or precision beyond time.Time's
nanosecond capacity remains an original string in Extra, preventing Go's parser
from accepting a different grammar or truncating the value. The subject then
handles that modeled-name conflict. The original option strings and types also
remain in the raw case inputs.

The native timestamp observations include `.1Z`, `+09:00`, a tenth fractional
digit and a comma separator. They do not establish acceptance or rejection of
every XML datetime lexical form, historical lookup or normalization behavior.
For the unconfigured extension, rejection is scoped to this subject's default
resolver configuration; other resolvers may explicitly support that extension.

The HTTP parsing-error cases archive actual GET/POST request bodies, query
strings and returned errors. Runtime adapter tests verify status 400 and
INVALID_OPTIONS. Only their TLS transport statement is judged in the standard
profile: parsing can fail before the resolver is invoked, so those cases do not
prove a resolver algorithm return or a client's query/body construction rules.
The additional 13 requirement statements come from native observations. General
full-document coverage and the other evidence limits above still apply.

## Returned metadata observations

The metadata checks independently inspect the actual native metadata or metadata
inside GET/POST HTTP envelopes. Native translated fields never override wire
metadata. Complete HTTP error envelopes now exercise missing and stale source
records through both methods; the raw archive retains the whole response.

The added checks cover returned versionId ASCII strings, resolution contentType
ASCII media
type syntax and the selected fixture representation, dereferencing contentType
ASCII strings, Core 1.0 single-keyword errors, and the standard namespace prefix for
selected standard-defined error keywords. Extension error types are not assigned
the standard-prefix rule. The dereferencing contentType recommendation is judged
separately from its conditional format requirement. Malformed or duplicate-member
envelopes cause ERROR rather than PASS. An omitted optional field produces
NOT_APPLICABLE for its conditional format check; it never establishes that format.
The dereferencing contentType recommendation fails if omitted from a successful
key response and also checks its expected JSON type and actual returned wire
content. Error or content-free results do not satisfy its success precondition.

These cases add five Core 1.0 requirement observations and four DID 1.1 requirement
observations plus one DID 1.1 recommendation observation. Version syntax checks do
not require the fixture's exact value, establish historical lookup, or prove the
version's operational provenance. Resolution media type checks require the
selected fixture type and actual JSON
content with a DID identifier; application/did also requires the selected DID 1.1
context as a string or the first array entry. Media type essence comparison
accepts case-insensitive type names and valid parameters. Dereferencing ASCII
checks do not impose media syntax beyond that
clause. These checks do not certify every supported representation. The source
observation times
are not document creation or update times. No created/updated timestamp is
invented, and their unexercised statements remain NOT_RUN. Native document and all-member HTTP/native comparisons now cover the selected
records described above. Other optional metadata and operational authority
retain the same evidence limits.

## Native document field observations

Five additional cases per profile inspect fresh native snapshots for active
records. Core 1.0 uses the compatibility resolver. DID 1.1 explicitly requests
application/did and verifies that the actual returned metadata declares that
representation before inspecting CID fields. A missing document, native error,
wrong representation or malformed/duplicate-member snapshot causes ERROR rather
than a document verdict. Input and the actual returned observation remain in the
raw archive; no projection verdict is copied.

The independent rules inspect root identifier presence (also DID syntax for
Core 1.0), method map/set shape and mandatory properties, known JWK method type
shape, Core 1.0 method identifier/controller syntax, authentication/assertion/key
agreement set shape, and service map/set and property types. Core 1.0 checks the
service's mandatory id/type/endpoint properties. CID checks required type and
endpoint properties and duplicate present service identifiers; optional CID
service identifiers are not made mandatory.

Absent optional properties are NOT_APPLICABLE. An explicit empty method/service
set is checked as a set, but its nonexistent elements do not supply per-element
PASS observations. Empty present relationships fail their nonempty constraint.
Known JWK material is checked for mandatory property and map shape only. Unknown
method types and unsupported reference forms receive NOT_SUPPORTED. Relative or
external references are not dereferenced or promoted to verified methods. No
cryptographic key validity, controller authorization or remote service operation
is established by these field checks.

The new cases observe thirteen additional requirement clauses in each profile.
Some record-level observations are NOT_APPLICABLE because signing-only or
expired-signing records omit particular relationships; the corresponding clauses
also have actual applicable observations on other records. All reported new PASS
clauses have applicable native evidence. General URL Standard clauses, JWK-specific
class semantics and full material validation retain their unobserved status in
this scope. Syntactically URI-looking strings are not proof of URL Standard
conformance, and a different registered key class is not treated as JsonWebKey.
Unexercised publication clauses remain NOT_RUN.

## Public JWK material observations

Five new DID 1.1 native cases inspect exact JsonWebKey methods on the fixed public
records. These actual fixture relationships use references. The collector also
supports embedded methods in all five relationship names; unit controls exercise
embedded authentication methods. Core 1.0 results are unchanged. The cases judge CID JsonWebKey clauses 3, 4, 8, 12 and 13 freshly
from the actual application/did accessor snapshot. Other method classes,
including JsonWebKey2020, are not treated as JsonWebKey.

The minimal supported public formats are EC P-256 and OKP Ed25519/X25519. The
checks require their kty/crv fields, canonical unpadded base64url and complete
32-byte coordinate/octet lengths. P-256 coordinates must form a curve point.
OKP observations cover encoded octets; they do not establish point mathematics,
small-order safety or signature/KEM suitability. Format checks return
NOT_SUPPORTED for other key types/curves or uninspected registered metadata,
including algorithms and certificate fields. Unknown additional members are
retained and ignored as RFC 7517 allows. A y parameter is a supported coordinate
only for EC; its presence on OKP leaves full format semantics unobserved.

Registered non-public names are derived from the complete embedded
[jwk-parameters-20261013.csv](../profiles/sageresolution/jwk-parameters-20261013.csv),
fetched from the [IANA JWK parameter registry](https://www.iana.org/assignments/jose/#web-key-parameters).
The source bytes have SHA-256
`e897697bbbfc6df505806acbead93009b9b9534bfd45ce82c6158e6767cc0871`.
The inspector verifies this hash before building the DID 1.1 cases and makes no
runtime registry request. Private-class exclusion and Private/Secret-class
exclusion are separate checks; present forbidden names fail regardless of value.
This is a dated registry observation, not a promise about future registrations
or all sensitive information in unknown extensions.

The secretKeyJwk exclusion applies to these explicitly public document fixtures.
Its absence is judged separately from optional publicKeyJwk format/curve checks.
A missing optional publicKeyJwk is NOT_APPLICABLE for those conditional rules.
Malformed maps cannot establish private-member exclusion. Empty method sets or
other method classes do not invent applicable JsonWebKey evidence.

The format expectations come from [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517),
[RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) and
[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037). No subject validator or old
projection verdict is used. Unit controls use public vectors and harmless
non-public-member markers; actual CLI and loopback TLS runs use public fixtures.
These cases add five newly observed requirement clauses. Algorithm recommendations,
general URL Standard checks, certificates, operational authority and full
cryptographic/protocol conformance retain their separate evidence limits.
