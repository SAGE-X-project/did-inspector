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
| DID 1.1 with CID and Resolution publications | 110 | 84 | 2 | 398 |

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


## Selected URL Standard observations

Five additional DID 1.1 cases freshly resolve each active fixed public record
and inspect its actual application/did accessor snapshot. They cover CID
subjects.1, controllers.3, verification-methods.5/.7, services.6/.13 and
DID 1.1 core-properties.1. Six previously unobserved requirements pass.
The optional root controller property is absent on all these actual records,
so its clause is NOT_APPLICABLE, rather than PASS. After the URL addition, DID 1.1 had 76 cases,
67 requirement passes, two recommendation passes, one inapplicable statement
and 416 unobserved statements. Core 1.0 results remain unchanged.

The independent parser is
[nlnwa/whatwg-url v0.6.2](https://github.com/nlnwa/whatwg-url/tree/v0.6.2),
commit `605b909fe66d0472311892f4feed6b4de3e2bdb8`, with versions and checksums
pinned in the root and SAGE adapter Go modules. CI preserves their selected module
metadata alongside the actual subject module and binary evidence. Its current Go-compatible transitive dependencies
are also pinned. The observer uses both validation-error reporting and failure
on validation errors. Because v0.6.2 predates the current strict-domain error
reporting step, a separate strict ToASCII check enables STD3, label/hyphen
validation and DNS length verification for selected ASCII hosts using pinned
`golang.org/x/net/idna v0.61.0`. Unit controls cover leading/trailing and third/
fourth-position hyphens, underscores, empty labels and overlong labels. It
parses the original string without a base URL and
never repairs the snapshot or substitutes a normalized serialization.

Under the [URL Standard writing and parsing rules](https://url.spec.whatwg.org/#url-writing),
parser recovery alone does not establish validity. Unit controls separately show
that permissive parsing can succeed while malformed escaping, whitespace or
missing HTTPS slashes remain invalid. Expectations come from those rules, not
from the subject's parser or verdict. The standard was reviewed on 2026-10-13 at
commit `fde3f74f063341a28d437216f75735b8b40128f5`; that revision records the review
context, without changing the pinned CID/DID publications or freezing a living
standard as the protocol's authoritative reference.

The selected scope is ASCII opaque did: URLs and HTTPS DNS URLs. Other schemes,
relative URLs/base resolution, non-ASCII and IDNA/percent-encoded/IP hosts remain
NOT_SUPPORTED. This is a bounded syntax observation, not a claim that the older
parser release implements every current URL Standard branch. Optional absent
fields and no applicable values are NOT_APPLICABLE. Embedded method definitions
are collected in all five relationships regardless of material class; reference
strings are not definitions. Unit controls exercise all five embedded locations;
actual fixtures use references. Endpoint maps have separate semantics, so nested
text is not guessed to be a URL. A string endpoint or string element in a mixed
endpoint set is inspected. Malformed enclosing sets produce ERROR when their
applicable values cannot be enumerated; other field obligations remain separate.

The remaining resolution scope is still incomplete. This report leaves 368
requirement and 48 recommendation statements NOT_RUN. These include generic
DID parsing and production/consumption operations, controller/reference and
service semantics, optional metadata/time/history, method/registry behavior,
proof/trust and additional resolution/dereferencing/binding branches. The complete gap inventory now classifies these statements against actual
adapter operations. The next work is to add fresh native result and metadata
assertions according to those evidence prerequisites. No runtime operation or PASS may be inferred from a missing case.
Endpoint reachability, operational authority, relative expansion, all URL
schemes, deployed Source behavior and full standard conformance are unestablished.

The complete [pending-clause inventory](sage-resolution-gaps.md) records every
current DID 1.1 NOT_RUN id, its addressed operation and evidence prerequisites.
Its classifications do not change report verdicts or erase the separate
Core 1.0 pending work.

## Native result and error observations

Ten fresh native `resolve` cases inspect five active public records and five
independent error scenarios: malformed DID, unsupported method, fixed Source
record miss, stale Source and unsupported Accept. The subject's `ResolveString`
parses malformed input; the inspector does not fabricate its error. Unsupported
method uses the actual SAGE-only resolver registration. Missing record uses a
request that differs from the single fixed Source record, not an operational
registry absence. Stale Source returns INTERNAL_ERROR; unsupported Accept returns
FEATURE_NOT_SUPPORTED. Neither is attributed to the NOT_FOUND algorithm branch.

The added checks inspect success document identity, resolution metadata, typed
error descriptor and the selected invalid/method/missing-record branch outcomes.
Error type, null document and empty document metadata have independent negative
controls. Expected scenarios are fixed before execution so a missing error cannot
make its own required check inapplicable. HTTP/comparison output is rejected by
this native observer. Actual inputs and complete native output are retained.

An absent optional W3C `deactivated` member is NOT_APPLICABLE; when present it
must be boolean false for these active fixtures. This does not repair the SAGE
profile's separate mandatory-marker failure. Successful cases likewise mark the
conditional error-descriptor rule inapplicable. Aggregation retains an applicable
PASS for that rule from actual error cases.

After the native result addition, DID 1.1 had 86 cases, 80 requirement and two recommendation passes, two
inapplicable statements and 402 unobserved statements. Thirteen requirements
and one optional conditional rule are newly observed. Core 1.0 is unchanged.
The schema-2 gap inventory retains every original historical entry and its
original provenance while tracking current CI expectations separately.

The native adapter marshals typed metadata for capture; these cases do not prove
the subject serializer, internal Source call order, authoritative history or full
DID-document conformance. Resolving.1 establishes that the selected method returns
a document for these actual inputs, not conformance of every property. There is
no output repair, projection verdict copying, external target or private key.

## Direct native output metadata serialization

The separate `InspectMetadata` operation freshly resolves ten selected success
and error scenarios and dereferences two valid DID URLs (found and missing
fragments). It directly calls the pinned
`resolution.ResolutionMetadata.MarshalJSON` and `document.Metadata.MarshalJSON`
methods. The `Document`/`document` role means didDocumentMetadata for resolve
and contentMetadata for dereference. Each structure retains the exact returned
bytes, serializer identity
and call error independently. It neither runs the subject validator nor uses a
generic encoder as evidence. An error in one structure cannot erase the other.
Native 1.1 attribution is unavailable for HTTP, compatibility functions and
adapter-rejected malformed dereference URLs.

Twenty-four cases separately inspect each output structure against
metadata-structure.1 through .4. The independent parser checks a UTF-8 JSON map,
string property names and recursive JSON values, rejecting malformed bytes,
duplicate members and non-map output. Actual serializer failure is FAIL for
serializability and ERROR for unavailable shape evidence. Missing or mismatched
serializer attribution is ERROR. Empty maps are valid; an absent optional
property is not repaired.

The serializability observation is limited to ASCII strings and safe integer
literals (absolute value at most 9007199254740991). Unicode, fractional or other
numeric values return NOT_SUPPORTED for that check, not a standard prohibition.
These limits avoid claims about numeric/Unicode roundtrip fidelity. The
[Infra JSON rules](https://infra.spec.whatwg.org/#serialize-an-infra-value-to-json-bytes)
convert compatible values and serialize to UTF-8; the requirement is that the
structure is serializable, not that Go and JavaScript emit identical bytes.

All four requirements pass for these actual output maps. DID 1.1 now has 110
cases, 84 requirement and two recommendation passes, two inapplicable statements
and 398 unobserved statements (350 requirements and 48 recommendations).
Core 1.0 and the separate projection observations are unchanged. The historical
416-entry inventory is retained as 398 pending and 18 observed entries.

These cases establish selected output communication shape and serialization
possibility only. They do not establish input metadata compliance, all typed
pre-serialization values, arbitrary Infra values, subject serializer fidelity,
ECMAScript byte equality, authority or whole-document conformance. Unit-only
malformed-output controls are never attributed to actual subject execution.
