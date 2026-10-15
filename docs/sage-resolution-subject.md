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

`--case-timeout` sets a positive per-case execution budget (default `5s`).
Use `--case-timeout 30s` for source inspection on cold or race-instrumented
runners, as CI does. This budget is an inspector execution limit, not a
protocol timing requirement. Expired or incomplete source analysis remains
ERROR; increasing the budget never substitutes evidence or changes predicates.

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
| DID 1.1 with CID and Resolution publications | 215 | 185 | 5 | 292 |

There are no requirement-level FAIL or ERROR statements in these observations.
The fresh DID 1.1 resolution scope retains two recommendation FAILs: missing
JWK alg and default JSON-LD production of an undefined root term. This is independent of the separate projection finding. The earlier recommendation
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

All four requirements pass for these actual output maps. After this addition, DID 1.1 had 110
cases, 84 requirement and two recommendation passes, two inapplicable statements
and 398 unobserved statements (350 requirements and 48 recommendations).
Core 1.0 and the separate projection observations are unchanged. The historical
416-entry inventory is retained as 398 pending and 18 observed entries.

These cases establish selected output communication shape and serialization
possibility only. They do not establish input metadata compliance, all typed
pre-serialization values, arbitrary Infra values, subject serializer fidelity,
ECMAScript byte equality, authority or whole-document conformance. Unit-only
malformed-output controls are never attributed to actual subject execution.

## Selected native error/state and HTTPS response branches

Three fresh native cases inspect missing DID dereferencing, deactivated DID
resolution and an ordinary unexpected Source error. Missing uses a different DID
with no fragment, not a missing key within an existing document. It establishes
the fixed Source record miss only. Deactivated uses the actual inactive public
record; metadata, null document and boolean true marker are checked separately.
`SourceFailure: fixture.unexpected` returns an ordinary Go error, not a SAGE error
code. The actual SAGE wrapper maps it to record.unreachable and INTERNAL_ERROR.
This tests that wrapper's unexpected Source path, not every internal failure.

Error type, absent content, actual null dereference stream and content metadata
have independent negative controls. The eleven previously pending native error
clauses pass; the already observed INTERNAL_ERROR type clause is freshly checked
again without counting it as a new requirement. Expected branches are fixed
before execution and never become inapplicable because output is missing.

Ten fresh owned loopback TLS cases cover GET/POST resolution envelopes, direct
DID-document responses, dereferencing envelopes, direct verification-method
responses and deactivated envelopes. Each archives a separate actual native call
on the same public record. TLS, request method/Accept/body and native input,
operation and Accept must match the independently selected scenario. Response
status, exact content-type and complete selected JSON representation are checked.
Direct responses are compared with native Raw, not just an accessor snapshot.

Eleven previously pending HTTPS clauses pass for those selected branches. Parent
clauses establish their particular response branch, not every option or media
type. The body-representation rule includes correspondence with the Content-Type
header; a header-only change fails both that rule and the header-equality rule.
A body-only change leaves the header assertion intact and fails the body rule.
GET support is observed at the owned interface; inspector-built requests do not
establish subject-client construction or production ingress behavior.

After the error/wire addition, DID 1.1 had 123 cases, 106 requirement and two recommendation passes, two
inapplicable statements and 376 unobserved statements (328 requirements and 48
recommendations). Core 1.0 remains unchanged. All original 416 pending-clause
entries are preserved as 376 pending and 40 newly observed entries. The primary
remaining counts are 44/0/106/117/105/4; they are routing counts, not task counts.

No output is repaired, validator verdict reused, operational registry queried or
service endpoint contacted. The two separate SAGE metadata failures remain for
implementation correction. Source authority, general algorithm conformance and
all representations are unestablished.

## Selected native key and document fields

Five fresh application/did resolutions inspect service member presence, selected
verification material and the JWK alg recommendation. Service maps must contain
id, type and serviceEndpoint. Optional absent service/method/JWK fields remain
inapplicable; an explicit empty service set has no member to violate that rule.
Root methods and embedded relationship definitions are inspected independently
of previously recorded projection results.

A single known JsonWebKey public material field passes the duplicate-material
check. Unknown method types, additional material aliases or uninspected extension
names remain NOT_SUPPORTED. If Ed25519 JWK and Multibase fields coexist, the
observer decodes the canonical 32-byte JWK x and the pinned CID 0xed01 Multibase
format. Equal public bytes FAIL; different or unrecognized dual encodings remain
NOT_SUPPORTED. This does not establish full key validity or cryptographic safety.

For an actual JsonWebKey with publicKeyJwk, the recommended alg must be present
as a nonempty string. Its absence is a recommendation FAIL, despite alg being an
optional JWK property. This is presence/type evidence only, not algorithm registry
membership or compatibility. All five actual native outputs lack alg, so the
fresh resolution report records that failure. No projection verdict is copied.

After the key-field addition, DID 1.1 had 128 cases, 108 requirement and two recommendation passes, one
recommendation failure, two inapplicable statements and 373 unobserved statements
(326 requirements and 47 recommendations). The requirement gate still passes.
Core 1.0 and the separate projection report are unchanged. The original inventory
retains 373 pending and 43 observed entries, including the new failure.

The versionId last-Update recommendation remains NOT_RUN because the fixed
Source version cannot demonstrate actual update history. The composite DID 1.1
verification-method clause also remains NOT_RUN: id/controller syntax cannot
prove every referenced CID obligation. No authority/history is fabricated and no
subject output, missing alg or existing SAGE metadata failure is repaired.

## Actual serialized document context and media type

Five fresh native resolutions inspect actual application/did Raw bytes, not the
accessor snapshot, for json-ld-processors.3/.4/.7 and production.4. The independent
parser requires a duplicate-free UTF-8 JSON map. Context presence and the exact
DID 1.1 string or first array item are checked independently of downstream media
type. Additional array values are inspected as JSON values only, limited to ASCII
strings and safe integers; other suffix values remain NOT_SUPPORTED.

Downstream contentType must be an ASCII, syntactically valid MIME type whose
case-insensitive essence is application/did. Valid parameters are allowed;
malformed parameters are rejected rather than discarded. Any error metadata
property or unusable native representation makes this observation unavailable.
Raw bytes, request and complete native result remain attached to each verdict.

Four requirements passed on these actual outputs. After this addition DID 1.1 had 133 cases,
112 requirement and two recommendation passes, one recommendation FAIL, two
inapplicable statements and 369 unobserved statements (322 requirements and
47 recommendations). Missing alg remains a recommendation failure. The original
416 entries are retained as 369 pending and 47 observed entries.

These cases establish context fields and media declaration, not general JSON
production or JSON-LD conformance. At that point production.1/.2 and
json-ld-processors.2 remained NOT_RUN: post-consumption getter equality cannot prove preservation of all
pre-producer input entries and value conversion rules. JSON-LD processing, term
semantics, remote context fetching and extension registration are not invoked
or established. Absent optional inputs, update history and authority stay outside
this evidence; no projection/generic verdict is copied and no output repaired.

## Actual producer and consumer call boundaries

Five fresh native resolutions use passive wrappers around the exact pinned
producer and consumer passed to advanced/sage.NewResolver. They retain detached
pre-producer data and representation-entry accessor maps, actual options,
serialized bytes, returned media type and errors. Consumer input bytes/media and
all options, detected version, dropped terms, and independently returned data
and representation-entry maps are retained separately. The underlying delegated
arguments and return values are unchanged. Unit controls and direct runtime
comparison with the unwrapped resolver verify observation transparency.

The observer requires one attributed call per actor, the actual default DID 1.1
options, and byte continuity from producer to consumer to resolver. It independently
parses all captured maps. @context has explicit production processing, so adding
the base context to an initially empty representation map is allowed; every
other actual pre-input entry is compared against the root serialization. The
consumer must return @context separately from every other retained input entry.
Producer media type is judged independently of consumer or resolver metadata.
A non-application/did consumer input is outside these consumer observations and
cannot gain PASS. Dropped-term processing is likewise outside the preservation
judgment rather than assumed valid. Malformed archives are ERROR with original
JSON fields preserved as byte strings, not empty evidence or repaired output.

The selected clauses are production-and-consumption.10/.11/.16/.17,
and consumption.2. Equality covers actual ASCII strings,
safe integers, booleans, nulls, arrays and maps in the selected fixtures. Other
numeric/Unicode values remain NOT_SUPPORTED; typed DateTime/Double conversion,
all data types, JSON-LD term semantics, remote contexts, secret material handling,
nonconforming inputs, arbitrary representations and whole conformance remain
unestablished. At that boundary production.1/.2, json-ld-processors.2 and consumption.1 remained NOT_RUN: their composite
rules need broader type and input evidence. No generic case/verdict, subject
validator or post-consumption getter provides the producer's expected input.

Five additional requirements passed. After that addition DID 1.1 had 138 cases, 117 requirement and
two recommendation passes, one alg recommendation failure, two inapplicable
statements and 364 NOT_RUN (317 requirements and 47 recommendations). The 416
historical entries remain as 364 pending and 52 observed (50 PASS, one
NOT_APPLICABLE and one FAIL). Core 1.0 and projection results remain separate
and unchanged. Source/history/authority and existing implementation findings
are neither repaired nor closed by this observation expansion.

## Root placement and direct selected-consumer inputs

Five fresh passive native producer calls independently inspect production.2:
every actual pre-producer data-model and representation-map entry name must
appear in the root JSON object. Additional base context insertion is allowed.
This checks placement only; value conversion is a separate obligation. It does
not infer production.1, json-ld-processors.2 or consumption.1 from equality.
Malformed producer output fails; missing attribution or unusable pre-input is
ERROR with all available original captures retained.

InspectConsumption invokes the exact pinned consumer.New().Consume that SAGE
integration selects, with explicit literal bytes, declared media and default
options. The adapter retains original errors and returned maps; it synthesizes
no resolver codes and supplies no validator verdicts. Seven fresh calls compare
the same context-free, minimal public did:sage document under application/did
(detected DID 1.1) and application/did+json (DID 1.0), then consume valid JSON
array, string, number, boolean and null roots under application/did. Each
non-object root must return an actual error and no document maps. The two media
calls independently establish production-and-consumption.15; the five root
calls establish consumption.3. A DID 1.0 root error cannot earn this DID 1.1
root verdict. Generic cases and prior verdicts are not reused.

These are selected library-actor input observations. They do not establish
SAGE resolver request parsing, registry/key/record validation, production
network ingress, all nonconforming documents, all representations or complete
schema/value-conversion conformance. At that boundary production-and-consumption.18
and the composite production/consumption rules remained NOT_RUN. Arbitrary extension
values and typed DateTime/Double evidence are not supplied by SAGE's current
record projection; their work remains pending rather than passed by inference.

After the root/media addition DID 1.1 had 150 cases, 120 requirement and two recommendation passes, one
alg recommendation failure, two inapplicable statements and 361 NOT_RUN
(314 requirements and 47 recommendations). All 416 historical entries remain
as 361 pending and 55 observed (53 PASS, one NOT_APPLICABLE and one FAIL).
Core 1.0 and projection remain unchanged and separate. Existing implementation
findings, deferred authority/history and planned work order remain intact.

## Paired nonconforming field consumption

Nine fresh paired cases make 18 direct calls to the same pinned consumer.
The accepted public control carries a supported JsonWebKey with the existing
public Ed25519 test material, authentication and a service. Each negative input
changes exactly one field: missing root id, numeric root id, missing method type
or controller, numeric method id or controller, missing service type or endpoint,
and an empty authentication set. All inputs are valid duplicate-free JSON maps,
not malformed transport or attacker reproductions. Service-id optionality
conflicts, arbitrary key classes and secret material are outside this selection.

The inspector independently verifies the named pinned field requirement and
that stripping only that field makes the two source objects equal. Numeric root
id refers to subjects.1, not subjects.3 (canonical authoritative dereferencing).
Fixture descriptors and the public control are fixed. Actual bytes, media,
options, returned maps and errors are retained for both calls. The control must
be accepted and preserved before the negative input's error/no-document result
can earn PASS. An unavailable or unconditionally rejected control is ERROR;
a negative input accepted without an error is FAIL. Returned error annotations
are evidence only, never the source of the expected rule or rejection verdict.

The two newly observed requirements are production-and-consumption.18 and
cid10 conformance.2, bounded to these independently nonconforming inputs.
Acceptance of the paired control is not a claim of full document/key conformance.
These library actor observations do not establish all schema violations,
full conversion rules, cryptographic safety, canonical authority, history,
SAGE resolver/registry validation, network ingress or whole conformance.
At that boundary production.1, json-ld-processors.2 and consumption.1 remained NOT_RUN.

After the paired field addition DID 1.1 had 159 cases, 122 requirement and two recommendation passes, one
alg recommendation failure, two inapplicable statements and 359 NOT_RUN
(312 requirements and 47 recommendations). All 416 historical entries remain
as 359 pending and 57 observed (55 PASS, one NOT_APPLICABLE and one FAIL).
Core 1.0 and projection evidence stay separate and unchanged. Existing findings
and the deferred implementation work remain open.

## Actual typed JSON production table

InspectTypedProduction constructs an explicit public document using typed model
constructors, not a subject consumer or validator output. Before invoking the
same pinned producer selected by SAGE integration, it captures actual extension
and representation-entry model kinds and original values, controller order and
set shape, separate pre-call maps, options, bytes and errors. Input construction
errors are distinct from producer rejection and establish no production-and-consumption.12
verdict. Actual type witnesses must match the reviewed complete fixture.

Two fresh library-actor cases select JSON and JSON-LD production. Each explicitly
covers all nine rows of the pinned production table: map, list, ordered set,
datetime, string, integer, double, boolean and null. The independent expected
conversion uses Unicode/escape/newline strings, safe integers, doubles 1.5 and
2, nested maps/lists, an ordered controller set and two datetimes with opposite
offsets and fractional seconds. Pre-input retains original datetime precision;
output must be UTC without subsecond precision. An integral double must retain a
decimal fraction, so 2 and 2e0 do not pass for 2.0. Number spelling is checked
separately from numerical JSON equality. Representation-map fields must also
survive, and JSON-LD selection must add the DID 1.1 base context.

The actual producer is never used to generate expected output, and a
post-consumption getter cannot stand in for the typed input. Incomplete fixture,
missing type attribution, builder failure or capture errors are ERROR. Actual
producer failure, missing entries, reordered lists/sets or incorrect conversions
are FAIL. Unit-only controls cover every represented row and guard these
boundaries. The selected finite fixture values do not establish all numeric or
Unicode ranges, contextual property conversions, canonical authority, history,
SAGE resolver/ingress or full JSON-LD term processing and remote contexts.

production.1 and json-ld-processors.2 now pass on these directly observed typed
inputs, with the same table and scope limits for both. At that boundary consumption.1 still needed
actual typed consumer evidence, and production-and-consumption.12 remained
unobserved: builder rejection must not be misreported as producer rejection.
After the typed producer addition DID 1.1 had 161 cases, 124 requirement and two recommendation passes, one
alg recommendation failure, two inapplicable statements and 357 NOT_RUN
(310 requirements and 47 recommendations). Historical entries remain as 357
pending and 59 observed (57 PASS, one NOT_APPLICABLE and one FAIL). Core 1.0,
projection and existing implementation findings remain separate and unchanged.

## Actual returned typed JSON consumption values

InspectTypedConsumption passes literal public JSON to the unchanged pinned
consumer selected by SAGE integration. It archives the actual call inputs,
options, errors, detected version and returned maps, then observes the returned
document through typed extension, representation, controller and method
accessors. It does not build an expected document with a subject producer or
use subject validator annotations as its oracle.

Two actual inputs differ in root object member order. Each covers the nine
consumption table rows with a nested/empty map, ordered list and controller set,
known expires/revoked datetime entries, strings with Unicode/escapes/newlines,
selected safe integers, doubles 1.5 and 2.0, booleans and null. Unknown
date-looking strings must stay strings; known datetime fields must retain the
same instant and nanosecond fraction. Map member insertion order is not
required, while list/set order is. Typed number kinds are checked separately
from JSON numerical equality, so an integral double becoming an Integer fails.

Only the reviewed complete literal fixtures are eligible. Missing attribution,
changed input/options or capture errors are ERROR. Consumer rejection, wrong
detected information, lost entries or incorrect typed values are FAIL. Unit
controls cover these boundaries and every selected type without executable
attack reproduction. Actual returned fields are compared to independent typed
expectations and separately to the full returned maps.

consumption.1 now passes on these selected JSON inputs. This does not establish
forced double property conversion without a fractional input, every numeric
range or property context, JSON-LD terms/remote contexts, operational authority,
SAGE resolver/ingress, or whole document/key conformance. The method timestamps
are data-model conversion evidence, not operational expiration/revocation or
historical truth. At that earlier boundary production-and-consumption.12 remained NOT_RUN; builder
rejection is not producer rejection.

After the typed consumer addition DID 1.1 had 163 cases, 125 requirement and two recommendation passes, one
alg recommendation failure, two inapplicable statements and 356 NOT_RUN
(309 requirements and 47 recommendations). Historical entries remain as 356
pending and 60 observed (58 PASS, one NOT_APPLICABLE and one FAIL). Core 1.0,
projection and existing implementation findings remain separate and unchanged.

## Actual representation input contracts

Four fresh calls reuse the explicit typed production and consumption operations
to inspect production-and-consumption.8 and .13. They do not copy verdicts from
earlier report cases. For the producer, actual typed input witnesses and the
separate pre-call document and representation maps must match independently
defined complete input fixtures. Both JSON and JSON-LD options are observed.
Missing call attribution, builder/capture failure or malformed map captures are
ERROR; mismatched document or representation witnesses are also ERROR because
the inspected call input cannot be attributed reliably to the reviewed fixture.

For the consumer, the archived literal bytes and declared media string must
match the complete reviewed public input and actual call with default options.
The two inputs differ in object member order. A missing operation or changed
bytes, media or options is ERROR rather than evidence for another call.

The observations judge only the supplied inputs. Downstream output, detection,
returned models and delegated errors remain archived but do not decide these
input contracts. Unit controls verify that output failure cannot silently
become an input failure or imply output success. Full output/rejection behavior,
all representations, authority, resolver ingress and JSON-LD processing remain
unestablished by these observations. At that earlier boundary production-and-consumption.12 remained
NOT_RUN: builder rejection is not producer rejection. Recognized timestamp
conversion alone proves no operational expiration/revocation non-use policy.

After the representation-input addition DID 1.1 had 167 cases, 127 requirement and two recommendation passes, one
alg recommendation failure, two inapplicable statements and 354 NOT_RUN
(307 requirements and 47 recommendations). The 416 original rows remain as
354 pending and 62 observed (60 PASS, one NOT_APPLICABLE and one FAIL), with all
original fields, baseline and routes preserved. Core 1.0, projection and existing
implementation findings remain separate and unchanged.

## Actual producer prevention of selected invalid context output

Three fresh pairs supply the same minimal public typed model and change only
one representation-specific @context value. The accepted control uses the DID
1.1 base string; negative values are Boolean false, Integer 42 and a list with
the base string followed by false. Scalar forms violate the required context
shape; the Boolean list suffix is excluded by json-ld-processors.1 and the
pinned context type definition, not by json-ld-processors.4 alone.

Each pair makes two actual calls to the unchanged selected producer. Typed
pre-input witnesses, both maps, options, bytes and errors are archived. A builder
rejection cannot pass, and an always-rejecting producer fails to establish the
accepted control. Subject validator verdicts and error annotations are never
used to decide the independently defined context condition.

The narrow prohibition can pass when the actual producer refuses with no
output or successfully returns an independently checked repaired minimal
document with the base context string or a base-only array. A valid repair is
not failed merely because the producer did not reject. Error plus partial bytes
and silent no-output are ERROR; no new rule requiring all errors to return no
bytes is imposed. Successful known invalid JSON/root/context is FAIL. Other
media, richer context semantics or a different document are NOT_SUPPORTED.

production-and-consumption.12 now passes only on these selected context output
conditions. It does not establish all invalid DID/document rejection, every
schema, JSON-LD processing, remote contexts, authority, resolver ingress,
downstream publication, or operational expiration/revocation non-use policy.
At that previous boundary DID 1.1 had 170 cases, 128 requirement and two recommendation passes, one
alg recommendation failure, two inapplicable statements and 353 NOT_RUN
(306 requirements and 47 recommendations). All 416 original rows remain as
353 pending and 63 observed (61 PASS, one NOT_APPLICABLE and one FAIL), with
original fields, baseline and routes preserved. Core 1.0 and projection remain
separate; existing implementation findings remain unchanged.

## Batched selected library actors

The complete [audit of 353 remaining clauses](sage-resolution-batch-review.md) supplies per-id actor/precondition/proof requirements and no verdict. The new batch adds 45 cases and fresh observations for 61 of those clauses. Core 1.0 remains unchanged. DID 1.1 now has 215 cases, 185 requirement and five recommendation passes, two recommendation failures, two inapplicable statements and 292 NOT_RUN (249 requirements, 43 recommendations). Full standard conformity remains NOT_ESTABLISHED.

Parser evidence calls the pinned Parse/ParseURL/ParseReference and DIDURL.Resolve operations against literal ABNF and RFC3986 controls. These are selected shared-library actors, not SAGE method policy or resolver invalid-string ingress. Multikey evidence selects actual codec rows by name/role, records their returned metadata, and separately calls encode and decode with independent literal prefixes, lengths and base58-btc strings. Published public point vectors satisfy compressed-point input preconditions; public scalar/seed test bytes exercise secret-row encoding without signing or operational custody. Equivalent-output permissions support only external encoding contracts, not every internal arithmetic step. Conflicting BLS secret clauses .20/.21 remain pending.

Actual universal.Client makes all sixteen GET/POST, resolve/dereference, full/direct and option/no-option requests. A passive RoundTripper reads GetBody copies; an actual universal handler delegates through passive function wrappers to the unchanged SAGE resolver. Endpoint, request bytes, exact native input/options/result and consumer calls are separate evidence. Options are captured before delegation and capture failures are retained. Two controlled full-result replies differ only in declared document media type and cause actual 1.1/1.0 consumption; these replies are explicitly not SAGE server output and have no native resolver invocation. Owned TLS does not establish production trust or mutual authentication.

Relying-party evidence uses the actual SAGE dereferencer and an explicit fixture clock of 1800000000. It preserves primary URL/options, document getters, selected method and actual errors.As problem objects serialized unchanged. Typed zero is passed to the actual native relying party; adapter parser failures cannot earn invalid-input PASS. Unauthorized purpose and absent method are ordinary owned-fixture unit/runtime scenarios. Mandatory refusal, CID type vocabulary and human title/detail recommendations are judged separately. Mixed MUST-raise/SHOULD-type clauses cover mandatory refusal and archive their advisory type diagnostically. Unreviewed nonempty prose is NOT_SUPPORTED rather than automatically invalid. No recursive-map walk, forged id/controller branch, authority or cryptographic-use proof is implied.

Six direct consumer pairs validate present JWK/Multikey type, public Multibase, alsoKnownAs URI set and nonempty capability relationships. Each accepted property is preserved; the paired negative changes only one independently validated field. They do not establish support for those fields in current SAGE registry records or turn optional absence into PASS.

The independent context oracle was fetched from [W3C's explicit v1.1rc1 file](https://www.w3.org/ns/did-vocab/v1.1rc1.jsonld); its exact SHA256 is the pinned publication's ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85. The ambiguous /ns/did/v1.1 URL returned a Multiple Choices page during preparation; that page is not used as an oracle. Actual local BaseContext API bytes/URL are checked against the frozen file. This verifies local cached availability/integrity, not consumer network wiring or full JSON-LD expansion/RDF. The frozen context independently has neither inspectionNote nor @vocab. The selected default consumer drops that root term; the default producer returns it and therefore records the new recommendation FAIL. Strict producer options are not silently enabled.

The historical inventory keeps all 416 ids, baseline fields and previous observations unchanged in meaning. Cases lacking actual evidence remain NOT_RUN. New library/fixture operations do not establish canonical storage, legitimate controllers, Update history, W3C registration or missing SAGE contract/service branches. These stay in the existing follow-up plan.

### Pinned source arithmetic

The DID1.1 resolution scope also inspects the fixed module source for the CID integer-arithmetic obligations. It binds independently read cache files to the full canonical module ZIP using the pinned Go h1 sum and nominal build dependency identity, then uses the standard Go parser/type checker for public call paths and selected algorithm closures. The artifact retains source bytes, typed operations, reviewed boundaries and unknown paths. It is source inspection, not compiled-byte attestation or proof of all executions. See [the grouped review](sage-remaining-clause-review.md#fixed-source-integer-arithmetic-inspection) for the exact limits.

The source observer requires an installed Go 1.26.8 toolchain including its standard-library source tree. For a binary built with `-trimpath`, explicitly provide `GOROOT` from that toolchain (`GOROOT="$(go env GOROOT)" did-inspector-sage ...`). CI and the native CLI test use this same execution environment. Missing standard source produces ERROR; it never substitutes a stub or infers PASS.

### Selected service routing roles

Four additional typed source-role clauses are now observed, corroborated by seven fresh ordinary URI-list/service calls. See [the scope and preserved limits](sage-remaining-clause-review.md#selected-service-routing-source-roles). Current DID1.1 resolution is 359 cases, 355 PASS, ten FAIL, four NOT_APPLICABLE and 117 NOT_RUN. Core1.0 and separate projection are unchanged; the failing conformance gate and planned core fixes remain. All 416 historical ids and baseline bytes are preserved.

### Selected service list and media branches

Four more source-role clauses are observed through twelve ordinary public literal calls and separately preserved original resolved documents/metadata. See [the bounded scope](sage-remaining-clause-review.md#selected-service-list-and-exact-media-branches). Current resolution is 360 cases, 359 PASS, ten FAIL, four NOT_APPLICABLE and 113 NOT_RUN. Existing findings remain for the approved core repair work; the original416 ids, baseline, subject pins and separate Core1.0/projection results are preserved.

### Resolved document and dispatch conditions

Three further internal clauses are observed through thirteen ordinary actual calls and separately bound typed source roles. See [the limited scope and remaining prerequisites](sage-remaining-clause-review.md#selected-resolved-document-and-dispatch-conditions). Current resolution is 361 cases, 362 PASS, ten FAIL, four NOT_APPLICABLE and110 NOT_RUN. Original416 ids, baseline bytes, existing findings, pins and separate Core1.0/projection results remain unchanged. Resource .11 adjusted URL is still pending; arbitrary rejected queries do not establish fallback behavior.


## Relative URL expansion guard and extension traversal

Two internal predicates are judged separately. `resolving-algorithm.27` passes the actual typed `expandRelativeUrls` guard. `resolving-algorithm.28` fails complete collection traversal: the same actual consumer preserves five relative `id` values in top-level method, embedded method and service extension maps, but the resolver leaves them relative. Moving identical maps to the document root expands them. Five ordinary literal documents cover absent, false and true options, relocated maps and valid empty collections; no external endpoint is fetched.

A separate nine-package, 39-file cache/ZIP capture binds the pinned resolver, its actual consumer-local document and helper chain. The inspector recomputes typed roles and guard semantics; 315 reviewed function contexts are premises, not a substitute for the independent operand and runtime checks. Bare `Extra` reads or unreviewed equivalent guards cannot manufacture PASS. Altered source controls are parsed/type-checked only and never executed. Pre-expansion consumption and post-expansion model/wire values remain distinct; the producer context is checked separately. This is not full RFC3986, representation conformance (.26), every-item processing (.29), JSON-LD, operational authority or physical tracing.

Current resolution: 362 cases, 363 PASS, eleven FAIL, four NOT_APPLICABLE, 108 NOT_RUN, zero ERROR. Original 416 ledger: 308 observed (294 PASS, eleven FAIL, three NOT_APPLICABLE) plus 108 pending. The 246 anchor has 138 execution verdicts (131 PASS, five FAIL, two NOT_APPLICABLE) plus 108 pending. Remaining classification: internal15, document actor51, choices12, registration15, operational/history10, interpretation4 and complete tuple1.

The new complete-expansion traversal failure is an additional stage-eight repair cause, separate from the earlier fragment-search omission: eleven failed clauses now map to eight repair causes. Earlier ten findings/seven causes, pins, original ledger ids, frozen text, Core1.0/projection results and old 38-file source captures are preserved. Core/spec changes remain deferred. Missing compiler source makes all 47 source-bound clauses ERROR; the other 317 PASS and earlier ten FAIL remain independently observable.


## Primary-resource URL and relying-party fragment extraction

Two URL predicates have separate evidence and verdicts. Resource .11 fails because an explicit passive ResourceHandler receives the original fragment-bearing URL after resolution, rather than the independently specified fragment-free primary URL. The observer records the same document/options and always returns unhandled; it does not provide a resource. The final NOT_FOUND is a diagnostic prerequisite, not the failure oracle. Seven ordinary routing calls include absent/present/empty/percent fragments, path/query combinations and a document branch that does not invoke the handler.

CID retrieve .3 passes the selected DID parser plus typed relying-party integration. The actual parser result is captured without changing the reference passed to VerificationMethod. Typed parser fragment storage and the same reference through checkRef/SelectMethod/findMethod's Fragment accessor are bound independently. Seven public did:sage references include two positive method/relationship selections and five parser diagnostics. Empty, percent and query-related downstream refusal/output changes do not change this extraction predicate. A handler evidence error cannot erase a valid extraction verdict, and an RP evidence error cannot erase an independently established URL-separation failure.

A separate 39-file, nine-package source capture includes relyingparty and preserves all earlier 38-file and resolver-expansion captures. The inspector recomputes two typed predicates under 337 reviewed function contexts and ten call edges. Known wrong extraction separator/offset or URL operand is judged independently; unsupported expressions and missing binding/context are evidence ERROR. Modified source controls are parsed/type-checked only and never executed. This is not all URL grammar, non-DID schemes, media-specific fragment semantics (.fragment.3), full representation/JSON-LD, authority or physical tracing.

Current resolution: 363 cases, 364 PASS, twelve FAIL, four NOT_APPLICABLE, 106 NOT_RUN, zero ERROR. Original 416 ledger: 310 observed (295 PASS, twelve FAIL, three NOT_APPLICABLE) plus 106 pending. The 246 anchor has 140 execution verdicts (132 PASS, six FAIL, two NOT_APPLICABLE) plus 106 pending. Remaining classification: internal13, document actor51, choices12, registration15, operational/history10, interpretation4 and complete tuple1.

The new primary-resource URL separation failure is an additional stage-eight repair cause, separate from fragment search and relative URL expansion. Twelve failed clauses now map to nine repair causes. Earlier eleven findings/eight causes, pins, frozen text, old ledger row content/order and Core1.0/projection results remain preserved. Missing compiler source yields exactly49 ERROR while317 PASS and the ten failures independent of source remain observable; the two source-bound failures also become ERROR. Core/spec/contract changes and registration remain in the approved later order.


## Qualifying expansion items and direct multihash component operations

Resolving .29 now has its own five literal object/id/relative-fragment conditions and unchanged actual outputs, under the same preserved consumer/resolver and closed-helper premises. It fails for the existing method/service extension traversal omission. The old .28 verdict is not copied: each candidate is independently qualified and compared. Root-relocated, disabled and empty controls remain present. The additional failed clause shares repair cause eight; it does not create a new repair cause. Full representation .26 and media-fragment .3 remain unobserved.

CID multihash .2/.3 pass for the original pinned internal component, directly invoked through the Inspector-owned `adapters/sageprobe` module. Its import path `github.com/sage-x-project/did-go/inspectorprobe` permits ordinary Go internal-package imports; the local replacement applies only to Inspector observer code. Root did-go and advanced/sage pins remain unchanged and unreplaced. Runtime BuildInfo records this observer separately from the subject's module/ZIP/cache/compiler premises. CI preserves its module descriptor and source hashes. This is neither a SAGE production caller nor an assertion of verbatim compiled subject bytes.

Thirty-two actual calls contain four encode successes, four decode successes, twenty independent length rejections and four diagnostic inputs. Eight rejection inputs keep declared and actual lengths equal while differing from the algorithm's expected length. A decoder checking only declared versus actual length therefore cannot pass. Unknown codes and invalid encode inputs are diagnostics, not additional implementation obligations. Partial values returned alongside rejection errors are retained; diagnostic outcomes do not judge the clauses. Encode/decode API or capture errors are attributed separately.

Current resolution: 365 cases, 366 PASS, thirteen FAIL, four NOT_APPLICABLE, 103 NOT_RUN, zero ERROR. Required436:352 PASS/nine FAIL/two NA/73 NOT_RUN; recommended50:14 PASS/four FAIL/two NA/30 NOT_RUN. Original416 ledger:313 observed (297 PASS/thirteen FAIL/three NA)+103 pending. Anchor246:143 execution verdicts (134 PASS/seven FAIL/two NA)+103 pending. Remaining: internal10, document actor51, choices12, registration15, operational/history10, interpretation4, complete tuple1. Existing310 observed rows and other243 anchor rows, baseline ids/text/hashes, earlier findings and Core1.0/projection results are preserved.

Thirteen failed clauses map to the same nine repair causes; .29 is added under the existing expansion traversal cause. Core/spec/contract repair, real registry bindings and registration remain in the approved later order. Missing standard-library source yields50 ERROR,319 PASS and the existing ten failures independent of that proof; the three source-bound expansion/URL findings become ERROR. The direct compiled multihash component calls remain independently observable in that condition.


## Actual returned minimal Core 1.0 representation

Resolving algorithm .26 is now checked on two actual root Resolve calls with compact and whitespace-varied id-only input. The literal driver returns application/did, consumed as V1.1; an explicit application/did+json Accept causes the same call to produce V1.0 JSON. Passive producer capture is opt-in for these calls only. Its original input maps, options, output bytes and media are linked to the final Resolve Raw and contentType. A separately converted document never substitutes for the actual return.

The independent oracle enumerates the complete selected minimal class: strict JSON object, one string id with DID syntax and the expected same-call identity, no representation-specific entries or optional properties. Missing/misattributed captures are ERROR. An attributed malformed JSON/root/id is FAIL. Other valid additional-member classes, duplicate-member ambiguity or other representations are unsupported, not normative failures. This does not establish full SAGE documents, JSON-LD/RDF, every output class, the pending metadata tuple placement, registry authority or verbatim compiled bytes. The root source module, nine cache files and their full pinned ZIP/h1 are separately bound without changing any pin.

Current resolution:366 cases,367 PASS,13 FAIL,4 NOT_APPLICABLE,102 NOT_RUN,zero ERROR. Required436:353 PASS/9 FAIL/2 NA/72 NOT_RUN; recommended50:14 PASS/4 FAIL/2 NA/30 NOT_RUN. Original416 ledger:314 observed(298 PASS/13 FAIL/3 NA)+102 pending. Anchor246:144 execution(135 PASS/7 FAIL/2 NA)+102 pending. Earlier313 observed rows and other245 anchor rows retain content and order. Remaining: internal9,document actor51,choices12,registration15,operational/history10,interpretation4,complete tuple1. Thirteen failed clauses still map to nine repair causes; repairs remain in the approved later order. Fragment .3, JSON-LD/RDF and original normative conflicts remain unobserved. Missing standard-library source still yields50 ERROR and10 FAIL, with320 PASS including this external output check.


## Remaining internal evidence boundaries

All nine previously pending internal clauses were reviewed together. Four now have selected actual observations: u/64 encode and decode allocation, no-context production injection, and plain-JSON fragment selection. The [nine-row boundary ledger](sage-internal-evidence-boundaries.json) retains exact text/hash/actor, observed case or concrete missing premise for every row. Review completion is not nine execution passes.

The original internal Multibase u component is called directly from the Inspector-owned observer module. Typed source proves the actual unique ASCII64 selector, same Base arguments, prefix-adjusted size and zero-initialized integer buffer. In this power-of-two branch the logarithm ratios equal 8/6 and 6/8 exactly. Stable input, successful allocation and at most4096 bytes/characters bound integer arithmetic on both supported architectures. Other formulas or contexts are unknown, never failed merely for using a valid alternative. RFC4648 helpers and the public Multikey z actor do not substitute for this actor. Eighteen small independently fixed positional-conversion calls corroborate reachability, not complete algorithm equivalence.

The actual selected V1.1 producer receives no context in its pre-call entries and adds the DID1.1 context to its same-call output. Independently downloaded context bytes have the full CID publication digest ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85. Only that no-context trigger is established. Invalid empty/Boolean/number contexts fail the independent output predicate; other valid unreviewed declarations are unsupported. Already-resolved CID URL routing, partial/remote contexts, full JSON-LD1.1 and RDF are not inferred.

Plain-JSON fragment input is explicitly opt-in, actually read/consumed as application/did+json V1.0; changing only Accept is insufficient. Frozen Core1.0 E.1 and its Fragment section provide the selected absolute-id meaning. Typed source connects the same document/reference, pre-authorization candidate and returned method. A unique public JsonWebKey and ordinary no-match control use original library calls. Downstream authorization failures do not themselves fail the intermediate selection step. Old routing requests retain their behavior and fields.

Five internal rows remain NOT_RUN with concrete closure conditions: encode.13 and decode.16 retain frozen prose/example conflicts; CID already-resolved-context and RDF-vocabulary clauses plus DID JSON-LD processing precondition still need an applicable standard processing actor and independent semantic evidence. Missing functionality is not blanket NA/NS and unrelated helper success cannot supply PASS. These items are retained in the original order; no core, contract, subject pin or frozen specification repair is included.

Current resolution:369 cases,371 PASS,13 FAIL,4 NOT_APPLICABLE,98 NOT_RUN,zero ERROR. Required436:357 PASS/9 FAIL/2 NA/68 NOT_RUN; recommended50:14 PASS/4 FAIL/2 NA/30 NOT_RUN. Original416 ledger:318 observed(302 PASS/13 FAIL/3 NA)+98 pending. Anchor246:148 execution(139 PASS/7 FAIL/2 NA)+98 pending. Earlier314 observed rows and other242 anchor rows retain content/order; all original ids/text/hashes/baseline and thirteen findings/nine repair causes are preserved. Remaining: internal5,document actor51,choices12,registration15,operational/history10,interpretation4,complete tuple1.
