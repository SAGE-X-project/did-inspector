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
| DID Core 1.0 | 11 | 20 | 0 | 186 |
| DID 1.1 with CID and Resolution publications | 47 | 43 | 2 | 441 |

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

Native document snapshots explicitly archive the actual identifier through its
accessor. They do not archive the complete native document data model. Native
verification methods preserve their typed public fields with identifier strings;
that encoding is not advertised as a standard DID representation. Native resolve
representation bytes and HTTP request/response bytes are preserved separately.
The ordinary report omits PASS details; `--raw-out` retains all inputs and these
observations. Raw HTTP records include ephemeral loopback URLs, so the raw file
is not byte-deterministic even when report timestamps are omitted.

A PASS is limited to each observed clause and fixture. Native identifier and
presence checks do not establish full document equality. HTTP complete-result
checks cover structure and returned identity/deactivation, not equality of all
members with a separate native resolution call. Full method-specific algorithms,
other optional extensions, caching, historical resolution, remote contexts, endpoint
operation and operational Source authority remain unestablished; publication
statements without a case remain NOT_RUN. Generic fixture-method conformance is
not advertised by this subject. These cases do not certify full conformance or
protected deployment.

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
full-document comparison and the other evidence limits above still apply.

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
invented, and their unexercised statements remain NOT_RUN. Full native document
comparison, all-member HTTP/native equivalence, optional metadata extensions and
operational authority retain the evidence limits above.
