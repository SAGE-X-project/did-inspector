# did-inspector design

## 1. Purpose

An implementation of Decentralized Identifiers is only interoperable if it does
what the specifications say. did-inspector checks an implementation (the
*subject*) against the pinned text of the W3C specifications and reports, per
normative statement, what it observed. Its first subject is
[`did-go`](https://github.com/SAGE-X-project/did-go); the design admits any
implementation that an adapter can reach.

It inspects DID Core 1.0 and DID 1.1 as separate profiles, so that a subject's
1.0 behavior and 1.1 behavior are judged independently, and it is built so that
a later DID version is added as one more profile.

## 2. Principles

1. **Independent oracle.** The inspector derives its expectations from the
   specification text alone. It extracts normative statements from the pinned
   publication bytes, checks their SHA-256, and implements its own checks. It
   never calls the subject's validators, never reads the subject's requirement
   registry as truth, and never accepts the subject's own verdicts.
2. **No dependency on the subject.** The inspector core does not import any
   subject. Subjects are reached through adapters. The `did-go` adapter is a
   separate Go module with its own `go.mod`, so the core builds without did-go.
3. **Scoped verdicts.** A PASS is recorded only for the subject revision,
   profile, statement and inspector revision that were actually checked. A
   statement with no case is `NOT_RUN`, never PASS. A subject that declares a
   feature unsupported gets `NOT_SUPPORTED`, which is not PASS either.
4. **Every case names its statements** and, where the statement allows, has a
   positive and a negative input.

## 3. Profiles

A profile is one set of pinned publications that a subject is inspected
against.

| Profile | Publications (spec keys) |
|---|---|
| `did-core-1.0` | DID Core 1.0 REC (`core10`); DID Core 1.0 §7 resolution functions |
| `did-1.1` | DID 1.1 CR Snapshot 2026-03-05 (`did11-cr20260305`), Controlled Identifiers 1.0 (`cid10`), DID Resolution v1.0 CRD 2026-10-01 (`res10-crd20261001`) |

The two profiles share no verdicts. A subject that conforms to 1.1 and not to
1.0 gets separate results. Statements that appear word for word in both
publications are still separate statements with separate ids, because each is
judged against the version it belongs to.

**Adding DID 2.0.** A new profile package (`profiles/did20`) with its own
pinned publication, extracted statements, fixtures and cases. The core, the
report format and the adapters do not change, except that an adapter declares
whether its subject supports the new version (§5). If DID 2.0 brings
operations that no capability covers, the capability set gains a new optional
capability, and subjects that lack it get `NOT_SUPPORTED`.

## 4. Statements

`statements/` holds, per spec key, the statements the inspector extracted
itself from the pinned bytes (the same extraction method as did-go's
`tools/xbar/extract_spec.py`, reimplemented here), with each statement's id,
section, text and the SHA-256 of the source file. A test fails when a
statement's source hash does not match the pinned hash, so a silently changed
publication cannot pass.

Each statement carries the inspector's own scope decision:

- `checked`: there is at least one case;
- `not-checkable`: no black-box observation can decide it (for example a
  statement addressed to specification authors), with a reason;
- `pending`: in scope but without a case yet; reported as `NOT_RUN`.

A statement that only recommends (SHOULD, RECOMMENDED) is `not-checkable`: a
subject may deviate from a recommendation with valid reason, and the verdict
set has no level for an unmet recommendation. A statement a case judges only
partly is `checked`, and its reason says which part remains unjudged; the
case says so in each observation's detail.

## 5. Subjects and adapters

The core defines a subject as a set of capabilities. An adapter implements the
ones its subject supports and declares the rest unsupported.

```go
type Subject interface {
    Describe() SubjectInfo                         // name, version, revision
    Supports(profile string, c Capability) bool    // per profile
}

// Capabilities (each an optional interface the adapter may implement):
type DIDParser interface      { ParseDID(s string) (DIDParts, error); ParseDIDURL(s string) (DIDURLParts, error) }
type DocumentProducer interface { Produce(doc DocumentJSON, version string) (data []byte, mediaType string, err error) }
type DocumentConsumer interface { Consume(data []byte, mediaType, requireVersion string, strict bool) (DocumentJSON, ConsumeInfo, error) }
type DocumentValidator interface { Validate(doc DocumentJSON, version string) ([]Finding, error) }
type Resolver interface       { Resolve(ctx context.Context, did string, opts map[string]any) (ResolutionResult, error) }
type Dereferencer interface   { Dereference(ctx context.Context, didURL string, opts map[string]any) (DereferenceResult, error) }
type V10Functions interface   { Resolve10(...); ResolveRepresentation10(...); Dereference10(...) }
type FixtureMethod interface  { LoadFixtureRegistry(r *fixtures.Registry) error }
```

`DocumentJSON` is the inspector's neutral form of a document: an ordered JSON
object, so that the inspector, not the subject, interprets the content. Results
carry the raw bytes and media types the subject produced, so the inspector can
check them itself.

Adapters:

- `adapters/didgo` (separate module): wraps did-go's public packages only.
- `adapters/https` (in the core module): reaches any resolver that exposes the
  DID Resolution HTTPS binding, so non-Go implementations can be inspected.
- Test resolvers that serve fixed fixtures (a `did:example` registry under the
  inspector's control) so that resolution cases do not depend on any network.

### 5.1 The fixture registry (addition)

Resolution and dereferencing cases need a resolver to run against, and the
inspector must not resolve anything itself. Each profile therefore ships a
fixture registry (`profiles/<profile>/testdata/registry.json`): the verifiable
data registry of a fixture DID method named `example`, under the inspector's
control. The format and its reader are in package `fixtures`, which uses the
standard library only and imports nothing of the inspector, so that adapters in
other modules can use it.

```json
{
  "format": "did-inspector-fixture-registry/1",
  "method": "example",
  "entries": {
    "did:example:123": {
      "deactivated": false,
      "fail": "",
      "versions": [
        {"versionId": "1", "validFrom": "2021-01-01T00:00:00Z",
         "mediaType": "application/did",
         "document": {"id": "did:example:123"},
         "documentMetadata": {"created": "2021-01-01T00:00:00Z"}}
      ]
    }
  }
}
```

- A DID of the method that has no entry does not exist (not found).
- `versions` are oldest first; the last one is the current version. Each has
  the stored bytes, either `document` (JSON, kept byte for byte) or `text`
  (anything else, for example malformed bytes), the `mediaType` the method
  stores them under (which may deliberately be wrong), and the DID document
  metadata the method reports. Stored metadata never carries `deactivated`.
- `deactivated: true` means the method reports the DID deactivated; the
  driver still returns the last version, flagged.
- `fail` makes the driver fail with that message instead of returning a
  record: an unexpected failure of the method's Read operation.
- `fixtures.UnsupportedMethod` (`inspectorunsupported`) names a method no
  subject may support; cases use it for METHOD_NOT_SUPPORTED.

The contract for subjects and adapters:

1. A subject that supports resolution cases implements `core.FixtureMethod`
   and declares the capability `fixture-method`. Every resolution and
   dereferencing case calls `LoadFixtureRegistry` with its profile's registry
   before it resolves; a later call replaces the registry. A subject without
   the capability gets `NOT_SUPPORTED` for those cases; a failing load gives
   `ERROR`.
2. After the call, the subject resolves DIDs of method `example` from the
   registry only: the adapter wires the registry into the subject as the
   method driver of `example`, through whatever driver or method plug-in
   interface the subject has. The driver's lookup is `Registry.Read`, so all
   adapters read the registry the same way:
   - the request carries the DID and the `versionId` and `versionTime` the
     resolver received as resolution options or DID parameters; without them
     the current version is returned; `versionTime` selects the most recent
     version whose `validFrom` is at or before it;
   - it returns the stored bytes, media type, metadata and deactivated flag,
     or `ErrNotFound`, `ErrVersionNotFound`, `ErrInvalidVersionTime`,
     `ErrMethodNotSupported` or an `*InjectedError`.
3. The driver does nothing else. Consuming the bytes under the media type,
   checking the document and its id, applying options such as
   `expandRelativeUrls`, building the resolution result and its metadata,
   and every step of DID URL dereferencing are the subject's own work, and
   that is what the cases judge. An adapter maps the driver's errors and flags
   to whatever its subject's driver interface expects (for example a not-found
   error, or deactivation inside the method's metadata) and does not build
   resolution results itself.

The cases' expected results are written separately, from the specification
text, in `testdata/resolution.json` and `testdata/dereferencing.json`.

## 6. Cases

A case is one check of one or more statements under one profile:

```go
type Case struct {
    ID         string     // stable, e.g. "did11/consumer/media-type-decides"
    Profile    string
    Statements []string   // statement ids it judges
    Needs      []Capability
    Run        func(ctx context.Context, s Subject) []Observation
}
```

Inputs come from fixture files (`profiles/<profile>/testdata/`) written from
the specification text: valid and invalid DIDs and DID URLs from the ABNF,
documents for each production and consumption rule, representations with each
media type and `@context` combination, resolution and dereferencing scenarios
with expected results and error types, and HTTPS binding exchanges.

Verdicts per observation: `PASS`, `FAIL` (with expected and observed values),
`NOT_SUPPORTED`, `NOT_APPLICABLE`, `ERROR` (the case itself could not run). A
statement's verdict is the worst of its observations, with `FAIL` > `ERROR` >
`NOT_SUPPORTED` > `PASS`; a statement with no observation is `NOT_RUN`.

## 7. Report

`did-inspector run --profile did-1.1 --subject didgo --out report.json` writes:

- subject name, version and revision; inspector revision; profile; the spec
  keys with the SHA-256 of each pinned source; the run time;
- per statement: verdict, the cases that judged it, and for failures the
  expected and observed values;
- totals per verdict and the list of `NOT_RUN` statements.

A text summary is printed. The report is evidence for that run only; it is not
a certification.

## 8. Layout

```
did-inspector/
├── cmd/did-inspector/      CLI: list profiles and cases, run, compare reports
├── core/                   Subject, capabilities, Case, Observation, verdict rules, runner
├── statements/             extractor, pinned sources' hashes, extracted statements per spec key
├── profiles/
│   ├── core10/             DID Core 1.0 cases and fixtures
│   └── did11/              DID 1.1 + CID 1.0 + DID Resolution cases and fixtures
├── checks/                 the inspector's own spec checks (ABNF, JSON rules, media types, metadata)
├── report/                 report model, JSON and text output
├── adapters/https/         HTTPS binding subject
└── adapters/didgo/         separate module wrapping did-go
```

`checks/` is the inspector's independent implementation of what the
specifications require (for example its own DID ABNF parser), used to judge
the subject's outputs. It is deliberately not shared with did-go.

## 9. Order of work

1. `statements`: extractor, pinned hashes, extracted statements for the four
   publications, scope decisions.
2. `core`, `report`, `checks`, CLI.
3. `profiles/did11` and `profiles/core10` cases, statement by statement.
4. `adapters/didgo`; CI that runs both profiles against a pinned did-go
   revision and stores the reports as artifacts.
5. `adapters/https` and its fixture resolver.

## 10. Limits

- A black-box inspector judges observable behavior. Statements about internal
  processing that leaves no observable trace are `not-checkable`.
- The inspector's own checks can be wrong. They are written from the
  specification text, reviewed against it, and kept separate from did-go so
  that one mistake does not hide in both.
- DID 1.1 and DID Resolution are not Recommendations; a new publication is a
  new spec key and new statements.
