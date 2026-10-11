# did-inspector

A conformance inspector for implementations of W3C Decentralized Identifiers.
It checks an implementation against the pinned text of DID Core 1.0, DID 1.1,
Controlled Identifiers 1.0 and DID Resolution, with DID 1.0 and DID 1.1
inspected as separate profiles, and is built so that later DID versions can be
added as new profiles. The design is in [`docs/design.md`](docs/design.md).

## Inspecting did-go

The adapter for [did-go](https://github.com/SAGE-X-project/did-go) is the
separate Go module `adapters/didgo`, so the inspector core builds without
did-go. Its `go.mod` pins the did-go revision under inspection and keeps
`replace github.com/sage-x-project/did-inspector => ../..`, so the adapter
always builds against the inspector core of the same checkout; the adapter
is not meant to be consumed from another repository. To inspect another
did-go revision, change the pin with `go get github.com/sage-x-project/did-go@<revision>`
inside `adapters/didgo`.

```sh
cd adapters/didgo
go run ./cmd/did-inspector-didgo --profile did-core-1.0 --out report.json
go run ./cmd/did-inspector-didgo --profile did-1.1 --out report.json
```

`--deterministic` leaves the run times out of the report, so that runs of the
same revisions give the same bytes. The reports for the pinned revision are in
[`docs/evidence`](docs/evidence); CI regenerates them, uploads them as
artifacts and fails when a statement is FAIL or ERROR.

Licensed under the Apache License, Version 2.0 (see `LICENSE`).
