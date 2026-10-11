# did-inspector

A conformance inspector for implementations of W3C Decentralized Identifiers.
It checks an implementation against the pinned text of DID Core 1.0, DID 1.1,
Controlled Identifiers 1.0 and DID Resolution, with DID 1.0 and DID 1.1
inspected as separate profiles, and is built so that later DID versions can be
added as new profiles. The design is in [`docs/design.md`](docs/design.md).

Licensed under the Apache License, Version 2.0 (see `LICENSE`).
