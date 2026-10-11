# Pinned publications

These are the W3C publications the inspector judges implementations against,
stored byte for byte as published. The inspector extracts its statements from
these bytes (`go generate ./statements`), and its tests fail if any file's
SHA-256 differs from the pin below or if the committed statement files differ
from what the extractor produces.

| Spec key | Publication | Dated URL | File | SHA-256 |
|---|---|---|---|---|
| `core10` | Decentralized Identifiers (DIDs) v1.0, W3C Recommendation 19 July 2022 | <https://www.w3.org/TR/2022/REC-did-core-20220719/> | `did-core-1.0-20220719.html` | `5e44345740d9bfaa852d3b66c57e98c9beb6c5bf6083b0126dd5daac377b9993` |
| `did11-cr20260305` | Decentralized Identifiers (DIDs) v1.1, W3C Candidate Recommendation Snapshot 05 March 2026 | <https://www.w3.org/TR/2026/CR-did-1.1-20260305/> | `did-core-1.1-cr-20260305.html` | `4a48022defe07d37d2decc3ec9027a932dc883b2ad164a5aeaf9256e530bd979` |
| `cid10` | Controlled Identifiers v1.0, W3C Recommendation 15 May 2025 | <https://www.w3.org/TR/2025/REC-cid-1.0-20250515/> | `controlled-identifiers-1.0-20250515.html` | `c5e9befba602b53de46669cf98067123d1901357a425f8bff621796b2ac4ac4a` |
| `res10-crd20261001` | DID Resolution v1.0, W3C Candidate Recommendation Draft 01 October 2026 | <https://www.w3.org/TR/2026/CRD-did-resolution-1.0-20261001/> | `did-resolution-1.0-crd-20261001.html` | `2b194843d37f5b7f01a4f5464f64d672dc4be43dafe5f2f49114c6070819586e` |

The pins are also recorded in `statements/gen/sources.go`. To check a file by
hand:

```sh
shasum -a 256 statements/sources/*.html
```

A new publication (for example a later DID 1.1 snapshot or DID Resolution
draft) is added as a new file with a new spec key; existing files are never
replaced.

## License

These documents are copyright of the World Wide Web Consortium and are
redistributed unmodified under the W3C Software and Document License, as each
document's copyright notice states ("W3C liability, trademark and permissive
document license rules apply"):

- `did-core-1.0-20220719.html`: Copyright © 2022 W3C® (MIT, ERCIM, Keio,
  Beihang). W3C Software and Document Notice and License,
  <https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document>.
- `did-core-1.1-cr-20260305.html`, `controlled-identifiers-1.0-20250515.html`
  and `did-resolution-1.0-crd-20261001.html`: Copyright © 2025 and 2026 World
  Wide Web Consortium. W3C Software and Document License,
  <https://www.w3.org/copyright/software-license-2023/>.

The license permits copying and redistributing the documents, in any medium,
for any purpose, provided that the copyright notice, a link or URL to the
original document, and the license are included. Each file keeps its original
copyright notice, and the dated URLs above link to the originals. The W3C
liability, trademark and document use rules
(<https://www.w3.org/policies/#copyright>) apply. These files are not covered
by the Apache License 2.0 that covers the rest of this repository.
