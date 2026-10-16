# Selected capabilities and remaining evidence boundaries

This review covers 22 clauses in the existing evidence-contract order: twelve optional/construction clauses, four frozen-text interpretations, five internal observations, and one dependent complete tuple. Review completion is not execution completion. Three clauses now have fresh downstream Client observations; nineteen remain NOT_RUN. No new authority, deployment, registry history, Update operation or standard interpretation is assumed.

Two grouped cases use five actual original Client calls to owned loopback TLS. The upstream is an explicit controlled public fixture, not SAGE server output. The history case requests old version 7, latest version 8 and an old-version omission control. It judges nextUpdate and nextVersionId separately. Missing optional fields in diagnostic controls are not mandatory failures. This is downstream conditional-metadata handling, not evidence of actual historical Updates.

The proxy case uses the same minimal DID 1.1 context document, once with no upstream contentType and once with explicit application/did. Actual default consumption receives application/json in the first branch; the original Client adds application/did from the observed DID 1.1 representation. Input/output maps and options are archived. This tests the downstream addition permission, not JSON-LD expansion, RDF, complete proxy preservation or trust. The separate known proxy-preservation failure remains unchanged.

Missing/misattributed captures yield ERROR. Actual original rejection/loss of a selected optional capability yields NOT_SUPPORTED only for that branch, not a mandatory violation. Unit mutation controls check attribution, wire options, bytes, media, returned versions and independent field outcomes. CI independently checks raw evidence and every reviewed boundary against pinned statement hashes and live verdicts.

## Clause contracts

### cid10#Multikey.20

Group: interpretation; current verdict: NOT_RUN.

Frozen BLS secret G2 row conflicts on varint prefix and public/secret payload description.

Completion condition: Resolve the exact frozen publication interpretation before selecting a codec oracle; retain 0x8030 prose versus independent 0x130a varint 0x8a26 and payload ambiguity. No inferred repair in the inspector.

### cid10#Multikey.21

Group: interpretation; current verdict: NOT_RUN.

Final base58 length depends on the unresolved preceding G2 row.

Completion condition: Resolve Multikey.20 and independently establish the selected complete payload/prefix/length oracle before judging the resulting encoding.

### cid10#base-decode.16

Group: internal; current verdict: NOT_RUN.

Frozen destination offset zeroes+1 differs from Example 19 and original append placement.

Completion condition: Obtain authoritative interpretation or a separately approved complete equivalent-output contract; final size and prefix checks do not establish copy placement.

### cid10#base-encode.13

Group: internal; current verdict: NOT_RUN.

Frozen nonzero loop differs from zero-skipping intent, Example 18 and original source.

Completion condition: Obtain authoritative interpretation or a separately approved complete equivalent-output contract over the selected domain; isolated source branches, prefix and length observations are insufficient.

### cid10#conformance.1

Group: optional; current verdict: NOT_RUN.

Normative keyword interpretation definition, not a runtime operation.

Completion condition: Keep frozen uppercase BCP14 interpretation and inspect actual obligations separately; no subject PASS from catalog validation.

### cid10#json-ld-context.1

Group: internal; current verdict: NOT_RUN.

Limited term lookup and matching DID context hashes do not establish CID context routing during JSON-LD processing.

Completion condition: Identify an applicable actual JSON-LD processor and original loader with independently pinned CID context bytes, lookup routing and no-fetch evidence. Do not replace its loader to assert subject support.

### cid10#multibase-0.1

Group: optional; current verdict: NOT_RUN.

No actual original component observation for a selected encoding beyond both normative z and u.

Completion condition: Select an independently defined additional encoding with valid public literals and z/u controls, then observe the unmodified original component. Adapter refusal or existing u64 support cannot close this permission.

### cid10#multihash.1

Group: optional; current verdict: NOT_RUN.

No actual original component observation for a selected additional hash encoding.

Completion condition: Select an independent additional code and digest length, capture original component encoding/decoding and rejection diagnostics with normative-code controls. Do not infer support from wrapper guards or claim hash computation.

### cid10#services.5

Group: interpretation; current verdict: NOT_RUN.

Frozen service id OPTIONAL conflicts with the same publication service property contract.

Completion condition: Resolve the exact frozen publication interpretation. Diagnostic acceptance of id absence cannot choose a normative rule or replace it with Core 1.0.

### cid10#vocabulary.1

Group: internal; current verdict: NOT_RUN.

JSON names and term lookup do not establish RDF predicate IRIs.

Completion condition: Establish processing applicability or observe the actual selected RDF dataset with independently fixed security vocabulary IRIs; engine absence alone is not blanket NA.

### did11-cr20260305#conformance.1

Group: optional; current verdict: NOT_RUN.

Normative keyword interpretation definition, not a runtime operation.

Completion condition: Keep frozen uppercase BCP14 interpretation and inspect actual obligations separately; no subject PASS from catalog validation.

### did11-cr20260305#json-ld-processors.1

Group: internal; current verdict: NOT_RUN.

Context shape, term grammar and local injection do not establish JSON-LD 1.1 processing rules.

Completion condition: Identify actual processing mode/entry point and an independently complete selected context-class oracle with safe positive/negative observations; preserve this pending boundary until then.

### res10-crd20261001#conformance.1

Group: optional; current verdict: NOT_RUN.

Normative keyword interpretation definition, not a runtime operation.

Completion condition: Keep frozen uppercase BCP14 interpretation and inspect actual obligations separately; no subject PASS from catalog validation.

### res10-crd20261001#dereferencing-algorithm-resource.48

Group: optional; current verdict: NOT_RUN.

No selected application-specific client handler is exercised by this batch.

Completion condition: Bind actual original dispatcher calls, URL/options, resolved document, explicit controlled application callback and final resource with absent/false controls. A fixture callback is not SAGE method path support.

### res10-crd20261001#did-document-metadata.12

Group: optional; current verdict: PASS.

Actual downstream Client preserves nextVersionId for a controlled older version 7 with declared latest version 8. Latest and older-without-next-field controls are diagnostic. No method authority or actual Update operation is established.

Completion condition: Retain actual downstream call attribution and controlled upstream condition; do not generalize this selected capability to registry history, authority or complete proxy preservation.

### res10-crd20261001#did-document-metadata.18

Group: optional; current verdict: NOT_RUN.

Alias shape or fixture equality does not establish a governing method guarantee.

Completion condition: Require the selected method equivalence contract and independent authority, identity, document and lifecycle evidence. Documentary alias nonselection cannot become runtime guarantee PASS.

### res10-crd20261001#did-document-metadata.8

Group: optional; current verdict: PASS.

Actual downstream Client preserves nextUpdate for a controlled older version 7 with declared latest version 8. Latest and older-without-next-field controls are diagnostic. No actual registry history or Update operation is established.

Completion condition: Retain actual downstream call attribution and controlled upstream condition; do not generalize this selected capability to registry history, authority or complete proxy preservation.

### res10-crd20261001#metadata-structure.5

Group: optional; current verdict: NOT_RUN.

No actual alternate metadata serialization entry point is selected.

Completion condition: Identify an actual original alternate-format serializer and independent format contract with normal inputs and refusal diagnostics. Inspector-generated XML/CBOR is not subject evidence.

### res10-crd20261001#resolver-architectures-proxied.3

Group: optional; current verdict: PASS.

Actual downstream Client adds its own contentType metadata when the controlled upstream omits it, through actual DID 1.1 context consumption. Explicit contentType control is retained; upstream metadata preservation is separately failing and is not repaired or asserted here.

Completion condition: Retain actual downstream call attribution and controlled upstream condition; do not generalize this selected capability to registry history, authority or complete proxy preservation.

### res10-crd20261001#resolving-algorithm.32

Group: tuple; current verdict: NOT_RUN.

Complete tuple contract depends on unresolved contentType placement.

Completion condition: Resolve resolving-algorithm.35, then bind the complete actual document/resolution-metadata/document-metadata tuple to an independent oracle and field-specific controls. Member PASS cannot close the tuple.

### res10-crd20261001#resolving-algorithm.35

Group: interpretation; current verdict: NOT_RUN.

Frozen algorithm places contentType in document metadata, unlike the general resolution metadata contract.

Completion condition: Resolve the selected publication placement contract. Capture both original metadata maps without moving or injecting fields to manufacture PASS.

### res10-crd20261001#versioning.1

Group: optional; current verdict: NOT_RUN.

Controlled version 7/8 replies are not actual document Update operations.

Completion condition: Observe actual authorized Updates and independently bind their document metadata version changes, history and authority. Do not copy downstream metadata preservation PASS.

## Preserved order and findings

The historical 416-clause ledger retains every original identity. Expected runtime: 371 cases, 374 PASS, 13 FAIL, four NOT_APPLICABLE, 95 NOT_RUN and zero ERROR. Requirements: 360 PASS, nine FAIL, two NOT_APPLICABLE, 65 NOT_RUN; recommendations: fourteen PASS, four FAIL, two NOT_APPLICABLE, thirty NOT_RUN. Anchor 246: 151 execution verdicts (142 PASS, seven FAIL, two NOT_APPLICABLE), 95 pending. Remaining runtime evidence is method-document 51, registration 15, authority/history ten, optional nine, internal five, interpretation four and complete tuple one.

The separately scoped author-document report remains 23 PASS, nineteen NOT_APPLICABLE, seven FAIL and two NOT_RUN; it does not execute or close the runtime method-document 51. Thirteen runtime failures still map to nine repair causes deferred to the approved core-repair stage. The seven documentary findings remain separate. Source/module/specification pins and prior internal-boundary contracts are unchanged.
