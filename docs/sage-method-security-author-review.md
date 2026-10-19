# Fresh independent method/representation-author semantic review

Decision: COMPLETE for the selected 51-clause fresh documentary review, with **26 PASS, 19 NOT_APPLICABLE, 4 FAIL and 2 NOT_RUN**. This is not an overall-conformance ACCEPT, runtime verdict, or permission to rewrite earlier results. The four remaining documentary failures are listed and reasoned individually below.

## Exact subject and method

Reviewed repository: `SAGE-X-project/sage-spec`.

Final main corpus revision: `6d611b19764cfae50936ab4c63dbe4e1f9f78487`; tree `8715f613048ad76b658d4559824c8c4bbe3b7e9b`. The same 16 files at reviewed PR source `5ff6d97a779d6a8270d20ccfe67e193674f9bce1` are byte-identical. Prior baseline: `06b50e177ccd22bce7d70fd80c2d7f822ae3fd3b`.

I obtained each subject file from the exact local Git blob and compared it both with the saved main-corpus file and with the baseline. Fifteen files are byte-identical. Only chapter06 changes: 134 inserted lines, sections6.1–6.4, growing from 6560 to 21944 bytes. Removing that exact inserted byte span restores the baseline chapter exactly. No authentication/fork binding proposal is among the normative corpus files. Source identity is independent of the user's dirty design checkout.

The old review artifact was used to identify the canonical 51 statement IDs/text digests and the original 16-file inventory. Its verdict/review-basis fields were not used as the semantic oracle. I compared every selected text with its canonical statement JSON, independently hashed its UTF-8 text, and checked the three frozen source HTML hashes. I read their relevant surrounding sections (especially author versus producer/consumer/issuer duties, conditional representation/extension clauses, out-of-band operation authority, verifiable-resolution trust alternatives and metadata-equivalence conditions). The judgments below are authored against this new corpus; totals were counted after assigning the rows.

Documentary PASS means only that this author duty is satisfied on the stated narrow criterion. NOT_APPLICABLE means the named actor/activity/condition is absent; it is not runtime PASS. NOT_RUN is retained for the two actual DID-issuer uniqueness obligations, for which policy text is insufficient execution evidence. FAIL identifies a substantive author omission, not a successful attack or runtime defect.

## Main semantic conclusions

The privacy requirement is now supported by a method-specific discussion of all nine RFC6973 §5 categories. The all-eight-attacks requirement is supported by an operation matrix that includes real amplification exposures and acknowledges missing protections. The DLT resource recommendation is supported by concrete peer/operator CPU, bandwidth, consensus, storage/history and read-cost burdens, with no invented measurements. These are three fresh documentary PASS judgments, not retroactive changes to the frozen baseline.

The composite RFC3552 duty remains FAIL on a **current** basis: RFC3552 §5 expressly requires security of the authentication method, its assumptions, lower-layer services and combined properties to be specified. The new DoS discussion addresses the earlier example omission, but management authentication/complete command binding is still left unspecified. An all-guidelines judgment cannot be promoted simply because the previous cited omission disappeared. Security.5 and .6 independently retain their all-operation integrity/authentication-characteristics gaps. Fork.1 remains FAIL because no selected means distinguishes competing same-ID/address/code branches; the unadopted TMP proposal is not corpus evidence.

The other judgments below explicitly reassess the effect of the new text. It does not add a representation, alias, proof property, Multikey header or authentication service type; it does not change the syntax, record operations, proof constructions or resolution contracts. Author-level operation predicates can be documented while concrete authentication and deployment binding remain deficient; these scopes must not be conflated.

## Per-statement judgments

References use subject chapter numbers; `A2AB-*`, `EXEC-*` refer to the pinned profiles. Frozen RFC/DID references refer to the exact sources pinned below. Each ID's exact statement digest is listed separately after the table.

| # | Statement ID | Responsible actor / scope | Fresh verdict | Independent current-corpus basis and limits |
|---|---|---|---|---|
| 1 | `cid10#Multikey.24` | Multikey/header author | **NOT_APPLICABLE** | No publicKeyMultibase/secretKeyMultibase header scheme is defined; DIDP-01 explicitly emits JWK and not Multikey. Raw registry key encodings are not new Multikey headers. [10 §6; 11 §§2–3] |
| 2 | `did11-cr20260305#extensibility.2` | representation-extension author | **NOT_APPLICABLE** | No alternative representation-level extensibility mechanism is specified. The resolution sage metadata and A2A AgentExtension have different object scopes. [10 §§1,3,6; A2AB-03] |
| 3 | `did11-cr20260305#extensibility.3` | representation-extension author | **NOT_APPLICABLE** | The antecedent is an alternative representation extension; none is authored. Producing two different record views is not a claim of lossless conversion of arbitrary representations. [10 §§6,8] |
| 4 | `did11-cr20260305#extensibility.4` | representation-extension author | **NOT_APPLICABLE** | There is no newly authored representation-extension mechanism requiring such a data-model mapping. The registry projection is not that mechanism. [10 §§1,6] |
| 5 | `did11-cr20260305#media-types.1` | DID method author; media identification | **PASS** | DIDP-01 names application/did for its DID1.1 view and DIDP-02/RESOLVE-03 distinguish document media type from the application/json resolution envelope. Frozen DID1.1 §6.3 identifies application/did. This judges selected media identification only, not registration or every implementation convention. [10 §§1,3,5–7] |
| 6 | `did11-cr20260305#method-operations.1` | DID method author; authorization predicate | **PASS** | REG-03/REG-09 specify controller or exact DID/registry/operator/scope authorization, lifecycle eligibility, prior-version comparison and one atomic transition; REG-04 defines proof checks and excludes PoP as authorization. Frozen §7.2 permits out-of-band authority. This closes the abstract permission procedure, not the missing credential/command-binding security contract. [09 §§3,4,6,8,9] |
| 7 | `did11-cr20260305#method-operations.2` | DID method author; creation procedure | **PASS** | Choose canonical identifier before proofs, reserve unused DID, validate initial record/proofs, bind controller and atomically create version1; chain commit/reveal and web authority are described. Associated created-state projection is explicit. An actual registration or ABI is not inferred. [06 §§1,2,4; 09 §§1,3,4,6,8; 10 §§1,2,6] |
| 8 | `did11-cr20260305#method-operations.3` | DID method author; resolution procedure | **PASS** | DID selects registry/profile; one fresh authorized record is structurally/proof/version checked and projected. Self-validation or explicit authenticated-source trust is stated; web adds exact allowlisted TLS-origin/freshness rules. This is guidance for response authenticity, not a portable proof or completed fork/deployment verification. [09 §§4–6,8; 10 §2] |
| 9 | `did11-cr20260305#method-operations.4` | DID method author; update procedure | **PASS** | Key additions/revocations, complete service replacement, lifecycle and scoped-grant changes have explicit eligibility, expected version, immutable fields and atomic record/grant/history effects. The resulting projection is defined. All-command integrity is separately incomplete. [09 §§1,3,9; 10 §§1–3,6] |
| 10 | `did11-cr20260305#method-operations.5` | DID method author; deactivation procedure | **PASS** | Authenticated controller or eligible scoped operator can take created/active to terminal deactivated; record remains readable and loses protected usability, with grants removed atomically. This describes how, without certifying live enforcement. [09 §§3,9; 10 §§3,10] |
| 11 | `did11-cr20260305#method-syntax.1` | DID method author; syntax | **PASS** | Exactly the case-sensitive did:sage method is defined. Registry kinds are formats inside that one method, not additional method names. [06 §1] |
| 12 | `did11-cr20260305#method-syntax.10` | DID method author; optional path restriction | **PASS** | Closed DID-URL grammar and prose reject paths, exercising the permission to be more restrictive. This does not claim a runtime path-dereference test. [06 §1] |
| 13 | `did11-cr20260305#method-syntax.11` | DID method author; optional query restriction | **PASS** | Closed DID-URL grammar and prose reject queries; no standard optional query support is implied. [06 §1] |
| 14 | `did11-cr20260305#method-syntax.12` | DID method author; optional fragment restriction | **PASS** | key-id is restricted to 1–32 ASCII alphanumeric/hyphen/underscore and a single fragment; absolute full-key references and exact equality are required. [06 §§1,3] |
| 15 | `did11-cr20260305#method-syntax.2` | DID method author; identifier generation | **PASS** | registry-id(kind/locator)+agent-id construction and profile-specific locator lengths/grammars specify the method-specific-id; client chooses agent-id before binding proofs and the registry reserves unused identifiers. [06 §§1,2; 09 §§3,6,8; 11 §5] |
| 16 | `did11-cr20260305#method-syntax.3` | DID method author; normalization | **PASS** | Case-sensitive prefix, lowercase kind/chain address, canonical profile form, no percent encoding or aliases and byte-equality semantics are explicit. Noncanonical values are rejected rather than repaired. [06 §§1,2; 09 §§6,8] |
| 17 | `did11-cr20260305#method-syntax.4` | DID issuer / Registry uniqueness invariant | **NOT_RUN** | The text requires unique registry-id and agent-id, permanent non-reassignment and tombstones; this is useful policy evidence. This statement constrains actual issued values, not merely the author's description. No issuer state/history or independent issuance evidence is in this corpus, so neither runtime PASS nor a collision FAIL is established. [06 §2; 09 §§1,3] |
| 18 | `did11-cr20260305#method-syntax.5` | DID issuer / global uniqueness invariant | **NOT_RUN** | Namespace construction and reservation describe intended global uniqueness under registry/chain trust assumptions. Actual DID issuance and cross-registry/fork deployment behavior were not observed; the separate fork gap is not a demonstrated collision. No issuer result is invented. [06 §2; 09 §§3,5,6] |
| 19 | `did11-cr20260305#method-syntax.7` | DID method author; optional multiple formats | **PASS** | Explicit eip155 and optional web profiles give different fixed locator formats; solana is reserved/rejected rather than an executable third profile. [06 §1; 09 §§6–8; 11 §5] |
| 20 | `did11-cr20260305#method-syntax.8` | DID method author; optional colon syntax | **PASS** | The grammar explicitly partitions registry kind/locator/agent-id with colons and fixes locator segment count by supported profile. No generic meaning for colon is assumed. [06 §1; 09 §6; 11 §5] |
| 21 | `did11-cr20260305#privacy-requirements.1` | DID method author; privacy analysis | **PASS** | Section6.4 addresses all nine RFC6973 §5 categories with public-record/history/query/service consequences and bounded mitigation limits, including intrusion/unsolicited traffic and exclusion. It disclaims erasure, unlinkability and regulatory proof. [06 §6.4; RFC6973 §5] |
| 22 | `did11-cr20260305#production-and-consumption.1` | representation specification author | **NOT_APPLICABLE** | The obligation is to specify a representation for every abstract-model datatype. SAGE selects existing standard representations and defines closed record projections; it does not author a new representation. Generic producer/consumer completeness is not certified. [10 §§1,6] |
| 23 | `did11-cr20260305#production-and-consumption.2` | representation specification author | **NOT_APPLICABLE** | No new representation/media-type association is proposed. Using standard application/did in a projection is not authorship of a new IANA representation registration. [10 §§1,6,7] |
| 24 | `did11-cr20260305#production-and-consumption.3` | representation specification author | **NOT_APPLICABLE** | No new representation-level fragment-processing rules are authored. Method restrictions on full key URLs are distinct from an author defining fragment semantics for a new media type. [06 §§1,3; 10 §4] |
| 25 | `did11-cr20260305#production-and-consumption.4` | representation specification author | **NOT_APPLICABLE** | No new representation datatype lexical system is defined. Existing standard representations are selected; byte encodings for registry proofs/keys do not redefine DID abstract-model serialization. [10 §§1,6] |
| 26 | `did11-cr20260305#production-and-consumption.5` | representation specification author | **NOT_APPLICABLE** | The permission to choose alternate lossless datatype serialization is unexercised. Distinct Core1.0/DID1.1 record projections are explicitly not lossless reserialization of one another. [10 §6] |
| 27 | `did11-cr20260305#production-and-consumption.6` | representation specification author | **NOT_APPLICABLE** | No representation-specific entries-map mechanism is newly defined. The fixed standard context and separate resolution metadata are not a novel mechanism. [10 §§3,6] |
| 28 | `did11-cr20260305#security-requirements.1` | DID method author; composite RFC3552 duty | **FAIL** | Residual DoS/exclusions are now substantively discussed, but RFC3552 §5 also requires the authentication method's security assumptions and tight lower-layer protection/combined properties to be specified. Chapter09 still delegates management credential/principal and complete command integrity to unfinished bindings; new6.1/6.2 explicitly acknowledge that gap. Therefore the all-guidelines obligation is still false; this is not inherited solely from its old DoS basis. [06 §§6.1–6.3; 09 §§6,8,9; RFC3552 §5] |
| 29 | `did11-cr20260305#security-requirements.10` | DID method author; cryptographic protection description | **PASS** | The corpus specifies signature domains/covered fields, record PoP, exact HTTP components, complete envelope coverage, HPKE exporter/combiner and session AEAD/AAD, plus channel vs object protection and susceptibility/assumption limits. This is a coverage-description judgment, not proof that every management operation is protected or the composition is secure. [01 §§1–3; 03 §§1–5; 04 §§1–6; 05 §§1–5; 08 §§1–6; 09 §4; 06 §§6.1–6.3] |
| 30 | `did11-cr20260305#security-requirements.11` | DID method author; secret labeling | **PASS** | CRYPTO-05 identifies private/shared/ephemeral and expired traffic secrets and prohibits logging; HPKE names exporter/ack/private state and erasure, session seed/key retention is explicit, and claim salt is secret before reveal. Public keys/records are distinguished. This does not certify custody or erasure implementation. [01 §3; 04 §§2–5; 05 §§1,5; 09 §6; 06 §§6.1,6.4] |
| 31 | `did11-cr20260305#security-requirements.12` | DID method author; conditional document signatures | **NOT_APPLICABLE** | The DID document is not signed as a whole in this method. Key PoP, signed Agent Cards/messages and authenticated record sources are different objects; no whole-document proof is emitted. The conditional implementation-of-DID-document-signatures recommendation is not exercised. [10 §§1,3,6; 07 §2; 09 §4] |
| 32 | `did11-cr20260305#security-requirements.13` | DID method author; DLT DoS burdens | **PASS** | Section6.3 relates transaction/proof CPU, peer propagation, consensus/finality, storage/history/tombstones and read/RPC burdens to DoS and externalized costs; explains limits of fees and per-record bounds, with measurements still future. The documentary SHOULD does not require invented measured fees. [06 §§6.2,6.3; 09 §§3,5,6] |
| 33 | `did11-cr20260305#security-requirements.14` | authentication-service-type author | **NOT_APPLICABLE** | No DID service type is introduced as a new authentication protocol service. A2AInterface is endpoint eligibility/discovery and grants no authority; existing A2A authentication schemes remain independent. The management proposal is outside this corpus. [09 §1; 11 §8; A2AB-05/06] |
| 34 | `did11-cr20260305#security-requirements.2` | DID method author; all listed attacks | **PASS** | The operation-specific matrix covers eavesdropping, replay, insertion, deletion, modification, DoS, amplification and MITM for creation/mutations/reads. Amplification now includes replication/storage/backend/proof costs. Discussing an acknowledged unmitigated exposure satisfies this discussion duty without claiming all attacks prevented. [06 §6.2] |
| 35 | `did11-cr20260305#security-requirements.3` | DID method author; other known attacks | **PASS** | Registry/key substitution, claim-name racing, stale/rollback source state, parser ambiguity, cross-protocol/key confusion, compromised components and downgrade/bypass are discussed, with charter/integration limits. No completeness or exploit-test claim is inferred. [06 §§3,6.1–6.4; 01; 02 §3; 09 §§4–6; charter §5; EXEC-01/09; A2AB-07] |
| 36 | `did11-cr20260305#security-requirements.4` | DID method author; residual-risk discussion | **PASS** | Compromised controller/trusted source/capture/policy, initially poisoned enrollment, traffic analysis, implementation-boundary failures, finality/outage availability and lack of a forward-secure ratchet are explicit residual risks. Discussion does not repair those exclusions or claim mitigation execution. [06 §§6.1–6.4; charter §5; 04 §6; 05 §5; EXEC-01/09] |
| 37 | `did11-cr20260305#security-requirements.5` | DID method author; all-operation integrity/update authentication | **FAIL** | Expected version, immutable fields and atomic grants/history are specified, but no selected binding protects the complete registry/DID/operation/version/arguments association for every management command. PoP/commitment/public-read TLS have narrower coverage. New6.2 records the absence rather than supplying an accepted command encoding/credential integration. [09 §§3,4,6,8,9; 06 §6.2] |
| 38 | `did11-cr20260305#security-requirements.6` | DID method author; authentication characteristics | **FAIL** | Management requires trusted authenticated controller/operator credentials but still leaves their actual method, credential-to-principal association, termination, compromise and replay characteristics to future deployment bindings. Describing trust assumptions generically is not specifying the selected method. The TMP proposal is not normative corpus evidence. [09 §§1,6,8,9; 06 §§6.1,6.2] |
| 39 | `did11-cr20260305#security-requirements.7` | DID method author; assignment policy discussion | **PASS** | Registry-qualified namespace, one registry per registry-id, unique local reservation, immutable/non-reassigned IDs and tombstones are stated, including independent claim races and proof-vs-authorization limits. This discusses policy; actual issuer uniqueness remains NOT_RUN and fork means remain deficient. [06 §§1,2,6.2; 09 §§1,3,6] |
| 40 | `did11-cr20260305#security-requirements.8` | DID method author; endpoint-authentication discussion | **PASS** | Web reads require allowlisted exact HTTPS origin and controlled destinations, no redirects/Card endpoint substitution, explicit authenticated-source trust; application HTTP/Card binding and expected-peer rules are discussed separately. Endpoint discovery is not authority. This does not certify roots/DNS/operations or fill unspecified management authentication. [09 §§5,8; 10 §§2,5; 03 §§2,5; A2AB-05/06; 06 §§6.1,6.2] |
| 41 | `did11-cr20260305#security-requirements.9` | DID method author; topology trust assumptions | **PASS** | The chain profile requires self-validated node or explicitly trusted authenticated resolver and configured readiness/finalized state, rejects arbitrary latest RPC as proof, and distinguishes malicious trusted validators and coherent observations. It does not claim a light-client verifier or all-network topology implementation. Fork selection remains separate. [09 §§5,6; 10 §2; 06 §§6.1,6.3] |
| 42 | `res10-crd20261001#dereferencing-algorithm-resource.45` | DID method author; optional path/query dereference | **NOT_APPLICABLE** | SAGE explicitly excludes paths and queries and defines only canonical full-key URL dereference. It therefore does not exercise this permission to supply method path/query processing. This is compatible with the separately exercised narrower-syntax permissions. [06 §1; 10 §4] |
| 43 | `res10-crd20261001#dereferencing-algorithm-resource.46` | DID-path extension author | **NOT_APPLICABLE** | No extension specification for DID-path dereferencing is authored. A2A and MCP application bindings are not such DID URL extensions. [06 §1; 10 §4; profile scopes] |
| 44 | `res10-crd20261001#dereferencing-algorithm-resource.47` | DID-query extension author | **NOT_APPLICABLE** | No DID-query dereferencing extension is authored; method queries are rejected. [06 §1; 10 §4] |
| 45 | `res10-crd20261001#did-document-metadata.17` | DID method author; equivalentId guarantee | **NOT_APPLICABLE** | RESOLVE-03 and DIDP-04 emit no equivalentId and define no alternate equivalent forms. The conditional equivalence guarantee is not exercised; ignoring a received alias does not validate that alias. [10 §§3,9] |
| 46 | `res10-crd20261001#did-document-metadata.22` | DID method author; canonicalId guarantee | **NOT_APPLICABLE** | No canonicalId metadata is emitted and no alias-to-canonical mapping is defined. Canonical syntax of the one id is not a canonicalId assertion. [06 §2; 10 §§3,9] |
| 47 | `res10-crd20261001#errors.6` | resolution-error extension author | **NOT_APPLICABLE** | The DID Resolution interface maps local SAGE diagnostics to existing standard error types and carries sageCode; it does not declare a newly defined DID Resolution error type refining another. Separate SAGE problem URIs do not exercise this refinement declaration. [10 §§5,10] |
| 48 | `res10-crd20261001#method-architectures.1` | DID method author; verifiable-resolution guidance | **PASS** | REG-05/RESOLVE-02 give a self-validating trusted-node route and an explicitly authenticated trusted-source route, with coherent fresh observations, proof validation and rollback/readiness refusal. Frozen §8.1 expressly permits local trusted and remote trusted secure-channel architectures. No trustless portability or runtime availability is claimed. [09 §§4–6,8; 10 §2] |
| 49 | `res10-crd20261001#method-architectures.2` | DID method author; use of declared verification proofs | **PASS** | The method's record proofs have specified exact challenge fields/domains, signer/algorithm checks and verification ordering; RESOLVE-02 requires their verification before projection. Their contribution is record/key binding under authenticated-state assumptions, not proof of finality or a whole returned document to an untrusted client. That use is documented; stronger portable result proofs are not implied. [09 §4; 10 §§1,2; 01 §§1–3] |
| 50 | `res10-crd20261001#method-architectures.3` | DID method author; optional embedded result proofs | **NOT_APPLICABLE** | No method result/state proof is placed in the DID document or its metadata. Registry PoP and separately signed Cards are not an embedded resolution-proof property. This optional placement is not exercised. [10 §§1,3,6] |
| 51 | `res10-crd20261001#vdr-forks.1` | DLT DID method author; fork-disambiguation recommendation | **FAIL** | Chain ID, registry address/code, finalized block hash and monotonic versions do not choose or reject competing branches retaining those identifiers. The corpus still leaves the complete branch/consensus/attestation binding unspecified; new6.2 admits this. The separate TMP fork proposal is excluded and cannot close this recommendation. [06 §§2,6.2; 09 §§5,6; 10 §2] |

## Exact normative corpus

| Path | Bytes | SHA256 | Difference from baseline |
|---|---:|---|---|
| `profiles/a2a-1.0-binding.md` | 10657 | `c4c7f263ea3e9ff122277976f0bebf4357c418956256c33fbbb28570b8a67b4d` | unchanged |
| `profiles/agent-mcp-security.md` | 27559 | `0538acbdcfc143d93fb7d99a2a2c09c068fc354388c4e37c7489204305b1913f` | unchanged |
| `profiles/non-http-mcp-security.md` | 55490 | `9c7851d095208c975792565266e481c120ef754ae8eb9529c62b53bf12a1d4fa` | unchanged |
| `spec/00-overview.md` | 9574 | `8655cddfa23979cb12432f83831e58ee2b6e240b5f1f92b84594d7084eaeb3f0` | unchanged |
| `spec/01-crypto.md` | 5347 | `35463137986ae692593cb12a3654085270f3337acea3aa3d7efcdde8cea78a0a` | unchanged |
| `spec/02-jcs.md` | 3656 | `4d4b202c8ddb5eb00c47a8e8056813a589834526e2174c023fb005a484eb3d94` | unchanged |
| `spec/03-rfc9421.md` | 8765 | `b28d567cbf3f7a6a256c73fd35696865b5c0ebdc814de57624b90df082d49407` | unchanged |
| `spec/04-hpke.md` | 8635 | `1420818451ce8363a16e391647dbaca8ec2f06efa56b6507027a4e17f399fdd6` | unchanged |
| `spec/05-session.md` | 6999 | `8a45b8bdd3b6bfc399a94c420b2161b8f16db5c6b29ed2e85584a6282b17cce5` | unchanged |
| `spec/06-did-sage.md` | 21944 | `995f99299abc0ebd02651bfda75a5d30145968add464e1f93b2e9d656ea8184b` | 6.1–6.4 only |
| `spec/07-a2a.md` | 4147 | `5ded622fdaf67342d5c6b4327da0f5787bfe9df2dc58b233cdfb500ffc96b042` | unchanged |
| `spec/08-transport.md` | 9152 | `e11e8200d67ee913fcd1a47781c6d31a353556c9dfd4e4ce0a88dbe97e10bba6` | unchanged |
| `spec/09-registry.md` | 20575 | `e8572cc037fd0fc84e678be436cc47854c5fd700aacbc141937d79ee03ea6017` | unchanged |
| `spec/10-resolution.md` | 16406 | `78fdf5fc998b92b0ce262a2509b1595458ff8a083cc4e8570c50efcd2e7270bd` | unchanged |
| `spec/11-registries.md` | 11316 | `aaf8e68a1af957fd079ff56d89636b792930e8e0202b3d09a084164005589513` | unchanged |
| `charter.md` | 19108 | `0c22ccfe49011c09967ccab993135b663599e2f05da4040383f1f24542cef2cd` | unchanged |

## Canonical statement identity

The exact source document hashes are:

- CID1.0 REC2025-05-15 HTML: `c5e9befba602b53de46669cf98067123d1901357a425f8bff621796b2ac4ac4a`.
- DID1.1 CR2026-03-05 HTML: `4a48022defe07d37d2decc3ec9027a932dc883b2ad164a5aeaf9256e530bd979`.
- DID Resolution1.0 CRD2026-10-01 HTML: `2b194843d37f5b7f01a4f5464f64d672dc4be43dafe5f2f49114c6070819586e`.
- Canonical statement JSON SHA256: cid10 `24e03cda21af04e5b218af260b7fc42ead72ec3224e3f1195ecae207de25e17e`; did11 `a54522f0e96126e52e50f886e5125bcdf99e9b32cd6e6068ed97087b393b1020`; res10 `de73498219515f9433fd80f28d7c3bbb9647c59fbd13ccb8f59dd66b66720c15`.
- Local RFC3552: `ba07e18bdffd18893e8607398bef42dbdb5f1c5aa0c7dd6891d43ca8a0b19e4f`; RFC6973: `94bb6027b22603c58728431ec4606a0f2a7aad569234322c55d6a91e22ffa06e`.

| Statement ID | SHA256 of exact canonical text |
|---|---|
| `cid10#Multikey.24` | `310d1814b55b741a40ea501a908c01a81cd1f4ebbadb0a280107b0006a4f0d52` |
| `did11-cr20260305#extensibility.2` | `116f03ebba51a0e50896099112d174f0bc31523ab78895d66619488e5ff53063` |
| `did11-cr20260305#extensibility.3` | `1e2e5134d3219f3b8cc32e7299425cad718db17d27c49a91003390d21ebfa30b` |
| `did11-cr20260305#extensibility.4` | `8b77a7a7414b1c93b975e1f6e7357251a30df57058c4575c65fe9df8b6cc0deb` |
| `did11-cr20260305#media-types.1` | `05898a7a8263e228b88118f7280b503360c6af1eb0b2fb2a5bdc7b2db7a1a143` |
| `did11-cr20260305#method-operations.1` | `d3baa658d5a6a9e66bc2cba1da4e71a5e0d7e3b49df895cb1d4eb81c2f7d0cd2` |
| `did11-cr20260305#method-operations.2` | `82093e661152dc13b4dd2fb83c34e9a7b2dfff9a7228b73762653806b9193387` |
| `did11-cr20260305#method-operations.3` | `a75bab77172b71661b814b3f68dfc517ee2091c1fd7bed8902fba33da4a05a45` |
| `did11-cr20260305#method-operations.4` | `fc2e1a5f40f7a1c09fa245de8c39ee8af8a3ff3dff53a5b1f8694c9c9add0895` |
| `did11-cr20260305#method-operations.5` | `6fd07f422770f601b428954086c0b505203adaaf763e780d253f622ed0016ca1` |
| `did11-cr20260305#method-syntax.1` | `69ee4c10a6543faf5679f4effcacce9954e2077e22f468bbca9972b9cf0bd038` |
| `did11-cr20260305#method-syntax.10` | `62663a6f13f857fcb22fbf0b30258d2a1776bd32134a36bc64445c560b7a3fe8` |
| `did11-cr20260305#method-syntax.11` | `76f45fe8788c1671053b26a4826c45af1974e6b500d60b80597d2e7e0f992f94` |
| `did11-cr20260305#method-syntax.12` | `0e225ad03972ac82c20e5c3d681379b12e60e03d6008a1817f5ddcb1894404ac` |
| `did11-cr20260305#method-syntax.2` | `b182adea95ba28bce23cd9c0318549bf1d677a2e5b9972f67c1c531de526d3b9` |
| `did11-cr20260305#method-syntax.3` | `ee943162323f401ed6b24280c305496be31d274d24962892509f71e4ab65c73c` |
| `did11-cr20260305#method-syntax.4` | `db03406ede87b4b30b3c414f89f05418fa4a85223e5d3f8c232472d2f478fc2f` |
| `did11-cr20260305#method-syntax.5` | `ad848045d9746d2af6aff593a2c5fcd68de5e30082d0fb937363f7dd7ece6a88` |
| `did11-cr20260305#method-syntax.7` | `8e5c4a0da5940649de31ced9541cd6cb149f0226c9a57f04af08cd3f9bc418df` |
| `did11-cr20260305#method-syntax.8` | `5ff207e3decb0cd070634b7c002db07b6ea6953f68b43d7ec56073ee11297aca` |
| `did11-cr20260305#privacy-requirements.1` | `c47fae06127b02269a8764e0f1b721e9d0198741530182397ea15539708ae2ee` |
| `did11-cr20260305#production-and-consumption.1` | `f112032c07077934450569e8378e35100f6beed0044e73b912ce49c3985547a6` |
| `did11-cr20260305#production-and-consumption.2` | `1a84e0112b30a491a51166e2f71d813da606cdcf1e5066b18538170bd52c18c8` |
| `did11-cr20260305#production-and-consumption.3` | `b71ddae72b33fb158e0a0d2d14a3cea5b1eda57e76276a5162966a21bd8c529b` |
| `did11-cr20260305#production-and-consumption.4` | `5a987d67caca593f66081a874414e395d5f61701e689f701d0c6b3354f4e9c14` |
| `did11-cr20260305#production-and-consumption.5` | `572fd118865fb61d024ae9f0829f11210e7da96c61ecc9c95c130b182369ddc2` |
| `did11-cr20260305#production-and-consumption.6` | `d1ecd1c6f7d1c7db3ad35f471f2bc4789bd5a0d76edeace01977b879b11fdf31` |
| `did11-cr20260305#security-requirements.1` | `11f7f73261e868824223349fbfa751f03b96b8ea90249fedadd503f1bd19c791` |
| `did11-cr20260305#security-requirements.10` | `1a67f55e75fc34dbb71da7f876c14cfae3111d559cce854d0569ebb111e19797` |
| `did11-cr20260305#security-requirements.11` | `28be932b25a09473668cf1c7c0129b2b6cf6239d13d6a291954799b561dc0c17` |
| `did11-cr20260305#security-requirements.12` | `70c566b00519925526d337b5a5d1546bcaae92d971f0f470c63a5cecb5eb9c29` |
| `did11-cr20260305#security-requirements.13` | `a5ea305e7140d57e7d4f1a9dcc59feb8643852f289c6da66502d0c8a0a36e248` |
| `did11-cr20260305#security-requirements.14` | `3758e875eb6dd4be6bfa66240f7e9bdfd6e162a1d9e94232e8ae65d86a223400` |
| `did11-cr20260305#security-requirements.2` | `d74dd966541d564febca74e1064fadaaa744cad40a5785ba72ab4fff88480ba6` |
| `did11-cr20260305#security-requirements.3` | `3fdc4a05f3f4eaa9c6167fa96b642b5f647c86419d818f6832e86cd6c5ec78b7` |
| `did11-cr20260305#security-requirements.4` | `946c892fcfa2dbfb3359ac69edcb144639980a933a8b4bb6d441499f5e9e55fa` |
| `did11-cr20260305#security-requirements.5` | `9b733ac26432e5bf9664609bcb09747dc0dd3340ebf598b3ffdc476d720cc220` |
| `did11-cr20260305#security-requirements.6` | `bed5cbf9fdd8820fc2add7c38bcf111997423fe35d6669cb1f38177b380884a8` |
| `did11-cr20260305#security-requirements.7` | `6d702a2a4e566ae601ad5b3081de0499d6708ccf9af9a72eeb46a8a6617e3ae3` |
| `did11-cr20260305#security-requirements.8` | `863bc9ad6558c7eca027156c0469cc00d9e16ff66c5d3053229d319b08b290af` |
| `did11-cr20260305#security-requirements.9` | `26aac44cdd2ed9341ed309d8cdec2cd9d07de670de9d78700470b909183e2b49` |
| `res10-crd20261001#dereferencing-algorithm-resource.45` | `47be1ab5eb643fe3dc5abda17c517decfe6165f4ee0896a8e2bc2d0e5b22d27a` |
| `res10-crd20261001#dereferencing-algorithm-resource.46` | `ef3a7426057ffec23550f0fe14ff0ee1909c1584d56a52ef363e9dbb5c744944` |
| `res10-crd20261001#dereferencing-algorithm-resource.47` | `ce2719c1839bf463fdd97e90785c9f2bc7419635177cd55b71da363f4a8356a9` |
| `res10-crd20261001#did-document-metadata.17` | `219feba40019f2480a03ffd37b2fd955c25e2ba21891fa0f08e5f0f031f44a38` |
| `res10-crd20261001#did-document-metadata.22` | `116fb5d219aa0e222dff57a354c2408b18956a2ad4822b45c20dedbc0c99bcdd` |
| `res10-crd20261001#errors.6` | `7c7d832b97e5cde7df1c8feda757fbff5c084e7ff8f3496ced69367fdd864580` |
| `res10-crd20261001#method-architectures.1` | `e9485a18127e4f84a8fc6032532d372e103a63517ef10ecbb8fc7f5f28cd56a2` |
| `res10-crd20261001#method-architectures.2` | `73e288ef4f386634774de96f20e19fbf350cc5be79557921fa3c186723554af9` |
| `res10-crd20261001#method-architectures.3` | `2945c5c577e7bf8646421340c94e56c40bbe54b4f4dd1daed25f3191d9cb74d9` |
| `res10-crd20261001#vdr-forks.1` | `74cf2546e1e2f76440a15d6d761a7b2849bbf631808057cb71f50e37447e5b74` |

## Unresolved conditions and evidence separation

1. Complete the actual all-command integrity and management credential/principal security contract in the specification before expecting security.5/.6 or composite security.1 closure. No specific root, credential type or ABI is invented by this review, and a generic future-binding promise is insufficient.
2. A means for fork disambiguation needs selected validation/attestation/branch/readiness semantics. Chain identification alone is insufficient; no new fork acceptance rule or operational root is chosen here.
3. Issuer uniqueness needs separate actual issuer/registry/deployment evidence; the two NOT_RUN rows do not become PASS from a namespace diagram or documentation check.
4. Current subject equality at main is independently established, but this semantic report does not accept a main CI execution. A new Inspector replay/checker record and its actual CI are also not completed here. A checker can verify identity, evidence spans and explicit authored decisions; it cannot derive general semantic truth from substring matches or old aggregate counts.

The frozen old corpus remains separately 23 PASS / 19 NOT_APPLICABLE / 7 FAIL / 2 NOT_RUN. This review does not edit its record, source pins, runtime reports or total, and does not union old and new inventories. Its three changed documentary judgments apply only to this exact new corpus. The fresh 51-clause summary does not alter separate three 0.10.0 alg/kid/JSON-LD recommendation causes, runtime 92 NOT_RUN, Core1.0 173 NOT_RUN, old unsupported subjects, issuer/operating/deferred-registration requirements or project completion status. All other standard clauses outside this selected author scope remain unreviewed here.

No Go/Rust execution, build/test/parser/formatter, network/API, repository edit, new agent or external review request occurred. Work was limited to fixed Git/file/JSON/hash and frozen HTML text inspection, plus writing this TMP report. Nothing in this report establishes deployed Registry honesty, custody, host isolation, full protocol compliance or completion of stages7/8.
