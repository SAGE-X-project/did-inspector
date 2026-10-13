package sageresolution

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

const edJWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
const xJWK = `{"kty":"OKP","crv":"X25519","x":"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
const pJWK = `{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}`

func jwkValue(t *testing.T, raw string) core.Value {
	t.Helper()
	v, e := core.ParseJSON([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func jwkDoc(t *testing.T, key string) Result {
	t.Helper()
	r := nativeSchemaFixture("did-1.1")
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[{"id":"did:sage:web:x:a#k","type":"JsonWebKey","controller":"did:sage:web:x:a","publicKeyJwk":` + key + `}]}`)
	return r
}
func TestSelectedPublicJWKFormatsAndEncodingNegatives(t *testing.T) {
	c, e := jwkRegistry()
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{edJWK, xJWK, pJWK} {
		if v := publicJWKFormat(jwkValue(t, raw), c); v != core.Pass {
			t.Fatal(raw, v)
		}
	}
	for _, raw := range []string{
		`null`, `{}`, `{"kty":7}`, `{"kty":""}`, `{"kty":"OKP"}`, `{"kty":"OKP","crv":7}`,
		strings.Replace(edJWK, `"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"`, `"x":"AA"`, 1),
		strings.Replace(edJWK, `HURo"`, `HURo="`, 1), strings.Replace(edJWK, `HURo"`, `HURp"`, 1),
		strings.Replace(edJWK, `HURo"`, `HURo\n"`, 1), strings.Replace(edJWK, `"x":`, `"x":7,"ignored":`, 1),
		strings.Replace(pJWK, `,"y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"`, ``, 1),
		`{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
	} {
		if v := publicJWKFormat(jwkValue(t, raw), c); v != core.Fail {
			t.Fatal(raw, v)
		}
	}
	for _, raw := range []string{`{"kty":"RSA","n":"public-fixture","e":"AQAB"}`, `{"kty":"OKP","crv":"Ed448"}`, `{"kty":"EC","crv":"P-384"}`, strings.Replace(edJWK, `}`, `,"alg":"EdDSA"}`, 1), strings.Replace(edJWK, `}`, `,"x5c":[]}`, 1), strings.Replace(edJWK, `}`, `,"y":7}`, 1)} {
		if v := publicJWKFormat(jwkValue(t, raw), c); v != core.NotSupported {
			t.Fatal(raw, v)
		}
	}
	// Additional unregistered members are retained and ignored per RFC7517.
	extended := strings.Replace(edJWK, `}`, `,"vendorExtension":{"sequence":[1,2]}}`, 1)
	if v := publicJWKFormat(jwkValue(t, extended), c); v != core.Pass {
		t.Fatal(v)
	}
}
func TestEveryPinnedPrivateParameterIsRejectedByPresence(t *testing.T) {
	c, e := jwkRegistry()
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"} {
		if !c.private[name] {
			t.Fatal("missing registry classification", name)
		}
		raw := strings.Replace(edJWK, `}`, `,"`+name+`":null}`, 1)
		obs := judgePublicJWK(jwkDoc(t, raw), c, "original")
		for _, id := range []string{"JsonWebKey.4", "JsonWebKey.13"} {
			if nativeVerdict(obs, id) != core.Fail {
				t.Fatal(name, id, obs)
			}
		}
		if nativeVerdict(obs, "JsonWebKey.3") != core.NotSupported {
			t.Fatal("uninspected private-format semantics", name)
		}
	}
	method := jwkValue(t, `{"publicKeyJwk":{"synthetic-secret":null}}`)
	c.secret["synthetic-secret"] = true
	if jwkMemberVerdict(method, "cid10#JsonWebKey.13", c) != core.Fail || jwkMemberVerdict(method, "cid10#JsonWebKey.4", c) != core.Pass {
		t.Fatal("class distinction")
	}
}
func TestCurveAndPublicSecretRulesHaveSeparateAttribution(t *testing.T) {
	c, _ := jwkRegistry()
	for _, tc := range []struct {
		key  string
		want core.Verdict
	}{
		{edJWK, core.Pass}, {xJWK, core.Pass}, {pJWK, core.Pass},
		{`{"kty":"EC"}`, core.Fail}, {`{"kty":"OKP","crv":""}`, core.Fail},
		{`{"kty":"EC","crv":"unknown-curve"}`, core.NotSupported}, {`{"kty":"AKP"}`, core.NotSupported},
		{`{"kty":"RSA"}`, core.NotApplicable}, {`{"kty":"oct"}`, core.NotApplicable}, {`{}`, core.Error}, {`null`, core.Error},
	} {
		if v := jwkCurve(jwkValue(t, tc.key)); v != tc.want {
			t.Fatal(tc, v)
		}
	}
	r := jwkDoc(t, edJWK)
	r.Snapshot = json.RawMessage(strings.Replace(string(r.Snapshot), `"publicKeyJwk":`, `"secretKeyJwk":null,"publicKeyJwk":`, 1))
	obs := judgePublicJWK(r, c, "")
	if nativeVerdict(obs, "JsonWebKey.12") != core.Fail || nativeVerdict(obs, "JsonWebKey.4") != core.Pass {
		t.Fatal("separate privacy constraints", obs)
	}
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[{"type":"JsonWebKey"}]}`)
	obs = judgePublicJWK(r, c, "")
	for _, id := range []string{"JsonWebKey.3", "JsonWebKey.4", "JsonWebKey.8", "JsonWebKey.13"} {
		if nativeVerdict(obs, id) != core.NotApplicable {
			t.Fatal("optional public field", id)
		}
	}
	if nativeVerdict(obs, "JsonWebKey.12") != core.Pass {
		t.Fatal("public secret property absent")
	}
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[{"type":"JsonWebKey","publicKeyJwk":null}]}`)
	obs = judgePublicJWK(r, c, "")
	if nativeVerdict(obs, "JsonWebKey.3") != core.Fail || nativeVerdict(obs, "JsonWebKey.4") != core.Error {
		t.Fatal(obs)
	}
}
func TestJWKScopeCollectsEmbeddedMethodsWithoutOtherClasses(t *testing.T) {
	c, _ := jwkRegistry()
	r := jwkDoc(t, edJWK)
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","authentication":["did:sage:web:x:a#ref",{"type":"JsonWebKey","publicKeyJwk":` + edJWK + `}],"verificationMethod":[{"type":"JsonWebKey2020","publicKeyJwk":` + edJWK + `},{"type":"Multikey","publicKeyMultibase":"public-fixture"}]}`)
	for _, o := range judgePublicJWK(r, c, "input") {
		if o.Verdict != core.Pass || o.Input != "input" || !strings.Contains(o.Detail, jwkRegistryHash) {
			t.Fatal(o)
		}
	}
	for _, snapshot := range []string{`{"id":"did:sage:web:x:a"}`, `{"verificationMethod":[]}`, `{"verificationMethod":[{"type":"JsonWebKey2020"}]}`} {
		r.Snapshot = json.RawMessage(snapshot)
		for _, o := range judgePublicJWK(r, c, "") {
			if o.Verdict != core.NotApplicable {
				t.Fatal("non-applicable class", o)
			}
		}
	}
}
func TestJWKExecutionDriftAndMalformedOutputsNeverPass(t *testing.T) {
	c, _ := jwkRegistry()
	for _, change := range []func(*Result){
		func(r *Result) { r.HasContent = false }, func(r *Result) { r.ContentKind = "verification-method" },
		func(r *Result) { r.Metadata = json.RawMessage(`{`) }, func(r *Result) { r.Metadata = json.RawMessage(`{"contentType":"application/did+json"}`) },
		func(r *Result) {
			r.Metadata = json.RawMessage(`{"contentType":"application/did","error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		},
		func(r *Result) { r.Snapshot = json.RawMessage(`{`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{"id":"x","id":"y"}`) },
		func(r *Result) { r.Snapshot = json.RawMessage(`{"verificationMethod":{}}`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{"authentication":{}}`) },
		func(r *Result) { r.ContentMetadata = json.RawMessage(`{`) },
	} {
		r := jwkDoc(t, edJWK)
		change(&r)
		for _, o := range judgePublicJWK(r, c, "original") {
			if o.Verdict != core.Error || o.Input != "original" {
				t.Fatal(o)
			}
		}
	}
	original := jwkParameterBytes
	defer func() { jwkParameterBytes = original }()
	jwkParameterBytes = append([]byte("changed"), original...)
	if _, e := Profile("did-1.1"); e == nil {
		t.Fatal("registry drift silently used")
	}
	if _, e := Profile("did-core-1.0"); e != nil {
		t.Fatal("unrelated profile affected", e)
	}
}
func TestStrictJWKBytesRejectsNonCanonicalEncodings(t *testing.T) {
	for _, value := range []core.Value{core.Number("7"), core.String(""), core.String("AA=="), core.String("A+"), core.String("AB"), core.String("AA\n"), core.String("A")} {
		if _, ok := strictJWKBytes(value, 1); ok {
			t.Fatal(value)
		}
	}
	raw := base64.RawURLEncoding.EncodeToString([]byte{1})
	if _, ok := strictJWKBytes(core.String(raw), 1); !ok {
		t.Fatal("canonical bytes")
	}
}
