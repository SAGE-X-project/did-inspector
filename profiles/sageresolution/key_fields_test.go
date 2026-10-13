package sageresolution

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

func TestNativeKeyFieldsPresenceAndRecommendations(t *testing.T) {
	result := nativeSchemaFixture("did-1.1")
	result.Snapshot = json.RawMessage(strings.Replace(string(result.Snapshot), `"x":"public-fixture"`, `"x":"public-fixture","alg":"EdDSA"`, 1))
	for _, obs := range judgeKeyFields(result, "unit") {
		if obs.Verdict != core.Pass || obs.Input != "unit" || obs.Observed == "" {
			t.Fatal(obs)
		}
	}
	for _, tc := range []struct{ old, new, id string }{{`"alg":"EdDSA"`, `"alg":7`, "cid10#JsonWebKey.7"}, {`,"alg":"EdDSA"`, ``, "cid10#JsonWebKey.7"}, {`"id":"did:sage:web:x:a#a2a",`, ``, "cid10#services.3"}} {
		bad := result
		bad.Snapshot = json.RawMessage(strings.Replace(string(result.Snapshot), tc.old, tc.new, 1))
		found := false
		for _, obs := range judgeKeyFields(bad, "unit") {
			if obs.Statement == tc.id {
				found = true
				if obs.Verdict != core.Fail {
					t.Fatal(obs)
				}
			}
		}
		if !found {
			t.Fatal(tc)
		}
	}
	result.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a"}`)
	obs := judgeKeyFields(result, "unit")
	for i := 0; i < 3; i++ {
		if obs[i].Verdict != core.NotApplicable {
			t.Fatal(obs)
		}
	}
	for _, snapshot := range []string{`{"service":[]}`, `{"service":[7]}`} {
		result.Snapshot = json.RawMessage(snapshot)
		want := core.Pass
		if strings.Contains(snapshot, "7") {
			want = core.Fail
		}
		if judgeKeyFields(result, "unit")[0].Verdict != want {
			t.Fatal(snapshot)
		}
	}
	for _, mutate := range []func(*Result){func(r *Result) { r.HasContent = false }, func(r *Result) { r.Exchange = &core.HTTPExchange{} }, func(r *Result) { r.Metadata = json.RawMessage(`null`) }, func(r *Result) { r.Metadata = json.RawMessage(`{}`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{`) }, func(r *Result) { r.ContentMetadata = json.RawMessage(`null`) }, func(r *Result) { r.Snapshot = json.RawMessage(`{"verificationMethod":7}`) }} {
		bad := nativeSchemaFixture("did-1.1")
		mutate(&bad)
		for _, obs := range judgeKeyFields(bad, "unit") {
			if obs.Verdict != core.Error || obs.Input != "unit" {
				t.Fatal(obs)
			}
		}
	}
}
func TestSelectedMaterialDoesNotInferAliases(t *testing.T) {
	public := make([]byte, 32)
	public[0] = 1
	jwk := core.Object(core.M("kty", core.String("OKP")), core.M("crv", core.String("Ed25519")), core.M("x", core.String(base64.RawURLEncoding.EncodeToString(public))))
	method := func(j core.Value, mb string) core.Value {
		out := core.Object(core.M("type", core.String("JsonWebKey")), core.M("publicKeyJwk", j))
		if mb != "" {
			out.Object = append(out.Object, core.M("publicKeyMultibase", core.String(mb)))
		}
		return out
	}
	if selectedMaterial(method(jwk, "")) != core.Pass {
		t.Fatal("single material")
	}
	encoded, _ := checks.MultibaseEncode('z', append([]byte{0xed, 0x01}, public...))
	if selectedMaterial(method(jwk, encoded)) != core.Fail {
		t.Fatal("same key twice")
	}
	different := append([]byte(nil), public...)
	different[0] = 2
	encodedDifferent, _ := checks.MultibaseEncode('z', append([]byte{0xed, 0x01}, different...))
	for _, m := range []core.Value{core.Object(core.M("type", core.String("Other"))), core.Object(core.M("type", core.String("JsonWebKey")), core.M("publicKeyHex", core.String("01"))), method(jwk, "bad"), method(jwk, encodedDifferent), method(core.Object(core.M("kty", core.String("EC"))), encoded), method(core.Object(core.M("kty", core.String("OKP")), core.M("crv", core.String("Ed25519")), core.M("x", core.String("bad"))), encoded)} {
		if selectedMaterial(m) != core.NotSupported {
			t.Fatal(m)
		}
	}
	if selectedAlg(core.Object(core.M("type", core.String("Other")))) != core.NotSupported || selectedAlg(core.Object(core.M("type", core.String("JsonWebKey")))) != core.NotApplicable || selectedAlg(core.Object(core.M("type", core.String("JsonWebKey")), core.M("publicKeyJwk", core.Null()))) != core.Fail {
		t.Fatal("JWK applicability")
	}
}

func TestKeyFieldsRejectAnyErrorPresenceAndUnknownEmbeddedMethods(t *testing.T) {
	for _, value := range []string{`null`, `{}`, `""`, `{"type":"https://www.w3.org/ns/did#INTERNAL_ERROR"}`} {
		r := nativeSchemaFixture("did-1.1")
		r.Metadata = json.RawMessage(`{"contentType":"application/did","error":` + value + `}`)
		for _, obs := range judgeKeyFields(r, "unit") {
			if obs.Verdict != core.Error {
				t.Fatal(obs)
			}
		}
	}
	r := nativeSchemaFixture("did-1.1")
	r.Snapshot = json.RawMessage(strings.Replace(string(r.Snapshot), `"authentication":["did:sage:web:x:a#sign"]`, `"authentication":[{"id":"did:example:x#other","type":"Other","controller":"did:example:x"}]`, 1))
	obs := judgeKeyFields(r, "unit")
	if obs[1].Verdict != core.NotSupported {
		t.Fatal("unknown embedded material became PASS", obs)
	}
}
