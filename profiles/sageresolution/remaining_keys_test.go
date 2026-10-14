package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

const nativeRemainingKeyDoc = `{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[{"id":"did:sage:web:registry.example:agent-1#sign","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}},{"id":"did:sage:web:registry.example:agent-1#agree","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"X25519","x":"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}],"authentication":["did:sage:web:registry.example:agent-1#sign"],"keyAgreement":["did:sage:web:registry.example:agent-1#agree"]}`

func nativeRemainingKeyControl() Result {
	return Result{Metadata: []byte(`{"contentType":"application/did"}`), ContentMetadata: []byte(`{}`), HasContent: true, ReturnedID: policyDID, ContentKind: "document", Raw: []byte(nativeRemainingKeyDoc)}
}
func TestCompleteSelectedPublicJWK(t *testing.T) {
	var d map[string]any
	_ = json.Unmarshal([]byte(policyBase), &d)
	m := d["verificationMethod"].([]any)[0].(map[string]any)
	for _, tt := range []struct {
		change func(map[string]any)
		want   core.Verdict
	}{
		{func(m map[string]any) {}, core.Pass}, {func(m map[string]any) { m["id"] = 42 }, core.Fail}, {func(m map[string]any) { m["id"] = "not-did-url" }, core.Fail}, {func(m map[string]any) { m["controller"] = "https://example.org" }, core.Fail}, {func(m map[string]any) { m["type"] = 42 }, core.Fail}, {func(m map[string]any) { m["type"] = "Other" }, core.NotSupported}, {func(m map[string]any) { delete(m, "publicKeyJwk") }, core.NotSupported},
		{func(m map[string]any) { m["extra"] = true }, core.NotSupported}, {func(m map[string]any) { m["publicKeyJwk"] = true }, core.Fail},
		{func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["d"] = "public negative fixture" }, core.Fail}, {func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["extension"] = true }, core.NotSupported},
		{func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["kty"] = "EC" }, core.Fail}, {func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["crv"] = 42 }, core.Fail}, {func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["crv"] = "Ed448" }, core.NotSupported},
		{func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["x"] = "AA" }, core.Fail}, {func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["x"] = "invalid=" }, core.Fail}, {func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["x"] = 42 }, core.Fail},
		{func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["kid"] = 42 }, core.Fail}, {func(m map[string]any) { m["publicKeyJwk"].(map[string]any)["alg"] = 42 }, core.Fail},
	} {
		b, _ := json.Marshal(m)
		var x map[string]any
		_ = json.Unmarshal(b, &x)
		tt.change(x)
		b, _ = json.Marshal(x)
		v, _ := core.ParseJSON(b)
		if completeSelectedPublicJWK(v) != tt.want {
			t.Fatal(string(b), tt.want)
		}
	}
	if completeSelectedPublicJWK(core.Null()) != core.Fail {
		t.Fatal("nonmap")
	}
}
func TestRemainingKeyAttributionAndRecommendations(t *testing.T) {
	out := nativeRemainingKeyControl()
	expected := map[string]core.Verdict{"cid10#JsonWebKey.5": core.Fail, "cid10#JsonWebKey.6": core.NotApplicable, "cid10#JsonWebKey.9": core.NotApplicable, "cid10#data-model.1": core.Pass, "did11-cr20260305#verification-methods.1": core.Pass}
	for _, o := range judgeRemainingNativeKeys(out, "input") {
		if o.Verdict != expected[o.Statement] {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	for _, change := range []func(*Result){func(r *Result) { r.HasContent = false }, func(r *Result) { r.ReturnedID = "other" }, func(r *Result) { r.ContentKind = "other" }, func(r *Result) { r.Metadata = []byte(`{`) }, func(r *Result) { r.Metadata = []byte(`{"error":{}}`) }, func(r *Result) { r.Raw = []byte(`{`) }, func(r *Result) { r.Raw = []byte(`{}`) }, func(r *Result) { r.Raw = []byte(`{"verificationMethod":true}`) }, func(r *Result) { r.Raw = []byte(`{"verificationMethod":[{}]}`) }} {
		r := nativeRemainingKeyControl()
		change(&r)
		for _, o := range judgeRemainingNativeKeys(r, "input") {
			if o.Verdict != core.Error {
				t.Fatal("false attribution")
			}
		}
	}
	for _, field := range []string{"kid", "type", "controller", "authentication"} {
		r := nativeRemainingKeyControl()
		var d map[string]any
		_ = json.Unmarshal(r.Raw, &d)
		m := d["verificationMethod"].([]any)[0].(map[string]any)
		switch field {
		case "kid":
			m["publicKeyJwk"].(map[string]any)["kid"] = "sign"
		case "type":
			m["type"] = "Other"
		case "controller":
			m["controller"] = "https://example.org"
		case "authentication":
			d["authentication"] = []any{}
		}
		r.Raw, _ = json.Marshal(d)
		obs := judgeRemainingNativeKeys(r, "input")
		for _, o := range obs {
			if field == "kid" && (o.Statement == "cid10#JsonWebKey.6" || o.Statement == "cid10#JsonWebKey.9") && o.Verdict != core.NotSupported {
				t.Fatal("fixture kid became producer policy PASS")
			}
			if field == "authentication" && o.Statement == "cid10#data-model.1" && o.Verdict != core.Fail {
				t.Fatal(o)
			}
			if field == "type" && o.Statement == "did11-cr20260305#verification-methods.1" && o.Verdict != core.NotSupported {
				t.Fatal(o)
			}
			if field == "controller" && o.Statement == "did11-cr20260305#verification-methods.1" && o.Verdict != core.Fail {
				t.Fatal(o)
			}
		}
	}
}

type remainingNativeKeyMock struct {
	noOperation
	fail bool
}

func (s remainingNativeKeyMock) InspectResolution(context.Context, sageprojection.Record, Request) (Result, error) {
	out := nativeRemainingKeyControl()
	if s.fail {
		return out, errors.New("adapter failed")
	}
	return out, nil
}
func TestRemainingNativeKeyDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendRemainingNativeKeyCases(&p, records)
		want := 1
		if name != "did-1.1" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s    core.Subject
				want core.Verdict
			}{{remainingNativeKeyMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.want || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
			if c.Run(t.Context(), remainingNativeKeyMock{})[0].Verdict != core.Fail {
				t.Fatal("actual native kid outcome")
			}
		}
	}
}

func TestRemainingCompositePreservesNormativeFailures(t *testing.T) {
	for _, field := range []string{"id", "x", "controller"} {
		for _, reverse := range []bool{false, true} {
			r := nativeRemainingKeyControl()
			var d map[string]any
			_ = json.Unmarshal(r.Raw, &d)
			ms := d["verificationMethod"].([]any)
			m := ms[0].(map[string]any)
			if field == "x" {
				m["publicKeyJwk"].(map[string]any)["x"] = 42
			} else {
				m[field] = 42
			}
			ms[1].(map[string]any)["type"] = "Other"
			if reverse {
				ms[0], ms[1] = ms[1], ms[0]
			}
			r.Raw, _ = json.Marshal(d)
			for _, o := range judgeRemainingNativeKeys(r, "input") {
				if o.Statement == "did11-cr20260305#verification-methods.1" && o.Verdict != core.Fail {
					t.Fatal(field, reverse, o)
				}
			}
		}
	}
	r := nativeRemainingKeyControl()
	var d map[string]any
	_ = json.Unmarshal(r.Raw, &d)
	ms := d["verificationMethod"].([]any)
	ms[1] = ms[0]
	r.Raw, _ = json.Marshal(d)
	for _, o := range judgeRemainingNativeKeys(r, "input") {
		if o.Verdict == core.Pass {
			t.Fatal("duplicate input role falsely attributed", o)
		}
	}
}
