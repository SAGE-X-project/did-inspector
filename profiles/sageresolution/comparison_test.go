package sageresolution

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func comparisonFixture() Result {
	r := native()
	r.ContentKind = "document"
	r.Metadata = json.RawMessage(`{"contentType":"application/did+json"}`)
	r.ContentMetadata = json.RawMessage(`{"versionId":"7","sage":{"state":"active","observedTime":1800000000}}`)
	r.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a","verificationMethod":[{"id":"did:sage:web:x:a#sign","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"public-fixture"}}],"authentication":["did:sage:web:x:a#sign"],"service":[{"id":"#a2a","type":"A2AInterface","serviceEndpoint":"https://example.org/a2a"}]}`)
	body := []byte(`{"didResolutionMetadata":` + string(r.Metadata) + `,"didDocument":` + string(r.Snapshot) + `,"didDocumentMetadata":` + string(r.ContentMetadata) + `}`)
	ex := core.HTTPExchange{Status: 200, Header: http.Header{"Content-Type": {"application/did-resolution"}}, Body: body}
	return Result{Exchange: &ex, Native: &NativeObservation{Request: Request{Function: "resolve", Input: r.ReturnedID}, Result: &r}}
}
func TestAllNativeAndWireFieldsAreCompared(t *testing.T) {
	w := expected{Check: "http-native-equality", Value: "resolve", Statements: []string{"s"}}
	if obs := judge(comparisonFixture(), []expected{w}, "original"); obs[0].Verdict != core.Pass || obs[0].Input != "original" || !strings.Contains(obs[0].Detail, "All captured content") || strings.Contains(obs[0].Detail, "full document equality and full algorithm conformance are untested") {
		t.Fatal(obs)
	}
	for _, tc := range []struct {
		name   string
		change func(*Result)
		want   core.Verdict
	}{
		{"key", func(o *Result) { o.Native.Result.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a"}`) }, core.Fail},
		{"metadata", func(o *Result) { o.Native.Result.ContentMetadata = json.RawMessage(`{"versionId":"8"}`) }, core.Fail},
		{"media", func(o *Result) { o.Native.Result.Metadata = json.RawMessage(`{"contentType":"application/did"}`) }, core.Fail},
		{"presence", func(o *Result) { o.Native.Result.HasContent = false }, core.Fail},
		{"wire content", func(o *Result) {
			o.Exchange.Body = []byte(`{"didResolutionMetadata":{},"didDocument":null,"didDocumentMetadata":{}}`)
		}, core.Fail},
		{"wire error", func(o *Result) {
			o.Exchange.Body = []byte(`{"didResolutionMetadata":{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}},"didDocument":null,"didDocumentMetadata":{}}`)
		}, core.Fail},
		{"duplicate", func(o *Result) {
			o.Exchange.Body = []byte(`{"didResolutionMetadata":{},"didDocument":{},"didDocument":{},"didDocumentMetadata":{}}`)
		}, core.Error},
		{"native metadata invalid", func(o *Result) { o.Native.Result.Metadata = json.RawMessage(`{`) }, core.Error},
		{"native content metadata invalid", func(o *Result) { o.Native.Result.ContentMetadata = json.RawMessage(`{`) }, core.Error},
		{"native content invalid", func(o *Result) { o.Native.Result.Snapshot = json.RawMessage(`{`) }, core.Error},
		{"native error", func(o *Result) {
			o.Native.Result.Metadata = json.RawMessage(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`)
		}, core.Error},
		{"wrong MIME", func(o *Result) { o.Exchange.Header.Set("Content-Type", "application/did") }, core.Fail},
		{"missing metadata", func(o *Result) { o.Exchange.Body = []byte(`{"didDocument":{}}`) }, core.Error},
		{"wrong operation", func(o *Result) { o.Native.Request.Function = "dereference" }, core.Error},
		{"missing result", func(o *Result) { o.Native.Result = nil }, core.Error},
		{"missing reference", func(o *Result) { o.Native = nil }, core.Error},
		{"missing wire", func(o *Result) { o.Exchange = nil }, core.Error},
	} {
		o := comparisonFixture()
		tc.change(&o)
		if obs := judge(o, []expected{w}, ""); obs[0].Verdict != tc.want {
			t.Fatal(tc.name, obs)
		}
	}
	o := comparisonFixture()
	o.Native.Request.Function = "unknown"
	if _, err := checkHTTPNative(o, expected{Value: "unknown"}); err == nil {
		t.Fatal("unknown comparison")
	}
	if _, err := checkHTTPNative(comparisonFixture(), expected{}); err == nil {
		t.Fatal("invalid expectation")
	}
}
func TestDeactivatedAndKeyComparisons(t *testing.T) {
	o := comparisonFixture()
	r := o.Native.Result
	r.HasContent = false
	r.Snapshot = nil
	r.Metadata = json.RawMessage(`{}`)
	r.ContentMetadata = json.RawMessage(`{"deactivated":true}`)
	o.Exchange.Body = []byte(`{"didResolutionMetadata":{},"didDocument":null,"didDocumentMetadata":{"deactivated":true}}`)
	if ok, err := checkHTTPNative(o, expected{Value: "resolve"}); err != nil || !ok {
		t.Fatal("deactivated", err)
	}
	o = comparisonFixture()
	o.Native.Request.Function = "dereference"
	o.Native.Result.ContentKind = "verification-method"
	o.Native.Result.Snapshot = json.RawMessage(`{"id":"did:sage:web:x:a#sign","publicKeyJwk":{"kty":"OKP","x":"public-fixture"}}`)
	o.Exchange.Header.Set("Content-Type", "application/did-url-dereferencing")
	o.Exchange.Body = []byte(`{"content":` + string(o.Native.Result.Snapshot) + `,"dereferencingMetadata":` + string(o.Native.Result.Metadata) + `,"contentMetadata":` + string(o.Native.Result.ContentMetadata) + `}`)
	if ok, err := checkHTTPNative(o, expected{Value: "dereference"}); err != nil || !ok {
		t.Fatal("key", err)
	}
	o.Exchange.Header.Set("Content-Type", "application/did-resolution")
	if ok, err := checkHTTPNative(o, expected{Value: "dereference"}); err != nil || ok {
		t.Fatal("wrong key envelope", err)
	}
}
func TestDIDSetsIgnoreOrderButExtensionListsDoNot(t *testing.T) {
	for _, tc := range []struct {
		left, right, kind string
		want              bool
	}{
		{`{"controller":"did:example:1","verificationMethod":[{"id":"#a"},{"id":"#b"}],"authentication":["#a","#b"],"service":[{"id":"#s","type":["A","B"],"serviceEndpoint":["https://a.example","https://b.example"]}]}`, `{"service":[{"serviceEndpoint":["https://b.example","https://a.example"],"type":["B","A"],"id":"#s"}],"authentication":["#b","#a"],"verificationMethod":[{"id":"#b"},{"id":"#a"}],"controller":["did:example:1"]}`, "document", true},
		{`{"proof":[{"n":1.0},{"n":2.0}],"equivalentId":["did:example:1","did:example:2"]}`, `{"proof":[{"n":2e0},{"n":1e0}],"equivalentId":["did:example:2","did:example:1"]}`, "metadata", true},
		{`{"extension":[1,2]}`, `{"extension":[2,1]}`, "document", false},
		{`{"verificationMethod":[{"id":"#a"}]}`, `{"verificationMethod":[{"id":"#a"},{"id":"#a"}]}`, "document", false},
		{`{"authentication":["#a","#b"]}`, `{"authentication":["#a","#a"]}`, "document", false},
		{`{"verificationMethod":[]}`, `{"verificationMethod":{}}`, "document", false},
		{`{"alsoKnownAs":["https://a.example","https://b.example"]}`, `{"alsoKnownAs":["https://b.example","https://a.example"]}`, "document", true},
		{`{"service":[{"type":"A","serviceEndpoint":"https://a.example"}]}`, `{"service":[{"type":["A"],"serviceEndpoint":["https://a.example"]}]}`, "document", true},
		{`{"id":"did:example:1"}`, `{"id":"did:example:1","extra":true}`, "document", false},
		{`{"id":"did:example:1"}`, `{"other":"did:example:1"}`, "document", false},
		{`{"id":"did:example:1"}`, `{"id":7}`, "document", false},
	} {
		a, err := core.ParseJSON([]byte(tc.left))
		if err != nil {
			t.Fatal(err)
		}
		b, err := core.ParseJSON([]byte(tc.right))
		if err != nil {
			t.Fatal(err)
		}
		if equalObserved(a, b, tc.kind) != tc.want {
			t.Fatal(tc)
		}
		if equalObserved(b, a, tc.kind) != tc.want {
			t.Fatal("asymmetric comparison", tc)
		}
	}
}
