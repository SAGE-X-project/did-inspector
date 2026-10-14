package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"net/http"
	"testing"
)

func cidHTTPControl(verb string) []RoutingBindingResult {
	out := []RoutingBindingResult{}
	for i, q := range cidHTTPRequests() {
		request, _ := checks.BindingRequest(verb, q.Request.Input, q.Request.Accept, map[string]any{"verificationRelationship": "authentication"})
		v := RoutingBindingResult{Request: q, Method: verb, Role: "owned TLS universal handler with actual root dereferencer and literal example driver; not SAGE registry", Native: []ClientInvocation{{Function: "dereference", Input: q.Request.Input, Options: []byte(`{"accept":"application/did","verificationRelationship":"authentication"}`), Result: Result{HasContent: true, Metadata: []byte(`{"contentType":"application/ld+json"}`)}}}, Exchange: core.HTTPExchange{Method: verb, URL: "https://127.0.0.1:1234/1.0/identifiers/" + request.Target, RequestHeader: request.Header, RequestBody: request.Body, TLS: true, Status: 200, Header: http.Header{}}}
		if i == 1 {
			problem := []byte(`{"type":"https://w3id.org/security#INVALID_VERIFICATION_METHOD","title":"Invalid verification method","status":400,"detail":"public CID refusal"}`)
			md, _ := json.Marshal(map[string]json.RawMessage{"error": problem})
			v.Native[0].Result = Result{Metadata: md, Raw: []byte(`null`), ContentMetadata: []byte(`{}`)}
			v.Exchange.Status = 400
			v.Exchange.Header.Set("Content-Type", "application/problem+json")
			v.Exchange.Body = problem
		}
		out = append(out, v)
	}
	return out
}
func TestCIDHTTPControls(t *testing.T) {
	for _, verb := range []string{"GET", "POST"} {
		if judgeCIDHTTP(verb, cidHTTPControl(verb), "input")[0].Verdict != core.Pass {
			t.Fatal(verb)
		}
		for _, change := range []func(*RoutingBindingResult){func(v *RoutingBindingResult) { v.Request.Request.Input = "other" }, func(v *RoutingBindingResult) { v.Method = "other" }, func(v *RoutingBindingResult) { v.Role = "other" }, func(v *RoutingBindingResult) { v.CaptureError = "lost" }, func(v *RoutingBindingResult) { v.Native = nil }, func(v *RoutingBindingResult) { v.Native[0].Options = []byte(`{`) }, func(v *RoutingBindingResult) { v.Native[0].Options = []byte(`{}`) }, func(v *RoutingBindingResult) { v.Native[0].Input = "other" }, func(v *RoutingBindingResult) { v.Native[0].Function = "other" }, func(v *RoutingBindingResult) { v.Native[0].CaptureError = "lost" }, func(v *RoutingBindingResult) { v.Exchange.URL = "https://external.example/" }, func(v *RoutingBindingResult) { v.Exchange.TLS = false }, func(v *RoutingBindingResult) { v.Exchange.Method = "other" }, func(v *RoutingBindingResult) { v.Exchange.RequestHeader = nil }, func(v *RoutingBindingResult) { v.Exchange.RequestBody = []byte(`{}`) }, func(v *RoutingBindingResult) { v.Native[0].Result.HasContent = true }, func(v *RoutingBindingResult) { v.Native[0].Result.Metadata = []byte(`{`) }, func(v *RoutingBindingResult) { v.Native[0].Result.Metadata = []byte(`{"error":null}`) }, func(v *RoutingBindingResult) {
			v.Native[0].Result.Metadata = []byte(`{"error":{"type":"https://example.org/other"}}`)
		}, func(v *RoutingBindingResult) { v.Exchange.Body = []byte(`{`) }} {
			values := cidHTTPControl(verb)
			change(&values[1])
			if judgeCIDHTTP(verb, values, "input")[0].Verdict != core.Error {
				t.Fatal("false attribution")
			}
		}
		for _, change := range []func(*RoutingBindingResult){func(v *RoutingBindingResult) { v.Exchange.Status = 200 }, func(v *RoutingBindingResult) { v.Exchange.Header.Set("Content-Type", "application/json") }, func(v *RoutingBindingResult) {
			v.Exchange.Body = []byte(`{"type":"not a URI reference","status":400,"detail":"public CID refusal"}`)
		}, func(v *RoutingBindingResult) {
			v.Exchange.Body = []byte(`{"type":"https://w3id.org/security#INVALID_VERIFICATION_METHOD","status":"400","detail":"public CID refusal"}`)
		}, func(v *RoutingBindingResult) {
			v.Exchange.Body = []byte(`{"type":"https://w3id.org/security#INVALID_VERIFICATION_METHOD","status":400,"detail":42}`)
		}, func(v *RoutingBindingResult) {
			v.Exchange.Body = []byte(`{"type":"https://w3id.org/security#INVALID_VERIFICATION_METHOD","status":400,"detail":"public CID refusal","title":42}`)
		}} {
			values := cidHTTPControl(verb)
			change(&values[1])
			if judgeCIDHTTP(verb, values, "input")[0].Verdict != core.Fail {
				t.Fatal("invalid problem details")
			}
		}
	}
	if judgeCIDHTTP("bad", nil, "input")[0].Verdict != core.Error {
		t.Fatal("missing calls")
	}
	for _, uri := range []string{"bad", "http://127.0.0.1/", "https://user@127.0.0.1/", "https://127.0.0.1/#frag", "https://external.example/"} {
		if ownedRoutingURL(uri) {
			t.Fatal("not owned")
		}
	}
	v := cidHTTPControl("GET")
	v[0].Native[0].Result.HasContent = false
	if judgeCIDHTTP("GET", v, "input")[0].Verdict != core.Error {
		t.Fatal("positive missing")
	}
	v = cidHTTPControl("GET")
	v[0].Native[0].Result.Metadata = []byte(`{`)
	if judgeCIDHTTP("GET", v, "input")[0].Verdict != core.Error {
		t.Fatal("lost positive metadata")
	}
}

type cidHTTPMock struct {
	noOperation
	fail bool
}

func (s cidHTTPMock) InspectRoutingBinding(_ context.Context, q RoutingRequest, verb string) (RoutingBindingResult, error) {
	if s.fail {
		return RoutingBindingResult{}, errors.New("lost capture")
	}
	i := 0
	if q.Request.Input == "did:example:123#one" {
		i = 1
	}
	return cidHTTPControl(verb)[i], nil
}
func TestCIDHTTPDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendCIDHTTPCases(&p)
		if name != "did-1.1" && len(p.Cases) > 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{cidHTTPMock{}, core.Pass}, {cidHTTPMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}

func TestRFC9457OptionalMembersAndNumericStatus(t *testing.T) {
	for _, body := range []string{`{}`, `{"type":"https://example.org/other"}`, `{"status":400.0}`, `{"status":4e2}`, `{"detail":"different explanation"}`, `{"instance":"/requests/public-fixture"}`} {
		v := cidHTTPControl("GET")
		v[1].Exchange.Body = []byte(body)
		if judgeCIDHTTP("GET", v, "input")[0].Verdict != core.Pass {
			t.Fatal("valid optional problem members", body)
		}
	}
	for _, s := range []string{"400.1", "400.00000000000000001", "4e999999999999", "4e-999999999999", "0"} {
		if problemStatusMatches(s, 400) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"not a URI", "%0g", "%", "http://[broken", "/bad[uri]", "/path^bad"} {
		if problemURIReference(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "about:blank", "/relative", "https://example.org/fixture", "#part", "?query=one", "%41"} {
		if !problemURIReference(s) {
			t.Fatal("valid URI reference", s)
		}
	}
	v := cidHTTPControl("GET")
	v[1].Exchange.Body = []byte(`{"instance":42}`)
	if judgeCIDHTTP("GET", v, "input")[0].Verdict != core.Fail {
		t.Fatal("bad instance")
	}
}

func TestProblemURIReferenceComponents(t *testing.T) {
	for _, s := range []string{"//example.org:80/a?b=c#part", "https://user:password@example.org/a", "urn:example:fixture", "data:text/plain,value", "http://[::1]:80/", "http://[::ffff:127.0.0.1]/", "scheme://[v1.future]/", "//%61.example/", "a/b:c", "?x=%5Bvalue%5D", "#%5Bpiece%5D", "http:///path"} {
		if !problemURIReference(s) {
			t.Fatal("valid generic URI reference", s)
		}
	}
	for _, s := range []string{"https://host/?q=[bad]", "#bad[fragment]", "http://[not-ip]/", "http://[127.0.0.1]/", "http://[::1]tail/", "http://[::1]:port/", "http://host:bad/", "http://a@b@host/", "123:bad", "a#b#c", "?bad%g0", "//un[bracketed]/"} {
		if problemURIReference(s) {
			t.Fatal("invalid URI reference", s)
		}
	}
	v := cidHTTPControl("GET")
	v[1].Exchange.Status = 200
	v[1].Exchange.Body = []byte(`{"status":200}`)
	if judgeCIDHTTP("GET", v, "input")[0].Verdict != core.Pass {
		t.Fatal("RFC9457 allows problem details with any valid HTTP status; separate binding duties remain separate")
	}
}
