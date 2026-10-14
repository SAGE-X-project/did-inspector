package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"net/http"
	"testing"
)

func bindingControl(verb string) RoutingBindingResult {
	f := routingBindingFixture()
	q := routingRequest(f)
	req, _ := checks.BindingRequest(verb, q.Request.Input, q.Request.Accept, nil)
	return RoutingBindingResult{Request: q, Method: verb, Role: "owned TLS universal handler with actual root dereferencer and literal example driver; not SAGE registry", Native: []ClientInvocation{{Function: "dereference", Input: q.Request.Input, Options: []byte(`{"accept":"text/uri-list"}`), Result: Result{Metadata: []byte(`{"contentType":"text/uri-list"}`), ContentMetadata: []byte(`{"contentType":"text/uri-list"}`), HasContent: true, Raw: append([]byte(nil), f.Content...)}}}, Exchange: core.HTTPExchange{Method: verb, URL: "https://127.0.0.1:1234/1.0/identifiers/" + req.Target, RequestHeader: req.Header, RequestBody: req.Body, TLS: true, Status: 303, Header: http.Header{"Location": []string{"https://agent.example/base/"}}}}
}
func TestRoutingBindingControlsAndGuards(t *testing.T) {
	for _, verb := range []string{"GET", "POST"} {
		q := routingRequest(routingBindingFixture())
		for _, o := range judgeRoutingBinding(q, verb, bindingControl(verb), "input") {
			if o.Verdict != core.Pass {
				t.Fatal(o)
			}
		}
		for _, change := range []func(*RoutingBindingResult){func(r *RoutingBindingResult) { r.Request.Request.Input = "other" }, func(r *RoutingBindingResult) { r.Method = "other" }, func(r *RoutingBindingResult) { r.Role = "other" }, func(r *RoutingBindingResult) { r.CaptureError = "lost" }, func(r *RoutingBindingResult) { r.Native = nil }, func(r *RoutingBindingResult) { r.Exchange.URL = "bad" }, func(r *RoutingBindingResult) { r.Exchange.URL = "https://external.example/" }, func(r *RoutingBindingResult) { r.Exchange.URL = "https://127.0.0.1:1234/other" }, func(r *RoutingBindingResult) { r.Exchange.TLS = false }, func(r *RoutingBindingResult) { r.Exchange.Method = "other" }, func(r *RoutingBindingResult) { r.Exchange.RequestHeader = nil }, func(r *RoutingBindingResult) { r.Exchange.RequestBody = []byte("other") }, func(r *RoutingBindingResult) { r.Native[0].Options = []byte(`{`) }, func(r *RoutingBindingResult) { r.Native[0].Options = []byte(`{}`) }, func(r *RoutingBindingResult) { r.Native[0].CaptureError = "lost" }, func(r *RoutingBindingResult) { r.Native[0].Input = "other" }, func(r *RoutingBindingResult) { r.Native[0].Function = "other" }, func(r *RoutingBindingResult) { r.Native[0].Result.Metadata = []byte(`{`) }, func(r *RoutingBindingResult) { r.Native[0].Result.Raw = []byte(`{`) }, func(r *RoutingBindingResult) { r.Native[0].Result.Raw = []byte(`[]`) }, func(r *RoutingBindingResult) { r.Native[0].Result.HasContent = false }, func(r *RoutingBindingResult) {
			r.Native[0].Result.Metadata = []byte(`{"error":{},"contentType":"text/uri-list"}`)
		}} {
			r := bindingControl(verb)
			change(&r)
			for _, o := range judgeRoutingBinding(q, verb, r, "input") {
				if o.Verdict != core.Error {
					t.Fatal("false attribution", o)
				}
			}
		}
		for _, field := range []string{"status", "location", "body"} {
			r := bindingControl(verb)
			switch field {
			case "status":
				r.Exchange.Status = 200
			case "location":
				r.Exchange.Header.Set("Location", "https://other.example/")
			case "body":
				r.Exchange.Body = []byte("nonempty")
			}
			for i, o := range judgeRoutingBinding(q, verb, r, "input") {
				want := core.Pass
				if i == 0 || field == "status" && i == 1 || field == "location" && i == 2 || field == "body" && i == 3 {
					want = core.Fail
				}
				if o.Verdict != want {
					t.Fatal(field, o)
				}
			}
		}
	}
}

type bindingMock struct {
	noOperation
	fail bool
}

func (s bindingMock) InspectRoutingBinding(_ context.Context, _ RoutingRequest, verb string) (RoutingBindingResult, error) {
	if s.fail {
		return RoutingBindingResult{}, errors.New("lost exchange")
	}
	return bindingControl(verb), nil
}
func TestRoutingBindingDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendRoutingBindingCases(&p)
		if name != "did-1.1" && len(p.Cases) > 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{bindingMock{}, core.Pass}, {bindingMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}
