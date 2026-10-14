package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"net"
	"net/url"
	"reflect"
)

var routingBindingIDs = []string{"res10-crd20261001#bindings-https.35", "res10-crd20261001#bindings-https.36", "res10-crd20261001#bindings-https.37", "res10-crd20261001#bindings-https.38"}

func routingBindingFixture() routingFixture {
	for _, f := range routingFixtures() {
		if f.Name == "service-urls" {
			return f
		}
	}
	panic("missing independent service endpoint list fixture")
}
func judgeRoutingBinding(q RoutingRequest, verb string, out RoutingBindingResult, input string) []core.Observation {
	obs := libraryUnavailable(routingBindingIDs, core.Error, "Actual pinned root dereferencer and universal handler, configured with a literal did:example document, called over owned loopback TLS. The actual delegate invocation/output and raw HTTP response are retained separately. Redirects are disabled and public endpoint literals are never contacted. This selected HTTP binding does not establish SAGE registry/authority or production ingress.", input, out)
	f := routingBindingFixture()
	if !reflect.DeepEqual(q, routingRequest(f)) || !reflect.DeepEqual(out.Request, q) || out.Method != verb || out.Role != "owned TLS universal handler with actual root dereferencer and literal example driver; not SAGE registry" || out.CaptureError != "" || len(out.Native) != 1 {
		return obs
	}
	req, e := checks.BindingRequest(verb, q.Request.Input, q.Request.Accept, nil)
	if e != nil {
		return obs
	}
	x := out.Exchange
	u, e := url.Parse(x.URL)
	if e != nil || !x.TLS || u.Scheme != "https" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.Fragment != "" || x.Method != verb || !reflect.DeepEqual(x.RequestHeader, req.Header) || string(x.RequestBody) != string(req.Body) {
		return obs
	}
	if u.RequestURI() != "/1.0/identifiers/"+req.Target {
		return obs
	}
	n := out.Native[0]
	options, e := parse(n.Options)
	if e != nil || n.CaptureError != "" || n.Function != "dereference" || n.Input != q.Request.Input {
		return obs
	}
	accept, _ := options.Get("accept")
	if accept.Str != "text/uri-list" {
		return obs
	}
	md, e := parse(n.Result.Metadata)
	v, e2 := core.ParseJSON(n.Result.Raw)
	if e != nil || e2 != nil {
		return obs
	}
	ct, _ := md.Get("contentType")
	_, failed := md.Get("error")
	want, _ := core.ParseJSON(f.Content)
	if failed || !n.Result.HasContent || ct.Str != "text/uri-list" || !equalObserved(v, want, "metadata") {
		return obs
	}
	selected := false
	for _, endpoint := range want.Array {
		if endpoint.Kind == core.KindString && endpoint.Str == x.Header.Get("Location") {
			selected = true
		}
	}
	predicates := []bool{x.Status == 303 && selected && len(x.Body) == 0, x.Status == 303, selected, len(x.Body) == 0}
	for i := range obs {
		obs[i].Verdict = core.Fail
		if predicates[i] {
			obs[i].Verdict = core.Pass
		}
		obs[i].Expected = "303, independently selected Location, and empty body for actual successful text/uri-list dereference"
	}
	return obs
}
func appendRoutingBindingCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	q := routingRequest(routingBindingFixture())
	for _, verb := range []string{"GET", "POST"} {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-binding-uri-list-" + verb, Profile: p.Name, Statements: routingBindingIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Request RoutingRequest
				Method  string
			}{q, verb})
			s, ok := target.(RoutingBindingSubject)
			if !ok {
				return libraryUnavailable(routingBindingIDs, core.NotSupported, "no owned routing HTTP observer", string(input), nil)
			}
			out, e := s.InspectRoutingBinding(ctx, q, verb)
			if e != nil {
				return libraryUnavailable(routingBindingIDs, core.Error, e.Error(), string(input), out)
			}
			return judgeRoutingBinding(q, verb, out, string(input))
		}})
	}
}
