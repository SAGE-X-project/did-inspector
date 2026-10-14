package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"math/big"
	"mime"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func cidHTTPRequests() []RoutingRequest {
	f := routingFixtures()[0]
	var doc map[string]any
	_ = json.Unmarshal(f.Document, &doc)
	doc["authentication"] = []string{"did:example:123#sign"}
	body, _ := json.Marshal(doc)
	qs := []RoutingRequest{}
	for _, fragment := range []string{"sign", "one"} {
		qs = append(qs, RoutingRequest{Document: ConsumptionRequest{Data: body, MediaType: "application/did"}, Request: Request{Function: "dereference", Input: "did:example:123#" + fragment, Accept: "application/did", Relationship: "authentication"}})
	}
	return qs
}
func judgeCIDHTTP(verb string, values []RoutingBindingResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{"cid10#processing-errors.1"}, core.Error, "The actual selected document.SelectMethod CID error is mapped by the pinned dereferencer into its native error result and exposed by the actual universal Handler over owned TLS. Public known-method and non-method service-fragment controls share one literal example document. This establishes the selected INVALID_VERIFICATION_METHOD HTTP error representation, not every CID error, SAGE registry authority, production ingress or proof validity.", input, values)
	qs := cidHTTPRequests()
	if len(values) != 2 || (verb != "GET" && verb != "POST") {
		return obs
	}
	for i, v := range values {
		q := qs[i]
		if !reflect.DeepEqual(v.Request, q) || v.Method != verb || v.Role != "owned TLS universal handler with actual root dereferencer and literal example driver; not SAGE registry" || v.CaptureError != "" || len(v.Native) != 1 {
			return obs
		}
		n := v.Native[0]
		opts, e := parse(n.Options)
		if e != nil || n.CaptureError != "" || n.Function != "dereference" || n.Input != q.Request.Input {
			return obs
		}
		want := core.Object(core.M("accept", core.String("application/did")), core.M("verificationRelationship", core.String("authentication")))
		if !equalObserved(opts.Value(), want, "metadata") {
			return obs
		}
		request, e := checks.BindingRequest(verb, q.Request.Input, q.Request.Accept, map[string]any{"verificationRelationship": "authentication"})
		if e != nil || v.Exchange.Method != verb || !v.Exchange.TLS || !strings.HasSuffix(v.Exchange.URL, "/1.0/identifiers/"+request.Target) || !reflect.DeepEqual(v.Exchange.RequestHeader, request.Header) || string(v.Exchange.RequestBody) != string(request.Body) {
			return obs
		}
		if !ownedRoutingURL(v.Exchange.URL) {
			return obs
		}
	}
	good, bad := values[0], values[1]
	if !good.Native[0].Result.HasContent || good.Exchange.Status != 200 {
		return obs
	}
	gm, e := parse(good.Native[0].Result.Metadata)
	if e != nil {
		return obs
	}
	if _, failed := gm.Get("error"); failed {
		return obs
	}
	md, e := parse(bad.Native[0].Result.Metadata)
	if e != nil || !nativeErrorDescriptor(md) || bad.Native[0].Result.HasContent {
		return obs
	}
	native, _ := md.Get("error")
	typ, _ := native.Get("type")
	if typ.Str != "https://w3id.org/security#INVALID_VERIFICATION_METHOD" {
		return obs
	}
	problem, e := parse(bad.Exchange.Body)
	if e != nil {
		return obs
	}
	pt, typePresent := problem.Get("type")
	status, statusPresent := problem.Get("status")
	detail, detailPresent := problem.Get("detail")
	title, titlePresent := problem.Get("title")
	instance, instancePresent := problem.Get("instance")
	ct, _, ctError := mime.ParseMediaType(bad.Exchange.Header.Get("Content-Type"))
	pass := ctError == nil && ct == "application/problem+json" && bad.Exchange.Status >= 100 && bad.Exchange.Status <= 599 && (!typePresent || (pt.Kind == core.KindString && problemURIReference(pt.Str))) && (!titlePresent || title.Kind == core.KindString) && (!detailPresent || detail.Kind == core.KindString) && (!instancePresent || (instance.Kind == core.KindString && problemURIReference(instance.Str))) && (!statusPresent || (status.Kind == core.KindNumber && problemStatusMatches(status.Number, bad.Exchange.Status)))
	nd, _ := native.Get("detail")
	obs[0].Detail += fmt.Sprintf(" Native type/detail preservation diagnostic (separate from RFC9457 optional-member validity): %t.", typePresent && pt.Kind == core.KindString && pt.Str == typ.Str && detailPresent && detail.Kind == core.KindString && detail.Str == nd.Str)
	obs[0].Verdict = core.Fail
	if pass {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "RFC9457 object and media type; optional standard members are checked only when present, with HTTP status consistency"
	return obs
}
func problemURIReference(s string) bool {
	// Validate RFC3986 components without retrieval or a WHATWG URL coercion.
	if !regexp.MustCompile(`^[A-Za-z0-9\-._~:/?\[\]@!$&'()*+,;=%#]*$`).MatchString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return false
			}
			if _, e := strconv.ParseUint(s[i+1:i+3], 16, 8); e != nil {
				return false
			}
			i += 2
		}
	}
	head, fragment, hasFragment := strings.Cut(s, "#")
	if hasFragment && !problemComponent(fragment, true) {
		return false
	}
	head, query, hasQuery := strings.Cut(head, "?")
	if hasQuery && !problemComponent(query, true) {
		return false
	}
	hasScheme := false
	if colon := strings.IndexByte(head, ':'); colon >= 0 && (strings.IndexByte(head, '/') < 0 || colon < strings.IndexByte(head, '/')) {
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`).MatchString(head[:colon]) {
			return false
		}
		hasScheme = true
		head = head[colon+1:]
	}
	if strings.HasPrefix(head, "//") {
		authority, path, _ := strings.Cut(head[2:], "/")
		if !problemAuthority(authority) {
			return false
		}
		return problemComponent(path, false)
	}
	if !hasScheme {
		first, _, _ := strings.Cut(head, "/")
		if strings.Contains(first, ":") {
			return false
		}
	}
	return problemComponent(head, false)
}
func problemComponent(s string, query bool) bool {
	pattern := `^[A-Za-z0-9\-._~:@!$&'()*+,;=%/]*$`
	if query {
		pattern = `^[A-Za-z0-9\-._~:@!$&'()*+,;=%/?]*$`
	}
	return regexp.MustCompile(pattern).MatchString(s)
}
func problemAuthority(s string) bool {
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		if !regexp.MustCompile(`^[A-Za-z0-9\-._~:!$&'()*+,;=%]*$`).MatchString(s[:at]) {
			return false
		}
		s = s[at+1:]
	}
	port := ""
	if strings.HasPrefix(s, "[") {
		host, tail, closed := strings.Cut(s[1:], "]")
		if !closed {
			return false
		}
		if (!strings.Contains(host, ":") || net.ParseIP(host) == nil) && !regexp.MustCompile(`^[vV][A-Fa-f0-9]+\.[A-Za-z0-9\-._~:!$&'()*+,;=]+$`).MatchString(host) {
			return false
		}
		if tail != "" {
			var hasPort bool
			port, hasPort = strings.CutPrefix(tail, ":")
			if !hasPort {
				return false
			}
		}
	} else {
		host, p, hasPort := strings.Cut(s, ":")
		if hasPort {
			port = p
		}
		if !regexp.MustCompile(`^[A-Za-z0-9\-._~!$&'()*+,;=%]*$`).MatchString(host) {
			return false
		}
	}
	return regexp.MustCompile(`^[0-9]*$`).MatchString(port)
}

func problemStatusMatches(s string, status int) bool {
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent, e := strconv.Atoi(s[i+1:])
		if e != nil || exponent > len(s)+3 || exponent < -(len(s)+3) {
			return false
		}
	}
	value, ok := new(big.Rat).SetString(s)
	return ok && value.Cmp(big.NewRat(int64(status), 1)) == 0
}

func ownedRoutingURL(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}
func appendCIDHTTPCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, verb := range []string{"GET", "POST"} {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-cid-http-" + verb, Profile: p.Name, Statements: []string{"cid10#processing-errors.1"}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			qs := cidHTTPRequests()
			input, _ := json.Marshal(struct {
				Requests []RoutingRequest
				Method   string
			}{qs, verb})
			s, ok := target.(RoutingBindingSubject)
			if !ok {
				return libraryUnavailable([]string{"cid10#processing-errors.1"}, core.NotSupported, "no actual owned CID error binding", string(input), nil)
			}
			values := []RoutingBindingResult{}
			for _, q := range qs {
				v, e := s.InspectRoutingBinding(ctx, q, verb)
				values = append(values, v)
				if e != nil {
					return libraryUnavailable([]string{"cid10#processing-errors.1"}, core.Error, e.Error(), string(input), values)
				}
			}
			return judgeCIDHTTP(verb, values, string(input))
		}})
	}
}
