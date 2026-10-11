package kit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// bindingFake answers binding requests from a table keyed by target and
// Accept header.
type bindingFake struct {
	fake
	endpoint string
	answers  map[string]core.HTTPExchange
	err      error
	sent     []core.HTTPRequest
}

func (b *bindingFake) Endpoint() string { return b.endpoint }

func (b *bindingFake) Exchange(_ context.Context, req core.HTTPRequest) (core.HTTPExchange, error) {
	b.sent = append(b.sent, req)
	if b.err != nil {
		return core.HTTPExchange{}, b.err
	}
	ex, ok := b.answers[req.Method+" "+req.Target+" "+req.Header.Get("Accept")]
	if !ok {
		return core.HTTPExchange{Status: http.StatusTeapot, TLS: true}, nil
	}
	return ex, nil
}

func answer(status int, ct, body string, extra ...string) core.HTTPExchange {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		h.Add(extra[i], extra[i+1])
	}
	return core.HTTPExchange{Status: status, Header: h, Body: []byte(body), TLS: true}
}

const (
	fullResult  = `{"didDocument":{"@context":"x","id":"did:example:1"},"didResolutionMetadata":{"contentType":"application/did"},"didDocumentMetadata":{"versionId":"1"}}`
	derefResult = `{"content":{"id":"did:example:1#k"},"dereferencingMetadata":{"contentType":"application/did"},"contentMetadata":{"deactivated":true}}`
)

func TestBindingRequestHelpers(t *testing.T) {
	b := BindingRequest{Function: FnDereference, Input: "did:example:1", Accept: "x/y", Options: map[string]any{"a": "b"}}
	if b.method() != http.MethodGet || b.accept() != "x/y" || b.full().accept() != "application/did-url-dereferencing" {
		t.Fatalf("helpers = %s %s", b.method(), b.full().accept())
	}
	if (BindingRequest{Function: FnResolve}).accept() != "application/did-resolution" {
		t.Fatal("resolution accept")
	}
	if !strings.Contains(b.describe(), `GET dereference(did:example:1) Accept: x/y options {"a":"b"}`) {
		t.Fatalf("describe = %s", b.describe())
	}
	f := &bindingFake{}
	if _, err := Exchange(ctx, f, BindingRequest{Method: "PUT", Input: "x"}); err == nil {
		t.Fatal("PUT sent")
	}
	if !EndpointIsHTTPS("https://x/") || EndpointIsHTTPS("http://x/") || EndpointIsHTTPS("::") {
		t.Fatal("EndpointIsHTTPS")
	}
}

func TestBindingChecks(t *testing.T) {
	res := BindingRequest{Function: FnResolve, Input: "did:example:1"}
	der := BindingRequest{Function: FnDereference, Input: "did:example:1#k"}
	full := answer(200, "application/did-resolution", fullResult)
	dfull := answer(410, "application/did-url-dereferencing", derefResult)
	repr := answer(200, "application/did", `{"id":"did:example:1"}`)
	type tc struct {
		check string
		o     BindingOutcome
		value string
		want  bool
	}
	cases := []tc{
		{"status", BindingOutcome{Ex: repr}, `200`, true},
		{"status", BindingOutcome{Ex: repr}, `[404, 410]`, false},
		{"contentType", BindingOutcome{Ex: repr}, `"application/did"`, true},
		{"contentType", BindingOutcome{Ex: repr}, `"text/plain"`, false},
		{"contentTypeOfResult", BindingOutcome{Request: res, Ex: repr, Full: &full}, ``, true},
		{"contentTypeOfResult", BindingOutcome{Request: res, Ex: answer(200, "application/json", "{}"), Full: &full}, ``, false},
		{"contentTypeOfResult", BindingOutcome{Request: res, Ex: repr}, ``, false},
		{"contentTypeOfResult", BindingOutcome{Request: res, Ex: repr, Full: &repr}, ``, false},
		{"contentTypeOfResult", BindingOutcome{Request: der, Ex: repr, Full: ptr(answer(200, "", `{"content":null,"dereferencingMetadata":{},"contentMetadata":{"contentType":"application/did"}}`))}, ``, true},
		{"contentTypeOfResult", BindingOutcome{Request: der, Ex: repr, Full: ptr(answer(200, "", `{"content":null,"dereferencingMetadata":{},"contentMetadata":{}}`))}, ``, false},
		{"resolutionResult", BindingOutcome{Request: res, Ex: full}, ``, true},
		{"resolutionResult", BindingOutcome{Request: res, Ex: repr}, ``, false},
		{"resolutionResult", BindingOutcome{Request: res, Ex: answer(200, "application/did-resolution", `{}`)}, ``, false},
		{"dereferencingResult", BindingOutcome{Request: der, Ex: dfull}, ``, true},
		{"resultContent", BindingOutcome{Request: res, Ex: full}, `{"id":"did:example:1"}`, true},
		{"resultContent", BindingOutcome{Request: res, Ex: full}, `{"id":"did:example:2"}`, false},
		{"resultContent", BindingOutcome{Request: res, Ex: repr}, `{"id":"did:example:1"}`, false},
		{"resultContent", BindingOutcome{Request: der, Ex: answer(200, "", `{"content":"text","dereferencingMetadata":{},"contentMetadata":{}}`)}, `{}`, false},
		{"resultContent", BindingOutcome{Request: der, Ex: dfull}, `{"id":"#k"}`, true},
		{"resultMetadataHas", BindingOutcome{Request: res, Ex: full}, `{"versionId":"1"}`, true},
		{"resultMetadataHas", BindingOutcome{Request: res, Ex: full}, `{"versionId":"2"}`, false},
		{"resultMetadataHas", BindingOutcome{Request: res, Ex: repr}, `{"versionId":"1"}`, false},
		{"bodyDocument", BindingOutcome{Ex: repr}, `{"@context":"y","id":"did:example:1"}`, true},
		{"bodyDocument", BindingOutcome{Ex: repr}, `{"id":"did:example:2"}`, false},
		{"bodyDocument", BindingOutcome{Ex: answer(200, "", "[]")}, `{}`, false},
		{"bodyMatchesResult", BindingOutcome{Request: res, Ex: answer(200, "", `{"@context":"x","id":"did:example:1"}`), Full: &full}, ``, true},
		{"bodyMatchesResult", BindingOutcome{Request: res, Ex: repr, Full: &full}, ``, false},
		{"bodyMatchesResult", BindingOutcome{Request: res, Ex: answer(200, "", "nope"), Full: &full}, ``, false},
		{"bodyMatchesResult", BindingOutcome{Request: res, Ex: repr}, ``, false},
		{"location", BindingOutcome{Ex: answer(303, "", "", "Location", "https://a/")}, `"https://a/"`, true},
		{"location", BindingOutcome{Ex: answer(303, "", "")}, `"https://a/"`, false},
		{"emptyBody", BindingOutcome{Ex: answer(303, "", "")}, ``, true},
		{"emptyBody", BindingOutcome{Ex: repr}, ``, false},
		{"problemDetails", BindingOutcome{Ex: answer(404, "application/problem+json", `{"type":"https://www.w3.org/ns/did#NOT_FOUND"}`)}, ``, true},
		{"problemDetails", BindingOutcome{Ex: answer(404, "application/problem+json", `{"type":"NOT_FOUND"}`)}, ``, false},
		{"problemDetails", BindingOutcome{Ex: answer(404, "application/problem+json", `[]`)}, ``, false},
		{"problemDetails", BindingOutcome{Ex: answer(404, "text/plain", `x`)}, ``, false},
	}
	for i, c := range cases {
		ok, exp, obs := BindingChecks[c.check](c.o, raw(c.value))
		if ok != c.want {
			t.Errorf("%d %s(%s) = %v (%s / %s), want %v", i, c.check, c.value, ok, exp, obs, c.want)
		}
		if !ok && exp == "" {
			t.Errorf("%d %s: failure without expected value", i, c.check)
		}
	}
	if s := (BindingOutcome{Ex: repr}).Summary(); !strings.Contains(s, "status 200") {
		t.Errorf("summary %s", s)
	}
}

func ptr(ex core.HTTPExchange) *core.HTTPExchange { return &ex }

func TestBindingCases(t *testing.T) {
	reg := &fixtures.Registry{Format: fixtures.Format, Method: fixtures.Method}
	file := BindingFile{
		Exchanges: []BindingScenario{
			{Case: "get", BindingRequest: BindingRequest{Function: FnResolve, Input: "did:example:1"}, Expect: []Expectation{
				{Check: "status", Value: raw("200"), Statements: []string{"k#1"}},
				{Check: "resolutionResult", Statements: []string{"k#2"}, Partial: "part"},
				{Check: "nosuch", Statements: []string{"k#3"}},
			}},
			{Case: "repr", BindingRequest: BindingRequest{Function: FnResolve, Input: "did:example:1", Accept: "application/did"}, Compare: true,
				Expect: []Expectation{{Check: "contentTypeOfResult", Statements: []string{"k#4"}}, {Check: "status", Value: raw("404"), Statements: []string{"k#5"}}}},
			{Case: "post", BindingRequest: BindingRequest{Function: FnResolve, Method: "POST", Input: "did:example:1"}, UnsupportedIfStatus: []int{405},
				Expect: []Expectation{{Check: "status", Value: raw("200"), Statements: []string{"k#6"}}}},
		},
		Probes: []BindingProbe{{Note: "p", BindingRequest: BindingRequest{Function: FnDereference, Input: "did:example:1#k"}}},
	}
	f := &bindingFake{endpoint: "https://r/", answers: map[string]core.HTTPExchange{
		"GET did:example:1 application/did-resolution":                answer(200, "application/did-resolution", fullResult),
		"GET did:example:1 application/did":                           answer(200, "application/did", `{}`),
		"POST did:example:1 application/did-resolution":               answer(405, "", ""),
		"GET did%3Aexample%3A1%23k application/did-url-dereferencing": answer(410, "application/did-url-dereferencing", derefResult),
	}}
	cases := BindingCases("p", reg, file)
	if len(cases) != 3 || cases[0].ID != "p/binding/get" || cases[0].Needs[1] != core.CapHTTPBinding {
		t.Fatalf("cases = %+v", cases)
	}
	got := map[string]core.Verdict{}
	for _, c := range cases {
		for _, o := range c.Run(ctx, f) {
			got[o.Statement] = o.Verdict
		}
	}
	want := map[string]core.Verdict{"k#1": core.Pass, "k#2": core.Pass, "k#3": core.Error, "k#4": core.Pass, "k#5": core.Fail, "k#6": core.NotSupported}
	for st, v := range want {
		if got[st] != v {
			t.Errorf("%s = %s, want %s", st, got[st], v)
		}
	}
	f.err = errors.New("down")
	if obs := cases[1].Run(ctx, f); obs[0].Verdict != core.Error {
		t.Fatalf("no response: %+v", obs)
	}
	f.err = nil
	invs := []BindingInvariant{
		{Statement: "k#7", Check: func(o BindingOutcome) (bool, bool, string, string) {
			return o.Ex.Status == 410, false, "not 410", "410"
		}},
		{Statement: "k#8", Check: func(BindingOutcome) (bool, bool, string, string) { return false, false, "", "" }},
	}
	ic := BindingInvariantCase("p/binding/inv", "p", reg, invs, file)
	got = map[string]core.Verdict{}
	for _, o := range ic.Run(ctx, f) {
		got[o.Statement] = o.Verdict
	}
	if got["k#7"] != core.Fail || got["k#8"] != core.NotApplicable {
		t.Fatalf("invariants = %v", got)
	}
	var sentRepr, sentFull bool
	for _, r := range f.sent {
		sentRepr = sentRepr || r.Header.Get("Accept") == "application/did"
		sentFull = sentFull || r.Header.Get("Accept") == "application/did-resolution"
	}
	if !sentRepr || !sentFull {
		t.Fatal("comparison request not sent")
	}
	f.err = errors.New("down")
	for _, o := range ic.Run(ctx, f) {
		if o.Verdict != core.NotApplicable {
			t.Fatalf("invariant without responses: %+v", o)
		}
	}
}

func TestValidateBinding(t *testing.T) {
	ok := BindingScenario{Case: "a", BindingRequest: BindingRequest{Function: FnResolve, Input: "x"}, Expect: []Expectation{{Check: "status", Statements: []string{"s"}}}}
	for name, f := range map[string]BindingFile{
		"duplicate":  {Exchanges: []BindingScenario{ok, ok}},
		"no case":    {Exchanges: []BindingScenario{{Expect: ok.Expect}}},
		"no expect":  {Exchanges: []BindingScenario{{Case: "b", BindingRequest: ok.BindingRequest}}},
		"bad check":  {Exchanges: []BindingScenario{{Case: "b", BindingRequest: ok.BindingRequest, Expect: []Expectation{{Check: "x", Statements: []string{"s"}}}}}},
		"no sts":     {Exchanges: []BindingScenario{{Case: "b", BindingRequest: ok.BindingRequest, Expect: []Expectation{{Check: "status"}}}}},
		"bad fn":     {Probes: []BindingProbe{{BindingRequest: BindingRequest{Function: "x"}}}},
		"bad method": {Probes: []BindingProbe{{BindingRequest: BindingRequest{Function: FnResolve, Method: "PUT"}}}},
	} {
		if err := ValidateBinding(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (BindingScenario{Expect: []Expectation{{Statements: []string{"a", "b"}}, {Statements: []string{"b"}}}}).Statements()[1] != "b" {
		t.Error("Statements")
	}
}
