package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
	"testing"
)

func routingControl(f routingFixture) RoutingResult {
	q := routingRequest(f)
	incoming := map[string]any{"accept": f.Request.Accept}
	if f.Request.Relationship != "" {
		incoming["verificationRelationship"] = f.Request.Relationship
	}
	options, _ := json.Marshal(incoming)
	forwarded := map[string]any{}
	for k, v := range f.Forwarded {
		forwarded[k] = v
	}
	if f.Name == "forward-uri-options" {
		delete(forwarded, "accept")
	}
	nested, _ := json.Marshal(forwarded)
	media := ""
	if f.Request.Accept == "application/did" {
		media = "application/did"
	}
	driver, _ := json.Marshal(map[string]any{"VersionID": "", "VersionTime": nil, "MediaType": media, "NoCache": false})
	out := RoutingResult{Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Request: q, Operation: "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference", Options: options, ResolveInputs: []string{"did:example:123"}, ResolveOptions: [][]byte{nested}, DriverOptions: [][]byte{driver}, Entries: []byte(`{}`)}
	if f.ErrorType != "" {
		typ := f.ErrorType
		if typ == "ANY" {
			typ = "INVALID_DID_URL"
		}
		md, _ := json.Marshal(map[string]any{"error": map[string]any{"type": "https://www.w3.org/ns/did#" + typ}})
		out.Result = Result{Metadata: md, ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
	} else {
		md, _ := json.Marshal(map[string]any{"contentType": f.Request.Accept})
		cm := []byte(`{}`)
		var content any
		_ = json.Unmarshal(f.Content, &content)
		if _, ok := content.([]any); ok {
			cm = []byte(`{"contentType":"text/uri-list"}`)
		}
		out.Result = Result{Metadata: md, ContentMetadata: cm, Raw: f.Content, HasContent: true}
		if _, ok := content.(map[string]any); ok {
			out.Result.ContentKind = "document"
			out.Result.ReturnedID = "did:example:123"
			out.Result.Snapshot = f.Content
			out.DataModel = f.Content
		}
	}
	return out
}
func TestRoutingGuardsAndIndependentForwarding(t *testing.T) {
	for _, f := range routingFixtures() {
		base := routingControl(f)
		want := core.Pass
		if f.Name == "forward-uri-options" {
			want = core.Fail
		}
		for _, o := range judgeRouting(f, base, "input") {
			if o.Verdict != want {
				t.Fatal(f.Name, o.Verdict)
			}
		}
		for _, change := range []func(*RoutingResult){func(r *RoutingResult) { r.Role = "SAGE registry" }, func(r *RoutingResult) { r.CaptureError = "lost" }, func(r *RoutingResult) { r.Operation = "invented" }, func(r *RoutingResult) { r.Request.Request.Input = "other" }, func(r *RoutingResult) { r.ResolveInputs = []string{"other"} }, func(r *RoutingResult) { r.ResolveOptions = nil }, func(r *RoutingResult) { r.Options = []byte(`{`) }, func(r *RoutingResult) { r.Options = []byte(`{}`) }} {
			r := routingControl(f)
			change(&r)
			if judgeRouting(f, r, "input")[0].Verdict != core.Error {
				t.Fatal("invalid trace", f.Name)
			}
		}
		bad := f
		bad.Name = "other"
		if judgeRouting(bad, base, "input")[0].Verdict != core.Error {
			t.Fatal("bad premise")
		}
		if strings.Contains(f.Name, "forward-") {
			r := routingControl(f)
			r.Result = Result{}
			r.DriverOptions = nil
			for _, o := range judgeRouting(f, r, "input") {
				if o.Verdict != want {
					t.Fatal("forward coupled to return")
				}
			}
			r = routingControl(f)
			r.ResolveOptions[0] = []byte(`{`)
			if judgeRouting(f, r, "input")[0].Verdict != core.Error {
				t.Fatal("missing input")
			}
			continue
		}
		for _, change := range []func(*RoutingResult){func(r *RoutingResult) { r.DriverOptions = nil }, func(r *RoutingResult) { r.DriverOptions[0] = []byte(`{`) }, func(r *RoutingResult) { r.DriverOptions[0] = []byte(`{}`) }, func(r *RoutingResult) { r.Result.Metadata = []byte(`{`) }, func(r *RoutingResult) { r.Result.ContentMetadata = []byte(`{`) }, func(r *RoutingResult) { r.Result.Raw = []byte(`{`); r.DataModel = []byte(`{`) }, func(r *RoutingResult) { r.Entries = []byte(`{"extra":1}`); r.Result.HasContent = !r.Result.HasContent }} {
			r := routingControl(f)
			change(&r)
			if judgeRouting(f, r, "input")[0].Verdict == core.Pass {
				t.Fatal("false routing PASS", f.Name)
			}
		}
		r := routingControl(f)
		r.Result.HasContent = !r.Result.HasContent
		if judgeRouting(f, r, "input")[0].Verdict != core.Error {
			t.Fatal("result mutation")
		}
		if f.ErrorType == "ANY" {
			r = routingControl(f)
			r.Result.Metadata = []byte(`{"error":{"type":"https://example.org/other-error"}}`)
			if judgeRouting(f, r, "input")[0].Verdict != core.Pass {
				t.Fatal("recommended type forced mandatory")
			}
		}
	}
}

type routingMock struct {
	noOperation
	fail bool
}

func (s routingMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	for _, f := range routingFixtures() {
		if f.Request.Input == q.Request.Input && f.Request.Accept == q.Request.Accept && f.Request.Relationship == q.Request.Relationship && string(f.Document) == string(q.Document.Data) {
			r := routingControl(f)
			if s.fail {
				return r, errors.New("adapter failed")
			}
			return r, nil
		}
	}
	return RoutingResult{}, errors.New("unknown")
}
func TestRoutingDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendRoutingCases(&p)
		want := 12
		if name != "did-1.1" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{routingMock{}, core.Pass}, {routingMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				want := tt.v
				if want == core.Pass && strings.HasSuffix(c.ID, "forward-uri-options") {
					want = core.Fail
				}
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != want || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o.Verdict)
					}
				}
			}
		}
	}
}

func TestRoutingClauseIndependence(t *testing.T) {
	find := func(name string) routingFixture {
		for _, f := range routingFixtures() {
			if f.Name == name {
				return f
			}
		}
		t.Fatal(name)
		return routingFixture{}
	}
	check := func(f routingFixture, r RoutingResult, fail map[string]bool) {
		for _, o := range judgeRouting(f, r, "input") {
			want := core.Pass
			if fail[o.Statement] {
				want = core.Fail
			}
			if o.Verdict != want {
				t.Fatal(o.Statement, o.Verdict, want)
			}
		}
	}
	f := find("unhandled-path")
	r := routingControl(f)
	r.Result.Metadata = []byte(`{"error":{"type":"https://example.org/wrong"}}`)
	check(f, r, map[string]bool{"res10-crd20261001#dereferencing-algorithm-resource.49": true, "res10-crd20261001#dereferencing-algorithm-resource.50": true})
	f = find("service-urls")
	r = routingControl(f)
	r.Result.ContentMetadata = []byte(`{"contentType":"text/plain"}`)
	check(f, r, map[string]bool{"res10-crd20261001#dereferencing-algorithm-resource.36": true, "res10-crd20261001#dereferencing-algorithm-resource.39": true})
	f = find("conflicting-fragment")
	for _, body := range []string{`{"error":null}`, `{"error":{}}`, `{"error":false}`, `{"error":{"type":"relative"}}`} {
		r = routingControl(f)
		r.Result.Metadata = []byte(body)
		if judgeRouting(f, r, "input")[0].Verdict != core.Fail {
			t.Fatal("invented refusal", body)
		}
	}
	f = find("service-id")
	r = routingControl(f)
	r.Result.ContentMetadata = []byte(`{"added":"metadata"}`)
	check(f, r, map[string]bool{"res10-crd20261001#dereferencing-algorithm-resource.31": true, "res10-crd20261001#dereferencing-algorithm-resource.34": true})
}
func TestRoutingServiceIdGuards(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{{`{}`, `{}`, false}, {`{"service":[]}`, `{"service":[]}`, true}, {`{"service":[{}]}`, `{"service":[{"id":"one"}]}`, false}, {`{"service":[{"id":"one"}]}`, `{"service":[{}]}`, false}, {`{"service":42}`, `{"service":[]}`, false}} {
		a, _ := core.ParseJSON([]byte(tt.a))
		b, _ := core.ParseJSON([]byte(tt.b))
		if routingServiceIDs(a, b) != tt.want {
			t.Fatal(tt)
		}
	}
}
