package sageprojection

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/report"
)

const fixtureDoc = `{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[{"id":"did:sage:web:registry.example:agent-1#sign","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"public-fixture"}}],"authentication":["did:sage:web:registry.example:agent-1#sign"],"assertionMethod":["did:sage:web:registry.example:agent-1#sign"],"keyAgreement":["did:sage:web:registry.example:agent-1#sign"],"service":[{"id":"did:sage:web:registry.example:agent-1#a2a","type":"A2AInterface","serviceEndpoint":"https://agent.example/a2a"}],"@context":"https://www.w3.org/ns/did/v1.1"}`

type mockSubject struct {
	err     error
	problem string
}

func (mockSubject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "unit-fixture", Revision: "fixture"}
}
func (mockSubject) Supports(string, core.Capability) bool { return false }
func (s mockSubject) Project(_ context.Context, _ Record, version string) (Result, error) {
	mt := "application/did+json"
	if version == "1.1" {
		mt = "application/did"
	}
	return Result{Raw: []byte(fixtureDoc), MediaType: mt, ProblemCode: s.problem}, s.err
}

func TestProfilesAndScope(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p, e := Profile(name)
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Cases) != 6 {
			t.Fatal("fixture cases")
		}
		res, e := (core.Runner{}).Run(t.Context(), p, mockSubject{})
		if e != nil {
			t.Fatal(e)
		}
		in, e := report.InputFor(p, res, "unit")
		if e != nil {
			t.Fatal(e)
		}
		r := report.Build(in)
		if len(r.GateFailures()) != 0 {
			t.Fatal(r.GateFailures())
		}
		if r.Totals.NotRun == 0 {
			t.Fatal("uninspected statements promoted")
		}
		for _, c := range res.Cases {
			for _, o := range c.Observations {
				if !strings.HasPrefix(o.Input, "{\"did\"") {
					t.Fatal("input provenance", o.Input)
				}
			}
		}
	}
	if _, e := Profile("unknown"); e == nil {
		t.Fatal("unknown profile")
	}
	saved := recordBytes
	recordBytes = []byte("tampered")
	defer func() { recordBytes = saved }()
	if _, e := Fixtures(); e == nil {
		t.Fatal("fixture drift")
	}
	if _, e := Profile("did-core-1.0"); e == nil {
		t.Fatal("drift not propagated")
	}
}
func TestAdapterFailuresAreNotPass(t *testing.T) {
	p, e := Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []core.Subject{onlySubject{}, mockSubject{err: errors.New("fixture failure")}, mockSubject{problem: "record.invalid"}} {
		res, e := (core.Runner{}).Run(t.Context(), p, s)
		if e != nil {
			t.Fatal(e)
		}
		for _, c := range res.Cases {
			for _, o := range c.Observations {
				if o.Verdict == core.Pass {
					t.Fatal("unexecuted PASS")
				}
			}
		}
	}
}

type onlySubject struct{}

func (onlySubject) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "bare"} }
func (onlySubject) Supports(string, core.Capability) bool { return false }
func TestIndependentOutputControls(t *testing.T) {
	rules := rulesFor("did-1.1")
	for _, raw := range []string{"{", `{"id":1,"id":2}`, `[]`} {
		for _, o := range judge(Result{Raw: []byte(raw)}, "did-1.1", rules, "input") {
			if o.Verdict != core.Error {
				t.Fatal("malformed output", o)
			}
		}
	}
	// Mutations are outputs from a unit subject, not copied implementation logic.
	mutate := func(field string, value any) core.DocumentJSON {
		var doc map[string]any
		if e := json.Unmarshal([]byte(fixtureDoc), &doc); e != nil {
			t.Fatal(e)
		}
		if field == "id" || field == "@context" || field == "verificationMethod" || field == "service" {
			doc[field] = value
		} else if strings.HasPrefix(field, "vm.") {
			vm := doc["verificationMethod"].([]any)[0].(map[string]any)
			vm[strings.TrimPrefix(field, "vm.")] = value
		} else if strings.HasPrefix(field, "svc.") {
			svc := doc["service"].([]any)[0].(map[string]any)
			svc[strings.TrimPrefix(field, "svc.")] = value
		} else {
			doc[field] = value
		}
		raw, e := json.Marshal(doc)
		if e != nil {
			t.Fatal(e)
		}
		d, e := core.ParseDocumentJSON(raw)
		if e != nil {
			t.Fatal(e)
		}
		return d
	}
	tests := []struct {
		id, field string
		value     any
	}{
		{"cid10#subjects.2", "id", 42}, {"cid10#verification-methods.2", "verificationMethod", []any{42}},
		{"cid10#verification-methods.3", "vm.publicKeyJwk", 42}, {"cid10#verification-methods.5", "vm.id", "bad"}, {"cid10#verification-methods.6", "vm.type", 42}, {"cid10#verification-methods.7", "vm.controller", "bad"},
		{"cid10#authentication.2", "authentication", []any{}}, {"cid10#assertion.2", "assertionMethod", []any{true}}, {"cid10#key-agreement.2", "keyAgreement", []any{"bad"}},
		{"cid10#services.2", "service", 42}, {"cid10#services.3", "service", []any{map[string]any{"id": "a"}}}, {"cid10#services.7", "service", []any{map[string]any{"id": "same"}, map[string]any{"id": "same", "type": "other"}}},
		{"cid10#services.9", "svc.type", []any{"A2AInterface", "A2AInterface"}}, {"cid10#services.12", "svc.serviceEndpoint", []any{"https://a.example", "https://a.example"}},
		{"did11-cr20260305#json-ld-processors.4", "@context", 42}, {"cid10#JsonWebKey.1", "vm.type", "Multikey"}, {"cid10#JsonWebKey.4", "vm.publicKeyJwk", map[string]any{"d": "unit-value"}}, {"cid10#JsonWebKey.8", "vm.publicKeyJwk", map[string]any{}},
	}
	for _, tt := range tests {
		for _, r := range rules {
			if r.id == tt.id {
				applies, ok := r.check(mutate(tt.field, tt.value), "application/did")
				if !applies || ok {
					t.Fatalf("mutation escaped %s", tt.id)
				}
			}
		}
	}
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		d, _ := core.ParseDocumentJSON([]byte(`{"didDocument":{"id":"did:sage:web:x:a"}}`))
		r := rulesFor(name)[0]
		if _, ok := r.check(d, ""); ok {
			t.Fatal("nested wrapper accepted")
		}
		d, _ = core.ParseDocumentJSON([]byte(fixtureDoc))
		raw, _ := d.MarshalJSON()
		obs := judge(Result{Raw: raw, MediaType: "text/html"}, name, rulesFor(name), "fixture")
		if obs[1].Verdict != core.Fail {
			t.Fatal("media type")
		}
	}
	for _, d := range []core.Value{core.String("https://www.w3.org/ns/did/v1.1"), core.Array(core.String("https://www.w3.org/ns/did/v1.1"), core.Object())} {
		if !validContext(d) {
			t.Fatal("valid context rejected")
		}
	}
	for _, d := range []core.Value{core.Array(), core.Array(core.String("wrong")), core.String("wrong")} {
		if validContext(d) {
			t.Fatal("wrong context accepted")
		}
	}
}
func TestCollectionAndOptionalRules(t *testing.T) {
	obj := core.Object(core.M("id", core.String("did:example:1")))
	for _, v := range []core.Value{core.Array(), core.Array(obj)} {
		if !maps(v) {
			t.Fatal("maps")
		}
	}
	for _, v := range []core.Value{core.String("bad"), core.Array(obj, obj), core.Array(core.Bool(true))} {
		if maps(v) {
			t.Fatal("not a set of maps")
		}
	}
	if !endpoint(core.Object()) || !endpoint(core.String("https://a.example")) || !endpoint(core.Array(core.Object(), core.String("https://a.example"))) {
		t.Fatal("endpoints")
	}
	if endpoint(core.Array()) || endpoint(core.Bool(true)) || endpoint(core.Array(core.Bool(true))) {
		t.Fatal("invalid endpoints")
	}
	if !stringsValue(core.String("type")) || !stringsValue(core.Array(core.String("one"), core.String("two"))) {
		t.Fatal("strings")
	}
	if stringsValue(core.Bool(true)) || stringsValue(core.Array(core.Bool(true))) {
		t.Fatal("invalid strings")
	}
	empty := core.NewDocument()
	if a, _ := setRule("verificationMethod", func(core.Value) bool { return true })(empty, ""); a {
		t.Fatal("absent optional method")
	}
	if a, _ := relationshipRule("authentication")(empty, ""); a {
		t.Fatal("absent relationship")
	}
	for _, v := range []core.Value{core.Array(obj), core.Array(core.String("did:example:1#key"))} {
		d := core.NewDocument(core.M("authentication", v))
		if a, ok := relationshipRule("authentication")(d, ""); !a || !ok {
			t.Fatal("valid relationship")
		}
	}
	for _, v := range []core.Value{core.Array(obj, obj), core.Array(core.String("did:example:1#key"), core.String("did:example:1#key"))} {
		d := core.NewDocument(core.M("authentication", v))
		if _, ok := relationshipRule("authentication")(d, ""); ok {
			t.Fatal("duplicate relation")
		}
	}
	// Optional collections are not evidence about an entry that is absent.
	for _, r := range rulesFor("did-1.1") {
		r.check(empty, "")
		r.check(core.NewDocument(core.M("verificationMethod", core.Array()), core.M("service", core.Array())), "")
	}
}
