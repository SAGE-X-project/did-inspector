package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

const typedModelFixture = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"],"text":"quote \" and slash \\ and newline \n","unicode":"한글","integer":9007199254740991,"double":1.5,"wholeDouble":2.0,"boolean":true,"null":null,"list":[-42,"ordered",false,null],"map":{"nested":["value",1.5],"empty":{}},"clock":"2020-12-21T04:17:47.123456789+09:00","otherClock":"2020-12-20T23:59:59.987654321-05:00"}`

func typedProductionFixture(ld bool) (TypedProductionResult, TypedProductionRequest) {
	q := typedProductionFixtures()[0]
	q.JSONLD = ld
	// Literal typed-model image is independent of the subject and expected converter.
	model := []byte(typedModelFixture)
	entries := []byte(`{"representationNote":{"note":"retained","flag":true}}`)
	wire := strings.ReplaceAll(string(model), `2020-12-21T04:17:47.123456789+09:00`, `2020-12-20T19:17:47Z`)
	wire = strings.ReplaceAll(wire, `2020-12-20T23:59:59.987654321-05:00`, `2020-12-21T04:59:59Z`)
	wire = strings.TrimSuffix(wire, "}") + `,"representationNote":{"note":"retained","flag":true}}`
	if ld {
		wire = `{"@context":"https://www.w3.org/ns/did/v1.1",` + strings.TrimPrefix(wire, "{")
	}
	r := TypedProductionResult{ID: q.ID, Controllers: append([]string{}, q.Controllers...), ControllerShape: "set", Calls: []ProductionCapture{{Operation: pipelineProducer, Version: "1.1", JSONLD: ld, Model: model, Entries: entries, Output: []byte(wire), MediaType: "application/did"}}}
	b, _ := json.Marshal(q.Fields)
	_ = json.Unmarshal(b, &r.Fields)
	b, _ = json.Marshal(q.Entries)
	_ = json.Unmarshal(b, &r.Entries)
	return r, q
}
func TestTypedProductionTableAndIndependentFailures(t *testing.T) {
	for _, ld := range []bool{false, true} {
		r, q := typedProductionFixture(ld)
		if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Pass || o.Input != "unit" || o.Observed == "" {
			t.Fatal(o)
		}
		for _, tc := range []struct{ from, to string }{
			{`"integer":9007199254740991`, `"integer":9007199254740991.0`},
			{`"wholeDouble":2.0`, `"wholeDouble":2`}, {`"wholeDouble":2.0`, `"wholeDouble":2e0`},
			{`"double":1.5`, `"double":1.6`},
			{`2020-12-20T19:17:47Z`, `2020-12-21T04:17:47+09:00`},
			{`2020-12-20T19:17:47Z`, `2020-12-20T19:17:47.123456789Z`},
			{`"boolean":true`, `"boolean":"true"`}, {`"null":null`, `"null":"null"`},
			{`"list":[-42,"ordered",false,null]`, `"list":["ordered",-42,false,null]`},
			{`"nested":["value",1.5]`, `"nested":["changed",1.5]`},
			{`"flag":true`, `"flag":false`}, {`"unicode":"한글"`, `"unicode":"changed"`},
		} {
			r, q := typedProductionFixture(ld)
			r.Calls[0].Output = []byte(strings.Replace(string(r.Calls[0].Output), tc.from, tc.to, 1))
			if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Fail {
				t.Fatal(tc, o)
			}
		}
		for _, wire := range []string{`{`, `[]`, `{"id":"one","id":"two"}`} {
			r, q := typedProductionFixture(ld)
			r.Calls[0].Output = []byte(wire)
			if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Fail {
				t.Fatal(o)
			}
		}
		r, q = typedProductionFixture(ld)
		r.Calls[0].Error = "actual producer failure"
		if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Fail {
			t.Fatal(o)
		}
		r, q = typedProductionFixture(ld)
		r.Calls[0].MediaType = "application/did;broken"
		if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Fail {
			t.Fatal(o)
		}
	}
}
func TestTypedWitnessAndPreInputAttribution(t *testing.T) {
	for _, mutate := range []func(*TypedProductionResult){
		func(r *TypedProductionResult) { r.BuildError = "builder error" }, func(r *TypedProductionResult) { r.CaptureError = "witness error" }, func(r *TypedProductionResult) { r.Calls = nil },
		func(r *TypedProductionResult) { r.ID = "other" }, func(r *TypedProductionResult) { r.ControllerShape = "single" }, func(r *TypedProductionResult) { r.Controllers[0] = "other" }, func(r *TypedProductionResult) { r.Fields[2].Value.Kind = "double" }, func(r *TypedProductionResult) { r.Entries = nil },
		func(r *TypedProductionResult) { r.Calls[0].Operation = "generic" }, func(r *TypedProductionResult) { r.Calls[0].Version = "1.0" }, func(r *TypedProductionResult) { r.Calls[0].JSONLD = true }, func(r *TypedProductionResult) { r.Calls[0].IncludeSecret = true }, func(r *TypedProductionResult) { r.Calls[0].CaptureError = "error" }, func(r *TypedProductionResult) { r.Calls[0].Model = []byte(`null`) }, func(r *TypedProductionResult) { r.Calls[0].Entries = []byte(`null`) }, func(r *TypedProductionResult) { r.Calls[0].Entries = []byte(`{}`) },
	} {
		r, q := typedProductionFixture(false)
		mutate(&r)
		if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Error || o.Observed == "" {
			t.Fatal(o)
		}
	}
}
func TestTypedExpectedRangeAndRecursiveErrors(t *testing.T) {
	for _, v := range []TypedValue{{Kind: "integer", Text: "bad"}, {Kind: "integer", Text: "9007199254740992"}, {Kind: "double", Text: "3.2"}, {Kind: "datetime", Text: "bad"}, {Kind: "unknown"}, {Kind: "list", Items: []TypedValue{{Kind: "unknown"}}}, {Kind: "map", Members: []TypedMember{{Name: "x", Value: TypedValue{Kind: "unknown"}}}}} {
		if _, e := typedJSON(v, true); e == nil {
			t.Fatal(v)
		}
	}
	v := TypedValue{Kind: "integer", Text: "-9007199254740991"}
	if _, e := typedJSON(v, false); e != nil {
		t.Fatal(e)
	}
	q := typedProductionFixtures()[0]
	q.Fields = append(q.Fields, TypedMember{Name: "id", Value: TypedValue{Kind: "string", Text: "other"}})
	if _, e := typedExpected(q, true, true); e == nil {
		t.Fatal("overlapping model entries")
	}
	q = typedProductionFixtures()[0]
	q.Fields[0].Value.Kind = "unknown"
	if _, e := typedExpected(q, true, true); e == nil {
		t.Fatal("invalid model fixture")
	}
	q = typedProductionFixtures()[0]
	q.Entries = []TypedMember{{Name: "bad", Value: TypedValue{Kind: "unknown"}}}
	if _, e := typedExpected(q, true, true); e == nil {
		t.Fatal("invalid entry fixture")
	}
	if _, e := typedMap([]TypedMember{{Name: "x", Value: TypedValue{Kind: "null"}}, {Name: "x", Value: TypedValue{Kind: "null"}}}, false); e == nil {
		t.Fatal("duplicate typed map")
	}
}

type typedOnly struct{ fail bool }

func (typedOnly) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit-typed"} }
func (typedOnly) Supports(string, core.Capability) bool { return false }
func (s typedOnly) InspectTypedProduction(_ context.Context, q TypedProductionRequest) (TypedProductionResult, error) {
	if s.fail {
		return TypedProductionResult{}, errors.New("unavailable")
	}
	out, _ := typedProductionFixture(q.JSONLD)
	return out, nil
}
func TestTypedCasesRetainOperationAndInput(t *testing.T) {
	p := core.Profile{Name: "did-1.1"}
	appendTypedProductionCases(&p)
	if len(p.Cases) != 2 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, tc := range []struct {
			s core.Subject
			v core.Verdict
		}{{typedOnly{}, core.Pass}, {typedOnly{true}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tc.s) {
				if o.Verdict != tc.v || o.Input == "" {
					t.Fatal(o)
				}
			}
		}
	}
	p = core.Profile{Name: "did-core-1.0"}
	appendTypedProductionCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("legacy profile expanded")
	}
}

func TestIncompleteTypedTableFixtureCannotPass(t *testing.T) {
	r, q := typedProductionFixture(false)
	q.Fields = q.Fields[:1]
	r.Fields = r.Fields[:1]
	if o := judgeTypedProduction(r, q, "unit"); o.Verdict != core.Error {
		t.Fatal("incomplete table fixture passed", o)
	}
}
