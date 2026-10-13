package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

const contextModel = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"]}`
const contextWire = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"],"@context":"https://www.w3.org/ns/did/v1.1"}`

func contextMock(q TypedProductionRequest) TypedProductionResult {
	copyData, _ := json.Marshal(q)
	var copyQ TypedProductionRequest
	_ = json.Unmarshal(copyData, &copyQ)
	entry := []byte(`{"@context":"https://www.w3.org/ns/did/v1.1"}`)
	call := ProductionCapture{Operation: pipelineProducer, Version: "1.1", JSONLD: true, Model: []byte(contextModel), Entries: entry, Output: []byte(contextWire), MediaType: "application/did"}
	switch q.Entries[0].Value.Kind {
	case "boolean":
		call.Entries = []byte(`{"@context":false}`)
		call.Error = "opaque actual error"
		call.Output = nil
		call.MediaType = ""
	case "integer":
		call.Entries = []byte(`{"@context":42}`)
		call.Error = "different opaque error"
		call.Output = nil
		call.MediaType = ""
	case "list":
		call.Entries = []byte(`{"@context":["https://www.w3.org/ns/did/v1.1",false]}`)
		call.Error = "another opaque error"
		call.Output = nil
		call.MediaType = ""
	}
	return TypedProductionResult{ID: copyQ.ID, Controllers: copyQ.Controllers, ControllerShape: "set", Fields: []TypedMember{}, Entries: copyQ.Entries, Calls: []ProductionCapture{call}}
}
func contextPairMock(f producerContextFixture) producerContextPair {
	return producerContextPair{contextMock(f.Positive), contextMock(f.Negative)}
}
func TestProducerContextRefusalAndRepair(t *testing.T) {
	for _, f := range producerContextFixtures() {
		r := contextPairMock(f)
		if o := judgeProducerContext(r, f, "input"); o.Verdict != core.Pass {
			t.Fatal(o)
		}
		// A successful repair is valid for this prohibition, not a refusal failure.
		r.Negative.Calls[0].Error = ""
		r.Negative.Calls[0].Output = []byte(contextWire)
		r.Negative.Calls[0].MediaType = "application/did"
		if o := judgeProducerContext(r, f, "input"); o.Verdict != core.Pass {
			t.Fatal("repair forbidden", o)
		}
		r.Negative.Calls[0].Output = []byte(`{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"],"@context":["https://www.w3.org/ns/did/v1.1"]}`)
		if o := judgeProducerContext(r, f, "input"); o.Verdict != core.Pass {
			t.Fatal("base array forbidden", o)
		}
	}
	f := producerContextFixtures()[0]
	for _, tt := range []struct {
		name   string
		change func(*producerContextPair)
	}{
		{"builder", func(r *producerContextPair) { r.Negative.BuildError = "builder refusal" }},
		{"capture", func(r *producerContextPair) { r.Negative.CaptureError = "missing" }},
		{"no actual call", func(r *producerContextPair) { r.Negative.Calls = nil }},
		{"wrong id", func(r *producerContextPair) { r.Negative.ID = "other" }},
		{"wrong controller", func(r *producerContextPair) { r.Negative.Controllers[0] = "other" }},
		{"wrong shape", func(r *producerContextPair) { r.Negative.ControllerShape = "single" }},
		{"lost fields", func(r *producerContextPair) { r.Negative.Fields = []TypedMember{{Name: "other"}} }},
		{"wrong context kind", func(r *producerContextPair) { r.Negative.Entries[0].Value.Kind = "integer" }},
		{"wrong actor", func(r *producerContextPair) { r.Negative.Calls[0].Operation = "fake" }},
		{"wrong version", func(r *producerContextPair) { r.Negative.Calls[0].Version = "1.0" }},
		{"wrong option", func(r *producerContextPair) { r.Negative.Calls[0].JSONLD = false }},
		{"secret option", func(r *producerContextPair) { r.Negative.Calls[0].IncludeSecret = true }},
		{"bad capture", func(r *producerContextPair) { r.Negative.Calls[0].CaptureError = "missing" }},
		{"invalid model", func(r *producerContextPair) { r.Negative.Calls[0].Model = []byte(`{`) }},
		{"missing entries", func(r *producerContextPair) { r.Negative.Calls[0].Entries = []byte(`{}`) }},
		{"bad entries", func(r *producerContextPair) { r.Negative.Calls[0].Entries = []byte(`{`) }},
		{"control rejected", func(r *producerContextPair) {
			r.Positive.Calls[0].Error = "reject everything"
			r.Positive.Calls[0].Output = nil
		}},
		{"invalid control", func(r *producerContextPair) { r.Positive.Calls[0].Output = []byte(`{}`) }},
		{"partial error", func(r *producerContextPair) { r.Negative.Calls[0].Output = []byte(`{"@context":`) }},
		{"silent no output", func(r *producerContextPair) { r.Negative.Calls[0].Error = "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := contextPairMock(f)
			tt.change(&r)
			if o := judgeProducerContext(r, f, "input"); o.Verdict != core.Error {
				t.Fatal(o)
			}
		})
	}
	r := contextPairMock(f)
	f.Name = "unknown"
	if o := judgeProducerContext(r, f, "input"); o.Verdict != core.Error {
		t.Fatal(o)
	}
}
func TestProducerContextOutputScopeAndViolations(t *testing.T) {
	f := producerContextFixtures()[0]
	for _, wire := range []string{`{`, `[]`, `{"@context":true,"@context":false}`, `{}`, `{"@context":false}`, `{"@context":42}`, `{"@context":"wrong"}`, `{"@context":[]}`, `{"@context":[false]}`, `{"@context":["wrong"]}`, `{"@context":["https://www.w3.org/ns/did/v1.1",false]}`} {
		r := contextPairMock(f)
		r.Negative.Calls[0].Error = ""
		r.Negative.Calls[0].MediaType = "application/did"
		r.Negative.Calls[0].Output = []byte(wire)
		if o := judgeProducerContext(r, f, "input"); o.Verdict != core.Fail {
			t.Fatal(wire, o)
		}
	}
	for _, wire := range []string{`{"@context":["https://www.w3.org/ns/did/v1.1","https://context.example/unknown"]}`, `{"@context":["https://www.w3.org/ns/did/v1.1",{}]}`, `{"@context":["https://www.w3.org/ns/did/v1.1",null]}`, `{"@context":["https://www.w3.org/ns/did/v1.1",42]}`, `{"@context":["https://www.w3.org/ns/did/v1.1",[]]}`, `{"@context":"https://www.w3.org/ns/did/v1.1"}`, `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:sage:web:registry.example:other","controller":[]}`} {
		r := contextPairMock(f)
		r.Negative.Calls[0].Error = ""
		r.Negative.Calls[0].MediaType = "application/did"
		r.Negative.Calls[0].Output = []byte(wire)
		if o := judgeProducerContext(r, f, "input"); o.Verdict != core.NotSupported {
			t.Fatal(wire, o)
		}
	}
	r := contextPairMock(f)
	r.Negative.Calls[0].Error = ""
	r.Negative.Calls[0].Output = []byte(contextWire)
	r.Negative.Calls[0].MediaType = "application/json"
	if o := judgeProducerContext(r, f, "input"); o.Verdict != core.NotSupported {
		t.Fatal(o)
	}
}

type contextOnly struct {
	failAt int
	calls  int
}

func (*contextOnly) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit"} }
func (*contextOnly) Supports(string, core.Capability) bool { return false }
func (s *contextOnly) InspectTypedProduction(_ context.Context, q TypedProductionRequest) (TypedProductionResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return TypedProductionResult{}, errors.New("unavailable")
	}
	return contextMock(q), nil
}
func TestProducerContextOperationScope(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendProducerContextCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("legacy scope")
	}
	p.Name = "did-1.1"
	appendProducerContextCases(&p)
	if len(p.Cases) != 3 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, s := range []core.Subject{noOperation{}, &contextOnly{failAt: 1}, &contextOnly{failAt: 2}, &contextOnly{}} {
			o := c.Run(t.Context(), s)[0]
			want := core.Pass
			if _, ok := s.(noOperation); ok {
				want = core.NotSupported
			}
			if v, ok := s.(*contextOnly); ok && v.failAt > 0 {
				want = core.Error
			}
			if o.Verdict != want || o.Input == "" {
				t.Fatal(o)
			}
		}
	}
}
