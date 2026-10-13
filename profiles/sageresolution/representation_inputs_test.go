package sageresolution

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func TestActualProducerInputContract(t *testing.T) {
	q := typedProductionFixtures()[0]
	for _, q := range typedProductionFixtures() {
		if o := judgeProducerInput(inputProducerGood(q), q, "input"); o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
	changes := []struct {
		name   string
		want   core.Verdict
		change func(*TypedProductionResult)
	}{
		{"builder", core.Error, func(r *TypedProductionResult) { r.BuildError = "not called" }},
		{"capture", core.Error, func(r *TypedProductionResult) { r.CaptureError = "missing" }},
		{"no-call", core.Error, func(r *TypedProductionResult) { r.Calls = nil }},
		{"repeated-call", core.Error, func(r *TypedProductionResult) { r.Calls = append(r.Calls, r.Calls[0]) }},
		{"operation", core.Error, func(r *TypedProductionResult) { r.Calls[0].Operation = "other" }},
		{"version", core.Error, func(r *TypedProductionResult) { r.Calls[0].Version = "1.0" }},
		{"option", core.Error, func(r *TypedProductionResult) { r.Calls[0].JSONLD = true }},
		{"secret", core.Error, func(r *TypedProductionResult) { r.Calls[0].IncludeSecret = true }},
		{"pre-capture", core.Error, func(r *TypedProductionResult) { r.Calls[0].CaptureError = "missing" }},
		{"bad-model", core.Error, func(r *TypedProductionResult) { r.Calls[0].Model = []byte(`{`) }},
		{"bad-entries", core.Error, func(r *TypedProductionResult) { r.Calls[0].Entries = []byte(`{`) }},
		{"id", core.Error, func(r *TypedProductionResult) { r.ID = "other" }},
		{"controller", core.Error, func(r *TypedProductionResult) { r.Controllers[0] = "other" }},
		{"shape", core.Error, func(r *TypedProductionResult) { r.ControllerShape = "single" }},
		{"typed-value", core.Error, func(r *TypedProductionResult) { r.Fields[2].Value.Kind = "double" }},
		{"lost-representation", core.Error, func(r *TypedProductionResult) { r.Entries = nil }},
		{"wrong-model", core.Error, func(r *TypedProductionResult) { r.Calls[0].Model = []byte(`{}`) }},
		{"wrong-map", core.Error, func(r *TypedProductionResult) { r.Calls[0].Entries = []byte(`{}`) }},
	}
	for _, tt := range changes {
		t.Run(tt.name, func(t *testing.T) {
			r := inputProducerGood(q)
			tt.change(&r)
			if o := judgeProducerInput(r, q, "input"); o.Verdict != tt.want {
				t.Fatal(o)
			}
		})
	}
	r := inputProducerGood(q)
	r.Calls[0].Error = "downstream failure"
	r.Calls[0].Output = nil
	r.Calls[0].MediaType = ""
	if o := judgeProducerInput(r, q, "input"); o.Verdict != core.Pass {
		t.Fatal("output judged as input", o)
	}
	q.Fields = nil
	if o := judgeProducerInput(r, q, "input"); o.Verdict != core.Error {
		t.Fatal("incomplete input", o)
	}
}
func TestActualConsumerInputContract(t *testing.T) {
	for _, q := range typedConsumptionFixtures() {
		r := consumerTypedGood(q)
		if o := judgeConsumerInput(r, q, "input"); o.Verdict != core.Pass {
			t.Fatal(o)
		}
		r.Call.Error = "downstream failure"
		r.Call.Model = nil
		r.Call.CaptureError = "no returned model"
		r.Methods = nil
		r.Call.Version = "unknown"
		if o := judgeConsumerInput(r, q, "input"); o.Verdict != core.Pass {
			t.Fatal("output judged as input", o)
		}
		r.Call.Input = []byte(`{}`)
		if o := judgeConsumerInput(r, q, "input"); o.Verdict != core.Error {
			t.Fatal("different call", o)
		}
	}
	q := typedConsumptionFixtures()[0]
	r := consumerTypedGood(q)
	q.MediaType = "application/did+json"
	if o := judgeConsumerInput(r, q, "input"); o.Verdict != core.Error {
		t.Fatal(o)
	}
}
func TestRepresentationInputCaseOperations(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendRepresentationInputCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("legacy scope")
	}
	p.Name = "did-1.1"
	appendRepresentationInputCases(&p)
	if len(p.Cases) != 4 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, s := range []core.Subject{noOperation{}, stub{err: true}, stub{}} {
			o := c.Run(t.Context(), s)[0]
			want := core.Error
			if _, ok := s.(noOperation); ok {
				want = core.NotSupported
			}
			if o.Verdict != want || o.Input == "" {
				t.Fatal(o)
			}
		}
	}
}

func inputProducerGood(q TypedProductionRequest) TypedProductionResult {
	r, _ := typedProductionFixture(q.JSONLD)
	data, _ := json.Marshal(r)
	var out TypedProductionResult
	_ = json.Unmarshal(data, &out)
	return out
}
