package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func optionProducerControl(ld bool) TypedProductionResult {
	output := optionModel
	if ld {
		output = optionLD
	}
	return TypedProductionResult{Calls: []ProductionCapture{{Operation: pipelineProducer, Model: []byte(optionModel), Entries: []byte(`{}`), Version: "1.1", JSONLD: ld, Output: []byte(output), MediaType: "application/did"}}}
}
func optionConsumerControl(strict bool) ConsumptionCapture {
	return ConsumptionCapture{Operation: pipelineConsumer, Input: []byte(optionLD), MediaType: "application/did", Require: "1.1", Expected: "unknown", Strict: strict, Version: "1.1", JSONLD: true, Model: []byte(optionModel), Entries: []byte(`{"@context":"https://www.w3.org/ns/did/v1.1"}`)}
}
func TestAdditionalProducerOptionAttribution(t *testing.T) {
	for _, ld := range []bool{false, true} {
		q := producerOptionsRequest(ld)
		if judgeProducerOptions(q, optionProducerControl(ld), "unit")[0].Verdict != core.Pass {
			t.Fatal("control")
		}
		for _, change := range []func(*TypedProductionResult){
			func(v *TypedProductionResult) { v.BuildError = "lost" }, func(v *TypedProductionResult) { v.CaptureError = "lost" }, func(v *TypedProductionResult) { v.Calls = nil }, func(v *TypedProductionResult) { v.Calls[0].Operation = "other" }, func(v *TypedProductionResult) { v.Calls[0].Version = "1.0" }, func(v *TypedProductionResult) { v.Calls[0].JSONLD = !ld }, func(v *TypedProductionResult) { v.Calls[0].IncludeSecret = true }, func(v *TypedProductionResult) { v.Calls[0].CaptureError = "lost" }, func(v *TypedProductionResult) { v.Calls[0].Model = []byte(`{}`) }, func(v *TypedProductionResult) { v.Calls[0].Entries = []byte(`null`) },
		} {
			v := optionProducerControl(ld)
			change(&v)
			if judgeProducerOptions(q, v, "unit")[0].Verdict != core.Error {
				t.Fatal(v)
			}
		}
		for _, change := range []func(*TypedProductionResult){func(v *TypedProductionResult) { v.Calls[0].Error = "refusal" }, func(v *TypedProductionResult) { v.Calls[0].MediaType = "other" }, func(v *TypedProductionResult) { v.Calls[0].Output = []byte(`{}`) }} {
			v := optionProducerControl(ld)
			change(&v)
			if judgeProducerOptions(q, v, "unit")[0].Verdict != core.NotSupported {
				t.Fatal(v)
			}
		}
		q.ID = "other"
		if judgeProducerOptions(q, optionProducerControl(ld), "unit")[0].Verdict != core.Error {
			t.Fatal("unknown premise")
		}
	}
	if !optionJSONEqual([]byte(optionLD), `{"id":"did:example:options","@context":"https://www.w3.org/ns/did/v1.1"}`) {
		t.Fatal("object key order")
	}
	if optionJSONEqual([]byte(`{`), `{}`) || optionJSONEqual([]byte(`{}`), `{`) {
		t.Fatal("invalid JSON")
	}
}
func TestAdditionalConsumerOptionAttribution(t *testing.T) {
	for _, strict := range []bool{false, true} {
		q := consumerOptionsRequest(strict)
		if judgeConsumerOptions(q, optionConsumerControl(strict), "unit")[0].Verdict != core.Pass {
			t.Fatal("control")
		}
		for _, change := range []func(*ConsumptionCapture){func(v *ConsumptionCapture) { v.Operation = "other" }, func(v *ConsumptionCapture) { v.Input = nil }, func(v *ConsumptionCapture) { v.MediaType = "other" }, func(v *ConsumptionCapture) { v.Require = "unknown" }, func(v *ConsumptionCapture) { v.Expected = "1.0" }, func(v *ConsumptionCapture) { v.Strict = !strict }, func(v *ConsumptionCapture) { v.CaptureError = "lost" }} {
			v := optionConsumerControl(strict)
			change(&v)
			if judgeConsumerOptions(q, v, "unit")[0].Verdict != core.Error {
				t.Fatal(v)
			}
		}
		for _, change := range []func(*ConsumptionCapture){func(v *ConsumptionCapture) { v.Error = "refusal"; v.CaptureError = "nil model" }, func(v *ConsumptionCapture) { v.Version = "1.0" }, func(v *ConsumptionCapture) { v.JSONLD = false }, func(v *ConsumptionCapture) { v.Model = []byte(`{}`) }, func(v *ConsumptionCapture) { v.Entries = []byte(`{}`) }} {
			v := optionConsumerControl(strict)
			change(&v)
			if judgeConsumerOptions(q, v, "unit")[0].Verdict != core.NotSupported {
				t.Fatal(v)
			}
		}
		q.Require = "1.0"
		if judgeConsumerOptions(q, optionConsumerControl(strict), "unit")[0].Verdict != core.Error {
			t.Fatal("unknown premise")
		}
	}
}

type optionsMock struct {
	noOperation
	fail bool
}

func (s optionsMock) InspectTypedProduction(_ context.Context, q TypedProductionRequest) (TypedProductionResult, error) {
	if s.fail {
		return TypedProductionResult{}, errors.New("lost")
	}
	return optionProducerControl(q.JSONLD), nil
}
func (s optionsMock) InspectConsumptionOptions(_ context.Context, q ConsumptionOptionsRequest) (ConsumptionCapture, error) {
	if s.fail {
		return ConsumptionCapture{}, errors.New("lost")
	}
	return optionConsumerControl(q.Strict), nil
}
func TestRepresentationOptionsDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendRepresentationOptionsCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendRepresentationOptionsCases(&p)
	if len(p.Cases) != 4 {
		t.Fatal("cases")
	}
	for _, c := range p.Cases {
		if e := c.Validate(); e != nil {
			t.Fatal(e)
		}
		for _, tt := range []struct {
			s core.Subject
			v core.Verdict
		}{{optionsMock{}, core.Pass}, {optionsMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tt.s) {
				if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
					t.Fatal(o)
				}
			}
		}
	}
}

func TestOptionJSONMeaningAndOrder(t *testing.T) {
	if !optionJSONEqual([]byte(`{"map":{"a":1,"b":[2,3]},"id":"x"}`), `{"id":"x","map":{"b":[2,3],"a":1}}`) {
		t.Fatal("object order")
	}
	for _, data := range []string{`{"id":"x","map":{"a":1,"b":[3,2]}}`, `{"id":"x","map":{"a":"1","b":[2,3]}}`, `{"id":"x","id":"x"}`} {
		if optionJSONEqual([]byte(data), `{"id":"x","map":{"a":1,"b":[2,3]}}`) {
			t.Fatal("meaning changed or duplicate property", data)
		}
	}
}
