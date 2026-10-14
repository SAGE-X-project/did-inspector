package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

const producerOptionsID = "did11-cr20260305#production-and-consumption.9"
const consumerOptionsID = "did11-cr20260305#production-and-consumption.14"
const optionModel = `{"id":"did:example:options"}`
const optionLD = `{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:options"}`

func producerOptionsRequest(ld bool) TypedProductionRequest {
	return TypedProductionRequest{ID: "did:example:options", ControllerShape: "absent", Version: "1.1", JSONLD: ld}
}
func consumerOptionsRequest(strict bool) ConsumptionOptionsRequest {
	return ConsumptionOptionsRequest{Document: ConsumptionRequest{Data: []byte(optionLD), MediaType: "application/did"}, Require: "1.1", Strict: strict}
}
func optionJSONEqual(a []byte, b string) bool {
	x, e := parse(a)
	y, f := parse([]byte(b))
	return e == nil && f == nil && equalObserved(x.Value(), y.Value(), "unknown")
}
func judgeProducerOptions(q TypedProductionRequest, v TypedProductionResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{producerOptionsID}, core.Error, "Actual selected direct producer with JSONLD false/true. Additional-option acceptance only; not all output conformance, JSON-LD processing or authority. Refusal is NOT_SUPPORTED, not a MAY violation. Output contrasts are capability evidence, not additional normative obligations.", input, v)
	if !reflect.DeepEqual(q, producerOptionsRequest(q.JSONLD)) || v.BuildError != "" || v.CaptureError != "" || len(v.Calls) != 1 {
		return obs
	}
	c := v.Calls[0]
	if c.Operation != pipelineProducer || c.Version != "1.1" || c.JSONLD != q.JSONLD || c.IncludeSecret || c.CaptureError != "" || !optionJSONEqual(c.Model, optionModel) || !optionJSONEqual(c.Entries, `{}`) {
		return obs
	}
	obs[0].Verdict = core.NotSupported
	want := optionModel
	if q.JSONLD {
		want = optionLD
	}
	if c.Error == "" && c.MediaType == "application/did" && optionJSONEqual(c.Output, want) {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "Selected additional JSONLD option reaches the actual producer and the public fixture is accepted with its selected representation"
	return obs
}
func judgeConsumerOptions(q ConsumptionOptionsRequest, v ConsumptionCapture, input string) []core.Observation {
	obs := libraryUnavailable([]string{consumerOptionsID}, core.Error, "Actual selected direct consumer with Require=1.1 and Strict false/true on literal explicit-context input. Additional-option acceptance only; no assumptions about all input conformance, option rejection policy, full JSON-LD processing or resolver ingress. Refusal is NOT_SUPPORTED, not a MAY violation.", input, v)
	if !reflect.DeepEqual(q, consumerOptionsRequest(q.Strict)) || v.Operation != pipelineConsumer || !bytes.Equal(v.Input, q.Document.Data) || v.MediaType != q.Document.MediaType || v.Require != q.Require || v.Expected != "unknown" || v.Strict != q.Strict {
		return obs
	}
	obs[0].Verdict = core.NotSupported
	if v.Error != "" {
		return obs
	}
	if v.CaptureError != "" {
		obs[0].Verdict = core.Error
		return obs
	}
	if v.Version == "1.1" && v.JSONLD && optionJSONEqual(v.Model, optionModel) && optionJSONEqual(v.Entries, `{"@context":"https://www.w3.org/ns/did/v1.1"}`) {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "Selected additional Require/Strict options reach the actual consumer and literal public input is accepted"
	return obs
}
func appendRepresentationOptionsCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, enabled := range []bool{false, true} {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/representation-options-producer-%t", p.Name, enabled), Profile: p.Name, Statements: []string{producerOptionsID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			q := producerOptionsRequest(enabled)
			input, _ := json.Marshal(q)
			s, ok := target.(TypedProductionSubject)
			if !ok {
				return libraryUnavailable([]string{producerOptionsID}, core.NotSupported, "no direct producer option observer", string(input), nil)
			}
			v, e := s.InspectTypedProduction(ctx, q)
			if e != nil {
				return libraryUnavailable([]string{producerOptionsID}, core.Error, e.Error(), string(input), v)
			}
			return judgeProducerOptions(q, v, string(input))
		}})
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/representation-options-consumer-%t", p.Name, enabled), Profile: p.Name, Statements: []string{consumerOptionsID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			q := consumerOptionsRequest(enabled)
			input, _ := json.Marshal(q)
			s, ok := target.(ConsumptionOptionsSubject)
			if !ok {
				return libraryUnavailable([]string{consumerOptionsID}, core.NotSupported, "no direct consumer option observer", string(input), nil)
			}
			v, e := s.InspectConsumptionOptions(ctx, q)
			if e != nil {
				return libraryUnavailable([]string{consumerOptionsID}, core.Error, e.Error(), string(input), v)
			}
			return judgeConsumerOptions(q, v, string(input))
		}})
	}
}
