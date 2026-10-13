package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

const producerInputStatement = "did11-cr20260305#production-and-consumption.8"
const consumerInputStatement = "did11-cr20260305#production-and-consumption.13"

func judgeProducerInput(out TypedProductionResult, q TypedProductionRequest, input string) core.Observation {
	raw, _ := json.Marshal(out)
	obs := core.Observation{Statement: producerInputStatement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "The actual selected producer receives the document data model and representation-specific entries map", Detail: "Fresh direct selected producer library call on the complete reviewed typed fixture. Actual types and separate pre-call maps are compared to independent input expectations. This input contract does not judge output, downstream errors, every representation, authority, resolver ingress or non-conforming document rejection."}
	if !knownTypedFixture(q) || out.BuildError != "" || out.CaptureError != "" || len(out.Calls) != 1 {
		return obs
	}
	p := out.Calls[0]
	if p.Operation != pipelineProducer || p.Version != "1.1" || p.JSONLD != q.JSONLD || p.IncludeSecret || p.CaptureError != "" {
		return obs
	}
	model, e := parse(p.Model)
	entries, f := parse(p.Entries)
	wantModel, g := typedExpected(q, false, false)
	wantEntries, h := typedMap(q.Entries, false)
	if e != nil || f != nil || g != nil || h != nil {
		return obs
	}
	if out.ID == q.ID && out.ControllerShape == "set" && reflect.DeepEqual(out.Controllers, q.Controllers) && typedMembersEqual(out.Fields, q.Fields) && typedMembersEqual(out.Entries, q.Entries) && typedOutputEqual(model.Value(), wantModel) && typedOutputEqual(entries.Value(), wantEntries) {
		obs.Verdict = core.Pass
	}
	return obs
}
func judgeConsumerInput(out TypedConsumptionResult, q ConsumptionRequest, input string) core.Observation {
	raw, _ := json.Marshal(out)
	obs := core.Observation{Statement: consumerInputStatement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "The actual selected consumer receives the literal representation bytes and declared Media Type string", Detail: "Fresh direct selected consumer library call, known public JSON fixtures and unchanged default options. Actual input bytes and media are archived before delegation. This input contract does not judge detection, returned data, downstream errors, all media, JSON-LD processing, authority or SAGE resolver ingress."}
	if knownTypedConsumption(q) && sameConsumerCall(out.Call, q) {
		obs.Verdict = core.Pass
	}
	return obs
}
func appendRepresentationInputCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for i, q := range typedProductionFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-representation-input-producer-%d", p.Name, i), Profile: p.Name, Statements: []string{producerInputStatement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(q)
			obs := core.Observation{Statement: producerInputStatement, Input: string(input), Verdict: core.NotSupported, Detail: "no actual producer input witness"}
			s, ok := target.(TypedProductionSubject)
			if !ok {
				return []core.Observation{obs}
			}
			out, e := s.InspectTypedProduction(ctx, q)
			if e != nil {
				obs.Verdict = core.Error
				obs.Detail = e.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeProducerInput(out, q, string(input))}
		}})
	}
	for i, q := range typedConsumptionFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-representation-input-consumer-%d", p.Name, i), Profile: p.Name, Statements: []string{consumerInputStatement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(q)
			obs := core.Observation{Statement: consumerInputStatement, Input: string(input), Verdict: core.NotSupported, Detail: "no actual consumer input witness"}
			s, ok := target.(TypedConsumptionSubject)
			if !ok {
				return []core.Observation{obs}
			}
			out, e := s.InspectTypedConsumption(ctx, q)
			if e != nil {
				obs.Verdict = core.Error
				obs.Detail = e.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeConsumerInput(out, q, string(input))}
		}})
	}
}
