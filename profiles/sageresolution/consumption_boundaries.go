package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

const rootProductionStatement = "did11-cr20260305#production.2"
const consumerMediaStatement = "did11-cr20260305#production-and-consumption.15"
const consumerRootStatement = "did11-cr20260305#consumption.3"

func judgeProductionRoot(result PipelineResult, input string) core.Observation {
	raw, err := pipelineArchive(result)
	obs := core.Observation{Statement: rootProductionStatement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "All actual pre-producer document entries appear as root JSON object members", Detail: "Fresh attributed native producer input maps and output bytes only. Root member placement is independent of the composite JSON value-conversion rules; arbitrary types, all representations, JSON-LD processing and whole conformance remain unestablished."}
	if err != nil {
		obs.Detail = "pipeline archive unavailable: " + err.Error()
		return obs
	}
	if len(result.Producer) != 1 {
		obs.Detail = "one actual producer call required"
		return obs
	}
	p := result.Producer[0]
	if p.Operation != pipelineProducer || p.Version != "1.1" || !p.JSONLD || p.IncludeSecret || p.Error != "" || p.CaptureError != "" {
		obs.Detail = "actual native producer attribution/options or capture unavailable"
		return obs
	}
	model, e := parse(p.Model)
	if e != nil {
		obs.Detail = e.Error()
		return obs
	}
	entries, e := parse(p.Entries)
	if e != nil {
		obs.Detail = e.Error()
		return obs
	}
	output, e := core.ParseJSON(p.Output)
	if e != nil || len(checks.DuplicateMembers(output)) > 0 || output.Kind != core.KindObject {
		obs.Verdict = core.Fail
		return obs
	}
	inputMaps, unique := combinedMaps(model.Value(), entries.Value())
	if !unique {
		obs.Detail = "overlapping input maps"
		return obs
	}
	obs.Verdict = core.Pass
	for _, m := range inputMaps.Object {
		if _, found := output.Get(m.Name); !found {
			obs.Verdict = core.Fail
		}
	}
	return obs
}
func judgeConsumption(result ConsumptionCapture, q ConsumptionRequest, id, version, input string) core.Observation {
	raw, _ := json.Marshal(result)
	obs := core.Observation{Statement: id, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual selected consumer uses the declared representation and rejects non-object document roots", Detail: "Direct pinned consumer used by SAGE integration, with literal public bytes and default options. Library actor boundary only, not SAGE resolver/ingress or all schema/value-conversion conformance. No generic cases, subject validator verdicts or fabricated resolution errors."}
	if result.Operation != pipelineConsumer || !bytes.Equal(result.Input, q.Data) || result.MediaType != q.MediaType || result.Require != "unknown" || result.Expected != "unknown" || result.Strict {
		obs.Detail = "mismatched actual input or consumer call attribution/options"
		return obs
	}
	source, err := core.ParseJSON(q.Data)
	if err != nil {
		obs.Detail = "inspection fixture must be valid JSON"
		return obs
	}
	if id == consumerRootStatement {
		if q.MediaType != "application/did" {
			obs.Detail = "DID 1.1 root observation requires application/did"
			return obs
		}
		if source.Kind == core.KindObject {
			obs.Detail = "non-object condition not applicable to this fixture"
			return obs
		}
		obs.Verdict = core.Fail
		if result.Error != "" && len(result.Model) == 0 && len(result.Entries) == 0 {
			obs.Verdict = core.Pass
		}
		return obs
	}
	if id != consumerMediaStatement || source.Kind != core.KindObject || (q.MediaType != "application/did" && q.MediaType != "application/did+json") {
		obs.Detail = "unsupported consumer media fixture"
		return obs
	}
	if result.CaptureError != "" {
		return obs
	}
	obs.Verdict = core.Fail
	if result.Error != "" || result.Version != version || result.JSONLD || len(result.DroppedTerms) > 0 {
		return obs
	}
	model, e := parse(result.Model)
	if e != nil {
		return obs
	}
	entries, e := parse(result.Entries)
	if e != nil {
		return obs
	}
	same, _ := checks.EqualJSON(source, model.Value())
	if same && len(entries.Members) == 0 {
		obs.Verdict = core.Pass
	}
	return obs
}
func appendConsumptionBoundaryCases(p *core.Profile, rows []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve", Input: record.DID, Accept: "application/did"}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-production-root-record-%d", p.Name, i), Profile: p.Name, Statements: []string{rootProductionStatement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			obs := core.Observation{Statement: rootProductionStatement, Input: string(input), Verdict: core.NotSupported, Detail: "no actual producer boundary operation"}
			s, ok := target.(PipelineSubject)
			if !ok {
				return []core.Observation{obs}
			}
			result, err := s.InspectPipeline(ctx, record, q)
			if err != nil {
				obs.Verdict = core.Error
				obs.Detail = err.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeProductionRoot(result, string(input))}
		}})
	}
	data, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{rows[0].DID})
	scenarios := []struct {
		name        string
		q           ConsumptionRequest
		id, version string
	}{
		{"media-did", ConsumptionRequest{data, "application/did"}, consumerMediaStatement, "1.1"},
		{"media-did-json", ConsumptionRequest{data, "application/did+json"}, consumerMediaStatement, "1.0"},
	}
	for i, literal := range []string{`[]`, `"text"`, `42`, `true`, `null`} {
		scenarios = append(scenarios, struct {
			name        string
			q           ConsumptionRequest
			id, version string
		}{fmt.Sprintf("nonobject-%d", i), ConsumptionRequest{[]byte(literal), "application/did"}, consumerRootStatement, ""})
	}
	for _, scenario := range scenarios {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/native-consumer-" + scenario.name, Profile: p.Name, Statements: []string{scenario.id}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(scenario.q)
			obs := core.Observation{Statement: scenario.id, Input: string(input), Verdict: core.NotSupported, Detail: "no actual selected consumer input operation"}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return []core.Observation{obs}
			}
			result, err := s.InspectConsumption(ctx, scenario.q)
			if err != nil {
				obs.Verdict = core.Error
				obs.Detail = err.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeConsumption(result, scenario.q, scenario.id, scenario.version, string(input))}
		}})
	}
}
