package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

const injectionModel = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"]}`
const injectionWire = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"],"@context":"https://www.w3.org/ns/did/v1.1"}`
const contextInjectionID = "cid10#context-injection.1"
const contextInjectionCase = "did-1.1/sage-resolution/context-injection-no-context"

func contextInjectionRequest() TypedProductionRequest {
	return TypedProductionRequest{ID: "did:sage:web:registry.example:agent-1", Controllers: []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}, JSONLD: true}
}
func judgeContextInjection(ctx context.Context, v TypedProductionResult, input string) []core.Observation {
	q := contextInjectionRequest()
	raw, _ := json.Marshal(v)
	o := core.Observation{Statement: contextInjectionID, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual selected producer injects a context whose independently pinned bytes have all CID v1 declarations into the selected context-free input", Detail: "The no-context branch only: actual typed model/entries/options and same-call production output. The independently downloaded W3C context SHA-256 equals the CID publication's context digest, so its full declarations, not merely the URL spelling, are the premise. This is not full JSON-LD processing, already-resolved CID URL routing, RDF vocabulary use, partial/remote context repair, or SAGE production ingress."}
	if ctx.Err() != nil || !contextOracleReady() || v.BuildError != "" || v.CaptureError != "" || v.ID != q.ID || v.ControllerShape != "set" || !reflect.DeepEqual(v.Controllers, q.Controllers) || len(v.Fields) != 0 || len(v.Entries) != 0 || len(v.Calls) != 1 {
		return []core.Observation{o}
	}
	c := v.Calls[0]
	if c.Operation != pipelineProducer || c.Version != "1.1" || !c.JSONLD || c.IncludeSecret || c.CaptureError != "" || !optionJSONEqual(c.Model, injectionModel) || !optionJSONEqual(c.Entries, `{}`) {
		return []core.Observation{o}
	}
	if c.Error != "" || len(c.Output) == 0 {
		return []core.Observation{o}
	}
	if c.MediaType != "application/did" {
		return []core.Observation{o}
	}
	if optionJSONEqual(c.Output, injectionWire) {
		o.Verdict = core.Pass
	} else {
		value, e := parse(c.Output)
		if e != nil {
			o.Verdict = core.Fail
		} else if _, present := value.Get("@context"); !present {
			o.Verdict = core.Fail
		} else {
			contextValue, _ := value.Get("@context")
			o.Verdict = injectionContextVerdict(contextValue)
			o.Detail += " Other successful context declarations require an independent equivalence oracle."
		}
	}
	return []core.Observation{o}
}
func appendContextInjectionCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: contextInjectionCase, Profile: p.Name, Statements: []string{contextInjectionID}, Run: func(ctx context.Context, s core.Subject) []core.Observation {
		q := contextInjectionRequest()
		b, _ := json.Marshal(q)
		target, ok := s.(TypedProductionSubject)
		if !ok {
			return libraryUnavailable([]string{contextInjectionID}, core.NotSupported, "requires actual typed production", string(b), nil)
		}
		v, err := target.InspectTypedProduction(ctx, q)
		if err != nil {
			return libraryUnavailable([]string{contextInjectionID}, core.Error, err.Error(), string(b), v)
		}
		return judgeContextInjection(ctx, v, string(b))
	}})
}

// Empty/invalid contexts cannot supply the required declarations. Other valid
// declarations stay unsupported until independently compared in full.
func injectionContextVerdict(v core.Value) core.Verdict {
	switch v.Kind {
	case core.KindString:
		if v.Str != "" {
			return core.NotSupported
		}
	case core.KindObject:
		if len(v.Object) > 0 {
			return core.NotSupported
		}
	case core.KindArray:
		if len(v.Array) == 0 {
			return core.Fail
		}
		for _, item := range v.Array {
			if (item.Kind != core.KindString && item.Kind != core.KindObject) || (item.Kind == core.KindString && item.Str == "") {
				return core.Fail
			}
		}
		return core.NotSupported
	}
	return core.Fail
}
