package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

func minimalRequest() RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: []byte(`{"id":"did:example:123"}`), MediaType: "application/did"}, Request: Request{Function: "resolve", Input: "did:example:123", Accept: "application/did"}}
}
func minimalProduction() TypedProductionRequest {
	return TypedProductionRequest{ID: "did:example:123", Version: "1.0", ControllerShape: "absent"}
}
func judgeMinimal(resolved RoutingResult, converted TypedProductionResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{"res10-crd20261001#resolving.6"}, core.Error, "Selected minimal root-library DID document, produced from a literal example driver and actually re-represented by the pinned producer using DID Core 1.0 JSON. Exact actual input/output models contain only the required absolute DID id; no optional controller, verification method, service, extensions or JSON-LD branch is present. All conditions of this minimal plain JSON representation are independently checked. This does not establish complete SAGE documents, registry authority, every representation, DID1.1 default media conformance or the unresolved algorithm result metadata conflict.", input, struct {
		Resolved  RoutingResult
		Converted TypedProductionResult
	}{resolved, converted})
	if !reflect.DeepEqual(resolved.Request, minimalRequest()) || resolved.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || resolved.Operation != "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve" || resolved.CaptureError != "" || !resolved.Result.HasContent || resolved.Result.ContentKind != "document" || resolved.Result.ReturnedID != "did:example:123" || len(converted.Calls) != 1 || converted.BuildError != "" || converted.CaptureError != "" || converted.ID != "did:example:123" {
		return obs
	}
	metadata, e := parse(resolved.Result.Metadata)
	representation, e2 := parse(resolved.Entries)
	if e != nil || e2 != nil || representation.Len() != 0 {
		return obs
	}
	if _, failed := metadata.Get("error"); failed {
		return obs
	}
	call := converted.Calls[0]
	if call.Operation != "github.com/sage-x-project/did-go/producer.Producer.Produce" || call.Version != "1.0" || call.JSONLD || call.IncludeSecret || call.Error != "" || call.CaptureError != "" {
		return obs
	}
	model, e := core.ParseJSON(resolved.DataModel)
	pre, e2 := core.ParseJSON(call.Model)
	entries, e3 := parse(call.Entries)
	wire, e4 := core.ParseJSON(call.Output)
	if e != nil || e2 != nil || e3 != nil || e4 != nil || entries.Len() != 0 {
		return obs
	}
	want := core.Object(core.M("id", core.String("did:example:123")))
	obs[0].Verdict = core.Fail
	if call.MediaType == "application/did+json" && equalObserved(model, want, "metadata") && equalObserved(pre, want, "metadata") && equalObserved(wire, want, "metadata") {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "Actual successful minimal document is capable of a fully conformant selected DID Core1.0 plain JSON representation"
	return obs
}
func appendMinimalCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-minimal-representation", Profile: p.Name, Statements: []string{"res10-crd20261001#resolving.6"}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q, production := minimalRequest(), minimalProduction()
		input, _ := json.Marshal(struct {
			Request    RoutingRequest
			Production TypedProductionRequest
		}{q, production})
		r, ok := target.(RoutingSubject)
		s, ok2 := target.(TypedProductionSubject)
		if !ok || !ok2 {
			return libraryUnavailable([]string{"res10-crd20261001#resolving.6"}, core.NotSupported, "requires actual root resolution and actual Core1.0 producer", string(input), nil)
		}
		resolved, e := r.InspectRouting(ctx, q)
		if e != nil {
			return libraryUnavailable([]string{"res10-crd20261001#resolving.6"}, core.Error, e.Error(), string(input), resolved)
		}
		converted, e := s.InspectTypedProduction(ctx, production)
		if e != nil {
			return libraryUnavailable([]string{"res10-crd20261001#resolving.6"}, core.Error, e.Error(), string(input), converted)
		}
		return judgeMinimal(resolved, converted, string(input))
	}})
}
