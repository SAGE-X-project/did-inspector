package sageresolution

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

//go:embed expansion_document.json
var expansionDocument []byte

//go:embed expansion_expected.json
var expansionExpected []byte
var expansionIDs = []string{"res10-crd20261001#resolving-algorithm.30", "res10-crd20261001#resolving-algorithm.31", "res10-crd20261001#resolving-algorithm.17", "res10-crd20261001#resolving-algorithm.34"}

func expansionRequest(enabled bool) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: expansionDocument, MediaType: "application/did"}, Request: Request{Function: "resolve", Input: "did:example:123", Accept: "application/did", Options: map[string]any{"expandRelativeUrls": enabled}}}
}
func judgeExpansion(values []RoutingResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{expansionIDs[0], expansionIDs[1], expansionIDs[3]}, core.Error, "Actual selected root library with literal example driver. Fixed relative references in service, verification method, purpose relationship and nested extension maps are compared with independent absolute DID URL literals. Both disabled and enabled outputs and driver inputs are observed. Internal iteration/order/conditional steps are not inferred, and this fixture is not a SAGE method or operational registry.", input, values)
	if len(values) != 2 {
		return obs
	}
	pass := true
	urlsCorrect := true
	for i, v := range values {
		q := expansionRequest(i == 1)
		if !reflect.DeepEqual(v.Request, q) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve" || v.CaptureError != "" || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != "did:example:123" || len(v.DriverOptions) != 1 || len(v.ResolveOptions) != 1 {
			return obs
		}
		options, e := parse(v.Options)
		if e != nil {
			return obs
		}
		enabled, _ := options.Get("expandRelativeUrls")
		if (i == 1 && (enabled.Kind != core.KindBool || !enabled.Bool)) || (i == 0 && enabled.Kind != core.KindNull && (enabled.Kind != core.KindBool || enabled.Bool)) {
			return obs
		}
		forwarded, e := core.ParseJSON(v.ResolveOptions[0])
		if e != nil || !equalObserved(forwarded, options.Value(), "metadata") {
			return obs
		}
		if i == 0 {
			continue
		} // Disabled output is diagnostic evidence, not the enabled-branch oracle.
		md, e := parse(v.Result.Metadata)
		model, e2 := core.ParseJSON(v.DataModel)
		entries, e3 := parse(v.Entries)
		if e != nil || e2 != nil || e3 != nil || entries.Len() != 0 {
			return obs
		}
		if _, failed := md.Get("error"); failed {
			return obs
		}
		ct, _ := md.Get("contentType")
		if !v.Result.HasContent || v.Result.ReturnedID != "did:example:123" || ct.Str != "application/did" {
			return obs
		}
		expected := expansionDocument
		if i == 1 {
			expected = expansionExpected
		}
		want, _ := core.ParseJSON(expected)
		if i == 1 {
			pass = pass && equalObserved(model, want, "metadata")
			urlsCorrect = expansionURLsCorrect(model)
		}
	}
	for i := range obs {
		obs[i].Verdict = core.Fail
		if (i < 2 && urlsCorrect) || (i == 2 && pass) {
			obs[i].Verdict = core.Pass
		}
		obs[i].Expected = "Independently resolved absolute references in the actual enabled output; disabled output is diagnostic only"
	}
	return obs
}
func expansionURLsCorrect(v core.Value) bool {
	paths := [][]string{{"verificationMethod", "0", "id"}, {"authentication", "0"}, {"service", "0", "id"}, {"extension", "id"}, {"extension", "nested", "0", "id"}}
	expected := []string{"did:example:123#sign", "did:example:123#sign", "did:example:123#one", "did:example:123/relative?scope=one#piece", "did:example:123#extension"}
	for i, path := range paths {
		x := v
		for _, part := range path {
			if part == "0" {
				if x.Kind != core.KindArray || len(x.Array) == 0 {
					return false
				}
				x = x.Array[0]
			} else {
				var ok bool
				x, ok = x.Get(part)
				if !ok {
					return false
				}
			}
		}
		if x.Kind != core.KindString || x.Str != expected[i] {
			return false
		}
	}
	return true
}
func judgeMethodRead(values []RoutingResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{"res10-crd20261001#resolving-algorithm.17"}, core.Error, "Actual root library method Read invocation on the explicitly literal example driver. Input DID, read options and returned raw document are independently observed; no SAGE registry/method authority or later output conformance is established.", input, values)
	if len(values) != 2 {
		return obs
	}
	for i, v := range values {
		if !reflect.DeepEqual(v.Request, expansionRequest(i == 1)) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve" || len(v.DriverOptions) != 1 {
			return obs
		}
		opts, e := parse(v.DriverOptions[0])
		if e != nil {
			return obs
		}
		media, _ := opts.Get("MediaType")
		if media.Str != "application/did" {
			return obs
		}
	}
	methodCalled := true
	for _, v := range values {
		if len(v.DriverInputs) != 1 || v.DriverInputs[0] != "did:example:123" || len(v.DriverResults) != 1 {
			return obs
		}
		read, e := parse(v.DriverResults[0])
		if e != nil {
			return obs
		}
		ct, _ := read.Get("ContentType")
		data, _ := read.Get("Data")
		if ct.Str != "application/did" || data.Kind != core.KindString {
			return obs
		}
		source, e := base64.StdEncoding.DecodeString(data.Str)
		if e != nil {
			return obs
		}
		actual, e := core.ParseJSON(source)
		want, _ := core.ParseJSON(expansionDocument)
		methodCalled = methodCalled && e == nil && equalObserved(actual, want, "metadata")
	}

	obs[0].Verdict = core.Fail
	if methodCalled {
		obs[0].Verdict = core.Pass
	}
	obs[0].Expected = "Actual selected method Read with the input DID and literal returned document"
	return obs
}
func appendExpansionCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-expansion-output", Profile: p.Name, Statements: expansionIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		qs := []RoutingRequest{expansionRequest(false), expansionRequest(true)}
		input, _ := json.Marshal(qs)
		s, ok := target.(RoutingSubject)
		if !ok {
			return libraryUnavailable(expansionIDs, core.NotSupported, "no selected root routing library", string(input), nil)
		}
		values := []RoutingResult{}
		for _, q := range qs {
			v, e := s.InspectRouting(ctx, q)
			values = append(values, v)
			if e != nil {
				return libraryUnavailable(expansionIDs, core.Error, e.Error(), string(input), values)
			}
		}
		return append(judgeExpansion(values, string(input)), judgeMethodRead(values, string(input))...)
	}})
}
