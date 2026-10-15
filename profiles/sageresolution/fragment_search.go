package sageresolution

import (
	"context"
	_ "embed"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

//go:embed fragment_search.json
var fragmentSearchBytes []byte

type fragmentSearchFixture struct {
	Name            string          `json:"name"`
	Document        json.RawMessage `json:"document"`
	ControlDocument json.RawMessage `json:"control_document"`
	Content         json.RawMessage `json:"expected_content"`
	Request         Request         `json:"request"`
}

func fragmentSearchFixtures() []fragmentSearchFixture {
	out := []fragmentSearchFixture{}
	_ = json.Unmarshal(fragmentSearchBytes, &out)
	return out
}

func fragmentSearchRequest(f fragmentSearchFixture, i int) RoutingRequest {
	doc := f.Document
	q := f.Request
	if i == 1 {
		doc = f.ControlDocument
	}
	if i == 2 {
		q.Input = "did:example:resources#absent"
	}
	return RoutingRequest{Document: ConsumptionRequest{Data: doc, MediaType: "application/did"}, Request: q}
}

// fragmentMatches is an independent every-map oracle over the fixed literal
// data model. It does not import or copy the subject's search helper.
func fragmentMatches(v core.Value, full, short string) []core.Value {
	out := []core.Value{}
	if v.Kind == core.KindObject {
		id, ok := v.Get("id")
		if ok && id.Kind == core.KindString && (id.Str == full || id.Str == short) {
			out = append(out, v)
		}
		for _, m := range v.Object {
			out = append(out, fragmentMatches(m.Value, full, short)...)
		}
	}
	if v.Kind == core.KindArray {
		for _, x := range v.Array {
			out = append(out, fragmentMatches(x, full, short)...)
		}
	}
	return out
}

func fragmentSearchWitness(f fragmentSearchFixture, i int, v RoutingResult) bool {
	q := fragmentSearchRequest(f, i)
	resource := resourceChoiceFixture{Document: q.Document.Data, Requests: []Request{q.Request}}
	if !resourceChoiceWitness(resource, 0, v) || !optionJSONEqual(v.ResolveOptions[0], `{"accept":"application/did"}`) {
		return false
	}
	actual, e := core.ParseJSON(v.DataModel)
	want, e1 := core.ParseJSON(q.Document.Data)
	entries, e2 := parse(v.Entries)
	if e != nil || e1 != nil || e2 != nil || entries.Len() != 0 || !equalObserved(actual, want, "unknown") {
		return false
	}
	raw, e3 := core.ParseJSON(v.Result.Raw)
	_, e4 := parse(v.Result.Metadata)
	_, e5 := parse(v.Result.ContentMetadata)
	return e3 == nil && e4 == nil && e5 == nil && v.Result.HasContent == (raw.Kind != core.KindNull)
}

func fragmentMatchedContent(v RoutingResult, want core.Value) bool {
	raw, e := core.ParseJSON(v.Result.Raw)
	md, e1 := parse(v.Result.Metadata)
	cm, e2 := parse(v.Result.ContentMetadata)
	if e != nil || e1 != nil || e2 != nil {
		return false
	}
	id, _ := want.Get("id")
	ct, _ := md.Get("contentType")
	_, failed := md.Get("error")
	return v.Result.HasContent && !failed && v.Result.ContentKind == "map" && v.Result.ReturnedID == id.Str && ct.Str == "application/ld+json" && cm.Len() == 0 && equalObserved(raw, want, "unknown")
}

func judgeFragmentSearch(f fragmentSearchFixture, v []RoutingResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{"cid10#fragment-resolution.4"}, core.Error, "Actual pinned root dereferencer with a fixed public literal example driver. The passive nested Resolve capture binds the same-call immutable data model before fragment processing. An independent every-map JSON oracle has one matching map; the same map relocated into an extension is a positive control and an absent identifier is a no-match control. Selected normal full-identifier map branches only. Not SAGE registry authority, all representations or an internal execution trace. A failure establishes the recursive-search obligation, not a particular internal return step.", input, v)
	known := false
	for _, candidate := range fragmentSearchFixtures() {
		if reflect.DeepEqual(candidate, f) {
			known = true
		}
	}
	if !known || len(v) != 3 {
		return obs
	}
	want, e := core.ParseJSON(f.Content)
	if e != nil {
		return obs
	}
	for i, x := range v {
		if !fragmentSearchWitness(f, i, x) {
			return obs
		}
		model, _ := core.ParseJSON(x.DataModel)
		matches := fragmentMatches(model, "did:example:resources#target", "#target")
		if len(matches) != 1 || !equalObserved(matches[0], want, "unknown") {
			return obs
		}
	}
	// The same normal nested map must be usable after relocation. A missing
	// or altered positive control cannot turn universal refusal into a FAIL.
	if !fragmentMatchedContent(v[1], want) {
		return obs
	}
	miss, e := core.ParseJSON(v[2].Result.Raw)
	md, e1 := parse(v[2].Result.Metadata)
	_, missing := md.Get("error")
	if e != nil || e1 != nil || miss.Kind != core.KindNull || v[2].Result.HasContent || !missing || !nativeErrorDescriptor(md) {
		return obs
	}
	if fragmentMatchedContent(v[0], want) {
		obs[0].Verdict = core.Pass
	} else {
		original, _ := core.ParseJSON(v[0].Result.Raw)
		problem, _ := parse(v[0].Result.Metadata)
		if original.Kind != core.KindNull || v[0].Result.HasContent || errorName(problem) != "https://www.w3.org/ns/did#NOT_FOUND" || !nativeErrorDescriptor(problem) {
			return obs
		}
		obs[0].Verdict = core.Fail
	}
	obs[0].Expected = "Recursively find and return the unique matching map preserved in the actual input document, including a map nested inside a verification method or service"
	return obs
}

func appendFragmentSearchCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range fragmentSearchFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/fragment-search-" + f.Name, Profile: p.Name, Statements: []string{"cid10#fragment-resolution.4"}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			s, ok := target.(RoutingSubject)
			if !ok {
				return libraryUnavailable([]string{"cid10#fragment-resolution.4"}, core.NotSupported, "no routing observer", string(input), nil)
			}
			values := []RoutingResult{}
			for i := 0; i < 3; i++ {
				v, e := s.InspectRouting(ctx, fragmentSearchRequest(f, i))
				values = append(values, v)
				if e != nil {
					return libraryUnavailable([]string{"cid10#fragment-resolution.4"}, core.Error, e.Error(), string(input), values)
				}
			}
			return judgeFragmentSearch(f, values, string(input))
		}})
	}
}
