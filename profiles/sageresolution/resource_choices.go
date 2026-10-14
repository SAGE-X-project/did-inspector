package sageresolution

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

//go:embed resource_choices.json
var resourceChoiceBytes []byte

type resourceChoiceFixture struct {
	Name       string          `json:"name"`
	Statement  string          `json:"statement"`
	Document   json.RawMessage `json:"document"`
	Requests   []Request       `json:"requests"`
	Content    json.RawMessage `json:"expected_content"`
	Kind       string          `json:"expected_kind"`
	ID         string          `json:"expected_id"`
	Media      string          `json:"expected_media"`
	Parameters map[string]any  `json:"expected_parameters"`
}

func resourceChoiceFixtures() []resourceChoiceFixture {
	out := []resourceChoiceFixture{}
	_ = json.Unmarshal(resourceChoiceBytes, &out)
	return out
}
func resourceChoiceRequest(f resourceChoiceFixture, i int) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Requests[i]}
}
func resourceChoiceWitness(f resourceChoiceFixture, i int, v RoutingResult) bool {
	if !reflect.DeepEqual(v.Request, resourceChoiceRequest(f, i)) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference" || v.CaptureError != "" || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != "did:example:resources" || len(v.ResolveOptions) != 1 || len(v.DriverInputs) != 1 || v.DriverInputs[0] != "did:example:resources" || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || v.Result.Native != nil || v.Result.Exchange != nil {
		return false
	}
	incoming, e := parse(v.Options)
	if e != nil {
		return false
	}
	q := f.Requests[i]
	wantIncoming, _ := json.Marshal(map[string]any{"accept": q.Accept})
	if !optionJSONEqual(v.Options, string(wantIncoming)) || incoming.Len() != 1 {
		return false
	}
	if _, e := parse(v.ResolveOptions[0]); e != nil {
		return false
	}
	// Nested option values are diagnostics here. Their transparent forwarding
	// is judged by its separate MUST, not by this optional capability.
	read, e := parse(v.DriverResults[0])
	if e != nil {
		return false
	}
	ct, _ := read.Get("ContentType")
	body, _ := read.Get("Data")
	raw, e := base64.StdEncoding.DecodeString(body.Str)
	if e != nil || ct.Str != "application/did" || !optionJSONEqual(raw, string(f.Document)) {
		return false
	}
	wantMedia := ""
	if q.Accept == "application/did" {
		wantMedia = "application/did"
	}
	driver, _ := json.Marshal(map[string]any{"VersionID": "", "VersionTime": nil, "MediaType": wantMedia, "NoCache": false})
	return optionJSONEqual(v.DriverOptions[0], string(driver))
}
func judgeResourceChoice(f resourceChoiceFixture, values []RoutingResult, input string) []core.Observation {
	obs := libraryUnavailable([]string{f.Statement}, core.Error, "Actual pinned root dereferencer with literal example driver. Selected returned document, verification method, service, nested map or service/serviceType/relativeRef capability with typed resource and declared media witnesses. Not SAGE Source, operational authority/history, every parameter/format, external endpoint retrieval, complete JSON-LD processing or internal algorithm trace. Optional refusal is NOT_SUPPORTED; missing/mismatched provenance is ERROR. Control outcomes are diagnostic only.", input, values)
	known := false
	for _, q := range resourceChoiceFixtures() {
		if reflect.DeepEqual(f, q) {
			known = true
		}
	}
	if !known || len(values) != 2 {
		return obs
	}
	for i, v := range values {
		if !resourceChoiceWitness(f, i, v) {
			return obs
		}
	}
	v := values[0]
	md, e := parse(v.Result.Metadata)
	if e != nil {
		return obs
	}
	cm, e := parse(v.Result.ContentMetadata)
	if e != nil {
		return obs
	}
	// The diagnostic control is archived after its actual call; its absence or
	// addition of resource/error metadata cannot invent an obligation of MAY.
	obs[0].Verdict = core.NotSupported
	_, failed := md.Get("error")
	if failed || !v.Result.HasContent {
		return obs
	}
	ct, _ := md.Get("contentType")
	if ct.Kind != core.KindString || ct.Str != f.Media || v.Result.ContentKind != f.Kind || v.Result.ReturnedID != f.ID {
		return obs
	}
	got, e := core.ParseJSON(v.Result.Raw)
	if e != nil {
		obs[0].Verdict = core.Error
		return obs
	}
	if f.Kind == "document" {
		model, e := core.ParseJSON(v.DataModel)
		if e != nil || !optionJSONEqual(v.Entries, `{}`) || !equalObserved(got, model, "document") {
			obs[0].Verdict = core.Error
			return obs
		}
	}
	want, _ := core.ParseJSON(f.Content)
	kind := f.Kind
	if kind == "verification-method" {
		kind = "method"
	}
	if kind == "map" {
		kind = "unknown"
	}
	if !equalObserved(got, want, kind) {
		return obs
	}
	if f.Kind == "uri-list" {
		media, _ := cm.Get("contentType")
		if media.Str != "text/uri-list" {
			return obs
		}
	}
	obs[0].Verdict = core.Pass
	obs[0].Expected = "Actual selected typed resource and media match independent public literals, or selected DID parameters produce their expected filtered document/URL list"
	return obs
}
func appendResourceChoiceCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range resourceChoiceFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/resource-choice-%s", p.Name, f.Name), Profile: p.Name, Statements: []string{f.Statement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			s, ok := target.(RoutingSubject)
			if !ok {
				return libraryUnavailable([]string{f.Statement}, core.NotSupported, "no actual root dereferencer observer", string(input), nil)
			}
			values := []RoutingResult{}
			for i := range f.Requests {
				v, e := s.InspectRouting(ctx, resourceChoiceRequest(f, i))
				values = append(values, v)
				if e != nil {
					return libraryUnavailable([]string{f.Statement}, core.Error, e.Error(), string(input), values)
				}
			}
			return judgeResourceChoice(f, values, string(input))
		}})
	}
}
