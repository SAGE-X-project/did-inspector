package sageresolution

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

var selectionIDs = []string{"res10-crd20261001#dereferencing-algorithm-resource.17", "res10-crd20261001#dereferencing-algorithm-resource.21", "res10-crd20261001#dereferencing-algorithm-resource.29", "res10-crd20261001#dereferencing-algorithm-resource.35"}

//go:embed selection.json
var selectionBytes []byte

//go:embed selection_witness.json
var selectionWitnessBytes []byte

type selectionFixture struct {
	Name       string          `json:"name"`
	Document   json.RawMessage `json:"document"`
	Request    Request         `json:"request"`
	Parameters map[string]any  `json:"parameters"`
	Kind       string          `json:"expected_kind"`
	Content    json.RawMessage `json:"expected_content"`
	Error      string          `json:"diagnostic_error"`
}
type selectionEvidence struct {
	Source  fragmentSourceEvidence   `json:"source_evidence"`
	Audit   sourcearith.ServiceAudit `json:"audit"`
	Runtime []RoutingResult          `json:"runtime"`
}

func selectionFixtures() []selectionFixture {
	var out []selectionFixture
	_ = json.Unmarshal(selectionBytes, &out)
	return out
}
func selectionRequest(f selectionFixture) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Request}
}
func selectionMedia(accept string) bool {
	return accept == "application/did" || accept == "application/did+json" || accept == "application/did+ld+json"
}
func selectionRuntime(values []RoutingResult) bool {
	fs := selectionFixtures()
	if len(fs) != len(values) {
		return false
	}
	for i, v := range values {
		f := fs[i]
		q := f.Request
		if !reflect.DeepEqual(v.Request, selectionRequest(f)) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != "github.com/sage-x-project/did-go/dereferencer.Dereferencer.Dereference" || v.CaptureError != "" || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != "did:example:resources" || len(v.DriverInputs) != 1 || v.DriverInputs[0] != "did:example:resources" || len(v.ResolveOptions) != 1 || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || v.Result.Native != nil || v.Result.Exchange != nil {
			return false
		}
		incoming := map[string]any{}
		nested := map[string]any{}
		driverMedia := ""
		resolvedMedia := "application/did"
		if q.Accept != "" {
			incoming["accept"] = q.Accept
		}
		if selectionMedia(q.Accept) {
			nested["accept"] = q.Accept
			if q.Accept == "application/did" {
				driverMedia = q.Accept
			}
			resolvedMedia = q.Accept
		}
		for k, val := range f.Parameters {
			nested[k] = val
		}
		a, _ := json.Marshal(incoming)
		b, _ := json.Marshal(nested)
		d, _ := json.Marshal(map[string]any{"VersionID": "", "VersionTime": nil, "MediaType": driverMedia, "NoCache": false})
		md, _ := json.Marshal(map[string]any{"contentType": resolvedMedia})
		if !optionJSONEqual(v.Options, string(a)) || !optionJSONEqual(v.ResolveOptions[0], string(b)) || !optionJSONEqual(v.DriverOptions[0], string(d)) || !optionJSONEqual(v.ResolvedMetadata, string(md)) || !optionJSONEqual(v.ResolvedDataModel, string(f.Document)) || !optionJSONEqual(v.ResolvedEntries, `{}`) {
			return false
		}
		read, e := parse(v.DriverResults[0])
		ct, _ := read.Get("ContentType")
		data, _ := read.Get("Data")
		body, e1 := base64.StdEncoding.DecodeString(data.Str)
		if e != nil || e1 != nil || ct.Str != "application/did" || !optionJSONEqual(body, string(f.Document)) {
			return false
		}
		meta, e := parse(v.Result.Metadata)
		content, e1 := core.ParseJSON(v.Result.Raw)
		if e != nil || e1 != nil {
			return false
		}
		if f.Error != "" {
			if v.Result.HasContent || content.Kind != core.KindNull || errorName(meta) != "https://www.w3.org/ns/did#"+f.Error {
				return false
			}
			continue
		}
		want, _ := core.ParseJSON(f.Content)
		ct, _ = meta.Get("contentType")
		_, failed := meta.Get("error")
		media := q.Accept
		if media == "" {
			media = "application/did"
		}
		if !v.Result.HasContent || failed || ct.Str != media || v.Result.ContentKind != f.Kind || !equalObserved(content, want, "unknown") {
			return false
		}
		if f.Kind == "document" {
			if v.Result.ReturnedID != "did:example:resources" || !optionJSONEqual(v.Result.ContentMetadata, `{}`) || !optionJSONEqual(v.DataModel, string(f.Content)) || !optionJSONEqual(v.Entries, `{}`) {
				return false
			}
		} else if !optionJSONEqual(v.Result.ContentMetadata, `{"contentType":"text/uri-list"}`) {
			return false
		}
	}
	return true
}
func selectionVerdict(a sourcearith.ServiceAudit, index int) core.Verdict {
	var w sourcearith.ServiceAudit
	if json.Unmarshal(selectionWitnessBytes, &w) != nil || !reflect.DeepEqual(a.Roots, w.Roots) || !reflect.DeepEqual(a.Frames, w.Frames) || !reflect.DeepEqual(a.Roles, w.Roles) || !reflect.DeepEqual(a.CallPaths, w.CallPaths) || len(a.Unknown) != 0 || len(a.Steps) != 4 || index < 0 || index >= 4 {
		return core.Error
	}
	if a.Steps[index].Kind != w.Steps[index].Kind {
		return core.Error
	}
	if !a.Steps[index].Correct {
		return core.Fail
	}
	return core.Pass
}
func judgeSelection(ctx context.Context, e selectionEvidence, input string) []core.Observation {
	obs := libraryUnavailable(selectionIDs, core.Error, "Selected list/filter roles, traversal of each selected service and exact single-media/absent accept document-versus-URI-list branches. Fixed source, reviewed helper/default/negotiation context, finite DID/URI offers and actual original resolved model/metadata are prerequisites. Fresh public literal calls corroborate the roles, including distinct matching services. No broad matching/RFC3986/RFC9110, wildcard/q, all media, authority or physical runtime trace. Player error/option forwarding behavior is diagnostic, not new MUSTs of these phase clauses. No modified subject or external endpoint fetch", input, e)
	if !selectionRuntime(e.Runtime) {
		return obs
	}
	prior := judgeFragmentSource(ctx, e.Source, input)
	var checked fragmentSourceEvidence
	if len(prior) != 3 || json.Unmarshal([]byte(prior[0].Observed), &checked) != nil || checked.Error != "" || fragmentSourceVerdict(checked.Audit, 2) != core.Pass || fragmentRuntime(checked.Runtime) != core.Pass {
		return obs
	}
	e.Source = checked
	p := sourcearith.NewProgram(ctx, IntegerSourceModule, checked.Source.Files)
	if _, err := p.Import(IntegerSourceModule + "/dereferencer"); err != nil {
		return obs
	}
	e.Audit = p.SelectionAudit()
	raw, _ := json.Marshal(e)
	canceled := ctx.Err() != nil
	for i := range obs {
		obs[i].Observed = string(raw)
		if !canceled {
			obs[i].Verdict = selectionVerdict(e.Audit, i)
		}
		obs[i].Expected = "Actual selected list and range, and exact accepted media partition under fixed helper and normal typed-input premises"
	}
	return obs
}
func appendSelectionCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/selection-source-roles", Profile: p.Name, Statements: selectionIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := fragmentSourceRequest()
		input, _ := json.Marshal(q)
		e := selectionEvidence{Source: fragmentSourceEvidence{Compiler: runtime.Version(), Architecture: runtime.GOARCH, Runtime: [][]RoutingResult{}}, Runtime: []RoutingResult{}}
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		if !ok || !ok1 {
			return libraryUnavailable(selectionIDs, core.NotSupported, "no source and service observers", string(input), e)
		}
		fail := func(err error) []core.Observation {
			return libraryUnavailable(selectionIDs, core.Error, err.Error(), string(input), e)
		}
		var err error
		e.Source.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			return fail(err)
		}
		for _, f := range fragmentFixtures() {
			vs := []RoutingResult{}
			for i := range f.Requests {
				v, err := routing.InspectRouting(ctx, resourceChoiceRequest(f, i))
				vs = append(vs, v)
				if err != nil {
					e.Source.Runtime = append(e.Source.Runtime, vs)
					return fail(err)
				}
			}
			e.Source.Runtime = append(e.Source.Runtime, vs)
		}
		for _, f := range selectionFixtures() {
			v, err := routing.InspectRouting(ctx, selectionRequest(f))
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				return fail(err)
			}
		}
		return judgeSelection(ctx, e, string(input))
	}})
}
