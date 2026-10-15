package sageresolution

import (
	"context"
	_ "embed"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

var serviceSourceIDs = []string{"res10-crd20261001#dereferencing-algorithm-resource.16", "res10-crd20261001#dereferencing-algorithm-resource.20", "res10-crd20261001#dereferencing-algorithm-resource.26", "res10-crd20261001#dereferencing-algorithm-resource.27"}

//go:embed service_source.json
var serviceSourceBytes []byte

//go:embed service_source_witness.json
var serviceSourceWitnessBytes []byte

type serviceFixture struct {
	Name       string          `json:"name"`
	Document   json.RawMessage `json:"document"`
	Request    Request         `json:"request"`
	Parameters map[string]any  `json:"parameters"`
	Kind       string          `json:"expected_kind"`
	Content    json.RawMessage `json:"expected_content"`
	Error      string          `json:"diagnostic_error"`
}
type serviceEvidence struct {
	Source  fragmentSourceEvidence   `json:"source_evidence"`
	Audit   sourcearith.ServiceAudit `json:"audit"`
	Runtime []RoutingResult          `json:"runtime"`
}

func serviceFixtures() []serviceFixture {
	var out []serviceFixture
	_ = json.Unmarshal(serviceSourceBytes, &out)
	return out
}
func serviceRequest(f serviceFixture) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Request}
}
func serviceRuntime(values []RoutingResult) bool {
	fs := serviceFixtures()
	if len(fs) != len(values) {
		return false
	}
	for i, v := range values {
		f := fs[i]
		fixture := resourceChoiceFixture{Document: f.Document, Requests: []Request{f.Request}}
		if !resourceChoiceWitness(fixture, 0, v) || !reflect.DeepEqual(v.Request, serviceRequest(f)) {
			return false
		}
		nested := map[string]any{}
		if f.Request.Accept == "application/did" {
			nested["accept"] = "application/did"
		}
		for k, val := range f.Parameters {
			nested[k] = val
		}
		b, _ := json.Marshal(nested)
		if !optionJSONEqual(v.ResolveOptions[0], string(b)) || !optionJSONEqual(v.DataModel, string(f.Document)) || !optionJSONEqual(v.Entries, `{}`) {
			return false
		}
		md, e := parse(v.Result.Metadata)
		cm, e1 := parse(v.Result.ContentMetadata)
		got, e2 := core.ParseJSON(v.Result.Raw)
		if e != nil || e1 != nil || e2 != nil {
			return false
		}
		if f.Error != "" {
			if v.Result.HasContent || got.Kind != core.KindNull || errorName(md) != "https://www.w3.org/ns/did#"+f.Error {
				return false
			}
			continue
		}
		want, _ := core.ParseJSON(f.Content)
		ct, _ := md.Get("contentType")
		_, failed := md.Get("error")
		media := "text/uri-list"
		if f.Kind == "document" {
			media = "application/did"
		}
		if !v.Result.HasContent || failed || ct.Str != media || v.Result.ContentKind != f.Kind || !equalObserved(got, want, "unknown") {
			return false
		}
		if f.Kind == "uri-list" {
			if !optionJSONEqual(v.Result.ContentMetadata, `{"contentType":"text/uri-list"}`) {
				return false
			}
		} else {
			if cm.Len() != 0 || v.Result.ReturnedID != "did:example:resources" {
				return false
			}
		}
	}
	return true
}
func serviceVerdict(a sourcearith.ServiceAudit, index int) core.Verdict {
	var w sourcearith.ServiceAudit
	if json.Unmarshal(serviceSourceWitnessBytes, &w) != nil || !reflect.DeepEqual(a.Roots, w.Roots) || !reflect.DeepEqual(a.Frames, w.Frames) || !reflect.DeepEqual(a.Roles, w.Roles) || !reflect.DeepEqual(a.CallPaths, w.CallPaths) || len(a.Unknown) != 0 || len(a.Steps) != 4 || index < 0 || index >= 4 {
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
func judgeServiceSource(ctx context.Context, e serviceEvidence, input string) []core.Observation {
	obs := libraryUnavailable(serviceSourceIDs, core.Error, "Fixed-source selected service/serviceType presence OR and relativeRef presence fallthrough, endpoint URL-to-parser/base receiver and relativeRef-to-parser/reference operand roles. Normal typed document, selected string HTTPS endpoints and literal ASCII relative references, including empty presence, under unchanged independently reviewed collection/caller/error/helper context and trusted Go parser role. Fresh ordinary library calls corroborate these phases. No external endpoint fetch, whole service selection/RFC3986 equivalence, all inputs, authority or physical runtime trace. Player error/option-forwarding diagnostics are prerequisites, not new MUSTs of these construction steps.", input, e)
	prior := judgeFragmentSource(ctx, e.Source, input)
	var checked fragmentSourceEvidence
	if len(prior) != 3 || json.Unmarshal([]byte(prior[0].Observed), &checked) != nil || checked.Error != "" || fragmentSourceVerdict(checked.Audit, 2) != core.Pass || fragmentRuntime(checked.Runtime) != core.Pass || !serviceRuntime(e.Runtime) {
		return obs
	}
	e.Source = checked
	p := sourcearith.NewProgram(ctx, IntegerSourceModule, checked.Source.Files)
	if _, err := p.Import(IntegerSourceModule + "/dereferencer"); err != nil {
		return obs
	}
	e.Audit = p.ServiceAudit()
	raw, _ := json.Marshal(e)
	canceled := ctx.Err() != nil
	for i := range obs {
		obs[i].Observed = string(raw)
		if !canceled {
			obs[i].Verdict = serviceVerdict(e.Audit, i)
		}
		obs[i].Expected = "Selected actual parameter guards and exact endpoint/reference parser operands under the independently fixed caller, collection and standard Go-library premises"
	}
	return obs
}
func appendServiceSourceCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/service-source-roles", Profile: p.Name, Statements: serviceSourceIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := fragmentSourceRequest()
		input, _ := json.Marshal(q)
		e := serviceEvidence{Source: fragmentSourceEvidence{Compiler: runtime.Version(), Architecture: runtime.GOARCH, Runtime: [][]RoutingResult{}}, Runtime: []RoutingResult{}}
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		if !ok || !ok1 {
			return libraryUnavailable(serviceSourceIDs, core.NotSupported, "no source and service observers", string(input), e)
		}
		fail := func(err error) []core.Observation {
			return libraryUnavailable(serviceSourceIDs, core.Error, err.Error(), string(input), e)
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
		for _, f := range serviceFixtures() {
			v, err := routing.InspectRouting(ctx, serviceRequest(f))
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				return fail(err)
			}
		}
		return judgeServiceSource(ctx, e, string(input))
	}})
}
