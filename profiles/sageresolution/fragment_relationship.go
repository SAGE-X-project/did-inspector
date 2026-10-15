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

var fragmentRelationshipIDs = []string{"res10-crd20261001#dereferencing-algorithm-fragment.1", "res10-crd20261001#dereferencing-algorithm-fragment.2"}

//go:embed fragment_relationship.json
var relationshipBytes []byte

//go:embed fragment_relationship_witness.json
var relationshipWitnessBytes []byte

type relationshipFixture struct {
	Name     string          `json:"name"`
	Document json.RawMessage `json:"document"`
	Request  Request         `json:"request"`
	Kind     string          `json:"expected_kind"`
	Content  json.RawMessage `json:"expected_content"`
	Error    string          `json:"diagnostic_error"`
}
type relationshipEvidence struct {
	Source  fragmentSourceEvidence                `json:"source_evidence"`
	Audit   sourcearith.FragmentRelationshipAudit `json:"audit"`
	Runtime []RoutingResult                       `json:"runtime"`
}

func relationshipFixtures() []relationshipFixture {
	var f []relationshipFixture
	_ = json.Unmarshal(relationshipBytes, &f)
	return f
}
func relationshipRequest(f relationshipFixture) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Request}
}
func relationshipOptions(f relationshipFixture) ([]byte, []byte) {
	o := map[string]any{"accept": "application/did"}
	nested := map[string]any{"accept": "application/did"}
	if f.Request.Relationship != "" {
		o["verificationRelationship"] = f.Request.Relationship
		nested["verificationRelationship"] = f.Request.Relationship
	}
	a, _ := json.Marshal(o)
	b, _ := json.Marshal(nested)
	return a, b
}
func relationshipRuntime(values []RoutingResult) bool {
	fs := relationshipFixtures()
	if len(values) != len(fs) {
		return false
	}
	for i, v := range values {
		f := fs[i]
		incoming, nested := relationshipOptions(f)
		if !reflect.DeepEqual(v.Request, relationshipRequest(f)) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != IntegerSourceModule+"/dereferencer.Dereferencer.Dereference" || v.CaptureError != "" || v.Result.Native != nil || v.Result.Exchange != nil || !optionJSONEqual(v.Options, string(incoming)) || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != "did:example:resources" || len(v.ResolveOptions) != 1 || !optionJSONEqual(v.ResolveOptions[0], string(nested)) || len(v.DriverInputs) != 1 || v.DriverInputs[0] != "did:example:resources" || len(v.DriverOptions) != 1 || !optionJSONEqual(v.DriverOptions[0], `{"VersionID":"","VersionTime":null,"MediaType":"application/did","NoCache":false}`) || len(v.DriverResults) != 1 {
			return false
		}
		read, e := parse(v.DriverResults[0])
		if e != nil {
			return false
		}
		ct, _ := read.Get("ContentType")
		body, _ := read.Get("Data")
		data, e := base64.StdEncoding.DecodeString(body.Str)
		if e != nil || ct.Str != "application/did" || !optionJSONEqual(data, string(f.Document)) || !optionJSONEqual(v.DataModel, string(f.Document)) || !optionJSONEqual(v.Entries, `{}`) {
			return false
		}
		md, e := parse(v.Result.Metadata)
		cm, e1 := parse(v.Result.ContentMetadata)
		raw, e2 := core.ParseJSON(v.Result.Raw)
		if e != nil || e1 != nil || e2 != nil || cm.Len() != 0 {
			return false
		}
		if f.Error != "" {
			if v.Result.HasContent || raw.Kind != core.KindNull || errorName(md) != "https://w3id.org/security#"+f.Error {
				return false
			}
			continue
		}
		want, _ := core.ParseJSON(f.Content)
		ct, _ = md.Get("contentType")
		_, failed := md.Get("error")
		kind := "method"
		if f.Kind == "map" {
			kind = "unknown"
		}
		id, _ := want.Get("id")
		if !v.Result.HasContent || failed || v.Result.ContentKind != f.Kind || v.Result.ReturnedID != id.Str || ct.Str != "application/ld+json" || !equalObserved(raw, want, kind) {
			return false
		}
	}
	return true
}
func relationshipVerdict(a sourcearith.FragmentRelationshipAudit, index int) core.Verdict {
	var w sourcearith.FragmentRelationshipAudit
	if json.Unmarshal(relationshipWitnessBytes, &w) != nil || a.Root != w.Root || a.Frame != w.Frame || !reflect.DeepEqual(a.Roles, w.Roles) || len(a.Unknown) != 0 || len(a.Steps) != 2 || index < 0 || index > 1 {
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
func judgeRelationship(ctx context.Context, e relationshipEvidence, input string) []core.Observation {
	obs := libraryUnavailable(fragmentRelationshipIDs, core.Error, "Selected fixed-source nonempty typed verificationRelationship option on a resolved document: type dispatch and guard, exact option-to-local-to-selection argument roles. Fresh referenced/embedded selection, other valid relationship refusal, no-fragment refusal and absent-option map control. Empty-option presence, complete retrieval/media semantics, authority, all inputs and physical execution trace remain separate. Diagnostic errors bind the selected player; these two construction steps prescribe no error type.", input, e)
	prior := judgeFragmentSource(ctx, e.Source, input)
	var checked fragmentSourceEvidence
	if len(prior) != 3 || json.Unmarshal([]byte(prior[0].Observed), &checked) != nil || checked.Error != "" || fragmentSourceVerdict(checked.Audit, 2) != core.Pass || fragmentRuntime(checked.Runtime) != core.Pass || !relationshipRuntime(e.Runtime) {
		return obs
	}
	e.Source = checked
	p := sourcearith.NewProgram(ctx, IntegerSourceModule, checked.Source.Files)
	if _, err := p.Import(IntegerSourceModule + "/dereferencer"); err != nil {
		return obs
	}
	e.Audit = p.FragmentRelationshipAudit(IntegerSourceModule + "/dereferencer.(*" + IntegerSourceModule + "/dereferencer.Dereferencer).fragment")
	raw, _ := json.Marshal(e)
	canceled := ctx.Err() != nil
	for i := range obs {
		obs[i].Observed = string(raw)
		if !canceled {
			obs[i].Verdict = relationshipVerdict(e.Audit, i)
		}
		obs[i].Expected = "Selected resolved-document/nonempty-option branch and exact typed relationship value, under the fixed unchanged caller and helper source context"
	}
	return obs
}
func appendFragmentRelationshipCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/fragment-relationship-source", Profile: p.Name, Statements: fragmentRelationshipIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := fragmentSourceRequest()
		input, _ := json.Marshal(q)
		e := relationshipEvidence{Runtime: []RoutingResult{}, Source: fragmentSourceEvidence{Compiler: runtime.Version(), Architecture: runtime.GOARCH, Runtime: [][]RoutingResult{}}}
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		if !ok || !ok1 {
			return libraryUnavailable(fragmentRelationshipIDs, core.NotSupported, "no source and relationship observers", string(input), e)
		}
		fail := func(err error) []core.Observation {
			return libraryUnavailable(fragmentRelationshipIDs, core.Error, err.Error(), string(input), e)
		}
		var err error
		e.Source.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			return fail(err)
		}
		for _, f := range fragmentFixtures() {
			values := []RoutingResult{}
			for i := range f.Requests {
				v, err := routing.InspectRouting(ctx, resourceChoiceRequest(f, i))
				values = append(values, v)
				if err != nil {
					e.Source.Runtime = append(e.Source.Runtime, values)
					return fail(err)
				}
			}
			e.Source.Runtime = append(e.Source.Runtime, values)
		}
		for _, f := range relationshipFixtures() {
			v, err := routing.InspectRouting(ctx, relationshipRequest(f))
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				return fail(err)
			}
		}
		return judgeRelationship(ctx, e, string(input))
	}})
}
