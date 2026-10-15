package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

const fragmentMediaID = "res10-crd20261001#dereferencing-algorithm-fragment.3"
const fragmentMediaCase = "did-1.1/sage-resolution/fragment-plain-json-media"

//go:embed fragment_media.json
var fragmentMediaBytes []byte

//go:embed fragment_media_witness.json
var fragmentMediaWitness []byte

type fragmentMediaEvidence struct {
	Source  IntegerSourceResult      `json:"source"`
	Audit   sourcearith.ServiceAudit `json:"audit"`
	Runtime []RoutingResult          `json:"runtime"`
	Error   string                   `json:"analysis_error,omitempty"`
}

func fragmentMediaRequests() []RoutingRequest {
	var f struct {
		Document json.RawMessage `json:"document"`
	}
	_ = json.Unmarshal(fragmentMediaBytes, &f)
	out := []RoutingRequest{}
	for _, fragment := range []string{"sign", "missing"} {
		out = append(out, RoutingRequest{PlainJSONFragment: true, Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did+json"}, Request: Request{Function: "dereference", Input: "did:example:resources#" + fragment, Accept: "application/did+json", Relationship: "authentication"}})
	}
	return out
}
func fragmentMediaSourceReady(ctx context.Context, v IntegerSourceResult) (sourcearith.ServiceAudit, bool) {
	empty := sourcearith.ServiceAudit{}
	q := fragmentSourceRequest()
	if !reflect.DeepEqual(v.Request, q) || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Replaced || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return empty, false
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil || sum != IntegerSourceSum {
		return empty, false
	}
	selected := sourcearith.SourceFiles(files, q.Packages)
	if len(selected) != 38 || len(selected) != len(v.Files) {
		return empty, false
	}
	for name, b := range selected {
		if !bytes.Equal(b, v.Files[name]) {
			return empty, false
		}
	}
	program := sourcearith.NewProgram(ctx, IntegerSourceModule, v.Files)
	if _, err := program.Import(IntegerSourceModule + "/dereferencer"); err != nil {
		return empty, false
	}
	a := program.FragmentRelationshipAudit(IntegerSourceModule + "/dereferencer.(*" + IntegerSourceModule + "/dereferencer.Dereferencer).fragment")
	var w sourcearith.FragmentRelationshipAudit
	if json.Unmarshal(relationshipWitnessBytes, &w) != nil || !reflect.DeepEqual(a, w) {
		return empty, false
	}
	var proof sourcearith.ServiceAudit
	if json.Unmarshal(fragmentMediaWitness, &proof) != nil {
		return empty, false
	}
	actual := program.FragmentMediaAudit()
	return actual, reflect.DeepEqual(actual, proof)
}
func fragmentMediaVerdict(q RoutingRequest, v RoutingResult, positive bool) core.Verdict {
	if !reflect.DeepEqual(v.Request, q) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != IntegerSourceModule+"/dereferencer.Dereferencer.Dereference" || v.CaptureError != "" || len(v.ResourceHandler) != 0 || len(v.Production) != 0 || len(v.Consumption) != 1 || v.Result.Native != nil || v.Result.Exchange != nil {
		return core.Error
	}
	if !reflect.DeepEqual(v.ResolveInputs, []string{"did:example:resources"}) || !reflect.DeepEqual(v.DriverInputs, v.ResolveInputs) || len(v.ResolveOptions) != 1 || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || !optionJSONEqual(v.Options, `{"accept":"application/did+json","verificationRelationship":"authentication"}`) || !bytes.Equal(v.Options, v.ResolveOptions[0]) || !optionJSONEqual(v.DriverOptions[0], `{"VersionID":"","VersionTime":null,"MediaType":"application/did+json","NoCache":false}`) {
		return core.Error
	}
	var driver struct {
		Data        []byte
		ContentType string
		Metadata    json.RawMessage
	}
	if json.Unmarshal(v.DriverResults[0], &driver) != nil || !bytes.Equal(driver.Data, q.Document.Data) || driver.ContentType != "application/did+json" || !optionJSONEqual(driver.Metadata, `{}`) {
		return core.Error
	}
	c := v.Consumption[0]
	if c.Operation != pipelineConsumer || !bytes.Equal(c.Input, q.Document.Data) || c.MediaType != "application/did+json" || c.Version != "1.0" || c.JSONLD || c.Require != "unknown" || c.Expected != "unknown" || c.Strict || len(c.DroppedTerms) != 0 || c.Error != "" || c.CaptureError != "" {
		return core.Error
	}
	for _, b := range [][]byte{c.Model, v.DataModel, v.ResolvedDataModel} {
		if !optionJSONEqual(b, string(q.Document.Data)) {
			return core.Error
		}
	}
	for _, b := range [][]byte{c.Entries, v.Entries, v.ResolvedEntries, v.Result.ContentMetadata} {
		if !optionJSONEqual(b, `{}`) {
			return core.Error
		}
	}
	if !optionJSONEqual(v.ResolvedMetadata, `{"contentType":"application/did+json"}`) {
		return core.Error
	}
	if !positive {
		md, err := parse(v.Result.Metadata)
		if err != nil || v.Result.HasContent || !bytes.Equal(v.Result.Raw, []byte("null")) || errorName(md) != "https://w3id.org/security#INVALID_VERIFICATION_METHOD" {
			return core.Error
		}
		return core.Pass
	}
	var f struct {
		Method json.RawMessage `json:"method"`
	}
	_ = json.Unmarshal(fragmentMediaBytes, &f)
	if v.Result.HasContent && v.Result.ContentKind == "verification-method" && v.Result.ReturnedID == "did:example:resources#sign" && optionJSONEqual(v.Result.Raw, string(f.Method)) && optionJSONEqual(v.Result.Metadata, `{"contentType":"application/json"}`) {
		return core.Pass
	}
	return core.Error
}
func judgeFragmentMedia(ctx context.Context, e fragmentMediaEvidence, input string) []core.Observation {
	obs := libraryUnavailable([]string{fragmentMediaID}, core.Error, "Actual same-call plain JSON Core1.0 document, unique absolute method id, explicit authentication relationship and matching/no-match fragments. Frozen Core1.0 E.1 defines the application/did+json fragment by its Fragment section, independently of JSON-LD media rules. Source binds pre-authorization method selection separately from its later authorization; a downstream refusal does not automatically FAIL this intermediate step. Not JSON-LD/RDF media semantics, all fragment paths, recursive search completeness or operational authority.", input, e)
	qs := fragmentMediaRequests()
	if ctx.Err() != nil || e.Error != "" || len(e.Runtime) != 2 {
		return obs
	}
	var ready bool
	e.Audit, ready = fragmentMediaSourceReady(ctx, e.Source)
	raw, _ := json.Marshal(e)
	obs[0].Observed = string(raw)
	if !ready {
		return obs
	}
	obs[0].Verdict = core.Aggregate([]core.Verdict{fragmentMediaVerdict(qs[0], e.Runtime[0], true), fragmentMediaVerdict(qs[1], e.Runtime[1], false)})
	obs[0].Expected = "The chosen plain-JSON media rule selects the unique matching verification method from the actual resolved document before relationship authorization"
	return obs
}
func appendFragmentMediaCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: fragmentMediaCase, Profile: p.Name, Statements: []string{fragmentMediaID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := fragmentSourceRequest()
		input, _ := json.Marshal(q)
		s, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		e := fragmentMediaEvidence{Runtime: []RoutingResult{}}
		if !ok || !ok1 {
			return libraryUnavailable([]string{fragmentMediaID}, core.NotSupported, "requires actual plain-JSON routing and source", string(input), e)
		}
		var err error
		e.Source, err = s.InspectIntegerSource(ctx, q)
		if err != nil {
			e.Error = err.Error()
			return judgeFragmentMedia(ctx, e, string(input))
		}
		for _, request := range fragmentMediaRequests() {
			v, err := routing.InspectRouting(ctx, request)
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				e.Error = err.Error()
				break
			}
		}
		return judgeFragmentMedia(ctx, e, string(input))
	}})
}
