package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

const returnedRepresentationID = "res10-crd20261001#resolving-algorithm.26"
const returnedRepresentationCase = "did-1.1/sage-resolution/returned-minimal-representation"

type returnedRepresentationEvidence struct {
	Source  IntegerSourceResult `json:"source"`
	Runtime []RoutingResult     `json:"runtime"`
}

func returnedRepresentationRequests() []RoutingRequest {
	out := []RoutingRequest{}
	for _, data := range []string{`{"id":"did:example:123"}`, " { \n \"id\" : \"did:example:123\" } \n"} {
		out = append(out, RoutingRequest{ObserveProduction: true, Document: ConsumptionRequest{Data: []byte(data), MediaType: "application/did"}, Request: Request{Function: "resolve", Input: "did:example:123", Accept: "application/did+json"}})
	}
	return out
}
func returnedRepresentationSourceRequest() IntegerSourceRequest {
	return IntegerSourceRequest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Packages: []string{"resolver", "consumer", "producer", "representation"}}
}
func returnedRepresentationSourceReady(v IntegerSourceResult) bool {
	if !reflect.DeepEqual(v.Request, returnedRepresentationSourceRequest()) || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Replaced || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return false
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil || sum != IntegerSourceSum {
		return false
	}
	selected := sourcearith.SourceFiles(files, v.Request.Packages)
	if len(selected) != 9 || len(selected) != len(v.Files) {
		return false
	}
	for name, data := range selected {
		if !bytes.Equal(v.Files[name], data) {
			return false
		}
	}
	return true
}

// This oracle enumerates every member of the selected id-only Core 1.0 JSON
// class. Other valid classes are unsupported, not declared nonconforming.
func returnedRepresentationJSON(data []byte) core.Verdict {
	v, err := core.ParseJSON(data)
	if err != nil || v.Kind != core.KindObject {
		return core.Fail
	}
	if len(checks.DuplicateMembers(v)) != 0 {
		return core.NotSupported
	}
	id, ok := v.Get("id")
	if !ok || id.Kind != core.KindString || !checks.IsDID(id.Str) {
		return core.Fail
	}
	if id.Str != "did:example:123" {
		return core.Error
	}
	if len(v.Object) != 1 {
		return core.NotSupported
	}
	return core.Pass
}

func returnedRepresentationVerdict(q RoutingRequest, v RoutingResult) core.Verdict {
	if !reflect.DeepEqual(v.Request, q) || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.Operation != IntegerSourceModule+"/resolver.DefaultResolver.Resolve" || v.CaptureError != "" || len(v.ResourceHandler) != 0 || len(v.Consumption) != 1 || len(v.Production) != 1 || v.Result.Native != nil || v.Result.Exchange != nil || v.Result.SageCode != "" || !v.Result.HasContent || v.Result.ContentKind != "document" || v.Result.ReturnedID != "did:example:123" {
		return core.Error
	}
	if !reflect.DeepEqual(v.ResolveInputs, []string{"did:example:123"}) || !reflect.DeepEqual(v.DriverInputs, v.ResolveInputs) || len(v.ResolveOptions) != 1 || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || !optionJSONEqual(v.Options, `{"accept":"application/did+json"}`) || !bytes.Equal(v.Options, v.ResolveOptions[0]) || !optionJSONEqual(v.DriverOptions[0], `{"VersionID":"","VersionTime":null,"MediaType":"","NoCache":false}`) {
		return core.Error
	}
	var driver struct {
		Data        []byte
		ContentType string
		Metadata    json.RawMessage
	}
	if json.Unmarshal(v.DriverResults[0], &driver) != nil || !bytes.Equal(driver.Data, q.Document.Data) || driver.ContentType != "application/did" || !optionJSONEqual(driver.Metadata, `{}`) {
		return core.Error
	}
	c, p := v.Consumption[0], v.Production[0]
	if c.Operation != pipelineConsumer || !bytes.Equal(c.Input, q.Document.Data) || c.MediaType != "application/did" || c.Require != "unknown" || c.Expected != "unknown" || c.Strict || c.Version != "1.1" || c.JSONLD || len(c.DroppedTerms) != 0 || c.Error != "" || c.CaptureError != "" || p.Operation != "github.com/sage-x-project/did-go/producer.Producer.Produce" || p.Version != "1.0" || p.JSONLD || p.IncludeSecret || p.Error != "" || p.CaptureError != "" {
		return core.Error
	}
	for _, data := range [][]byte{c.Model, p.Model, v.DataModel, v.ResolvedDataModel, v.Result.Snapshot} {
		if returnedRepresentationJSON(data) != core.Pass {
			return core.Error
		}
	}
	for _, data := range [][]byte{c.Entries, p.Entries, v.Entries, v.ResolvedEntries, v.Result.ContentMetadata} {
		if !optionJSONEqual(data, `{}`) {
			return core.Error
		}
	}
	metadata, err := parse(v.Result.Metadata)
	media, ok := metadata.Get("contentType")
	if err != nil || !ok || media.Kind != core.KindString || media.Str != p.MediaType || !optionJSONEqual(v.ResolvedMetadata, string(v.Result.Metadata)) || !bytes.Equal(p.Output, v.Result.Raw) {
		return core.Error
	}
	if _, failed := metadata.Get("error"); failed {
		return core.Error
	}
	if p.MediaType != "application/did+json" {
		return core.NotSupported
	}
	return returnedRepresentationJSON(v.Result.Raw)
}
func judgeReturnedRepresentation(ctx context.Context, e returnedRepresentationEvidence, input string) []core.Observation {
	obs := libraryUnavailable([]string{returnedRepresentationID}, core.Error, "Actual root Resolve return for two literal id-only documents, with passive same-call consumer and producer receipts. Input consumer V1.1 is distinct from the final Core1.0 application/did+json representation. Every member of this minimal class is independently checked; other valid classes remain unsupported. No separate re-representation substitutes for Resolve output. Not all SAGE documents, JSON-LD/RDF, complete algorithms, metadata tuple placement, authority or compiled-byte attestation.", input, e)
	qs := returnedRepresentationRequests()
	if ctx.Err() != nil || !returnedRepresentationSourceReady(e.Source) || len(e.Runtime) != len(qs) {
		return obs
	}
	verdicts := []core.Verdict{}
	for i, q := range qs {
		verdicts = append(verdicts, returnedRepresentationVerdict(q, e.Runtime[i]))
	}
	obs[0].Verdict = core.Aggregate(verdicts)
	obs[0].Expected = "The actual same-call Resolve Raw and contentType form a conformant complete id-only Core1.0 JSON representation"
	return obs
}
func appendReturnedRepresentationCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: returnedRepresentationCase, Profile: p.Name, Statements: []string{returnedRepresentationID}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := returnedRepresentationSourceRequest()
		input, _ := json.Marshal(q)
		e := returnedRepresentationEvidence{Runtime: []RoutingResult{}}
		source, ok := target.(IntegerSourceSubject)
		routing, ok2 := target.(RoutingSubject)
		if !ok || !ok2 {
			return libraryUnavailable([]string{returnedRepresentationID}, core.NotSupported, "requires pinned source and passive actual Resolve producer observations", string(input), e)
		}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			return libraryUnavailable([]string{returnedRepresentationID}, core.Error, err.Error(), string(input), e)
		}
		for _, request := range returnedRepresentationRequests() {
			v, err := routing.InspectRouting(ctx, request)
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				return libraryUnavailable([]string{returnedRepresentationID}, core.Error, err.Error(), string(input), e)
			}
		}
		return judgeReturnedRepresentation(ctx, e, string(input))
	}})
}
