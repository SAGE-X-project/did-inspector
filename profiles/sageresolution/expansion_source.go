package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
	"strconv"
)

var expansionSourceIDs = []string{"res10-crd20261001#resolving-algorithm.27", "res10-crd20261001#resolving-algorithm.28"}

//go:embed expansion_source.json
var expansionSourceBytes []byte

//go:embed expansion_source_witness.json
var expansionSourceWitness []byte

type expansionSourceFixture struct {
	Name     string          `json:"name"`
	Document json.RawMessage `json:"document"`
	Request  Request         `json:"request"`
	Expected json.RawMessage `json:"expected"`
	Paths    [][]string      `json:"extension_paths"`
}
type expansionSourceEvidence struct {
	Source       IntegerSourceResult      `json:"source"`
	Audit        sourcearith.ServiceAudit `json:"audit"`
	Runtime      []RoutingResult          `json:"runtime"`
	Compiler     string                   `json:"type_checker_compiler"`
	Architecture string                   `json:"type_checker_architecture"`
	Error        string                   `json:"analysis_error,omitempty"`
}

func expansionSourceFixtures() []expansionSourceFixture {
	out := []expansionSourceFixture{}
	_ = json.Unmarshal(expansionSourceBytes, &out)
	return out
}
func expansionSourceRequest() IntegerSourceRequest {
	return IntegerSourceRequest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Packages: []string{"resolver", "method", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"}}
}
func expansionSourceRouting(f expansionSourceFixture) RoutingRequest {
	return RoutingRequest{Document: ConsumptionRequest{Data: f.Document, MediaType: "application/did"}, Request: f.Request}
}
func expansionNode(v *core.Value, path []string) *core.Value {
	for _, key := range path {
		if v.Kind == core.KindArray {
			i, e := strconv.Atoi(key)
			if e != nil || i < 0 || i >= len(v.Array) {
				return nil
			}
			v = &v.Array[i]
			continue
		}
		if v.Kind != core.KindObject {
			return nil
		}
		found := false
		for i := range v.Object {
			if v.Object[i].Name == key {
				v = &v.Object[i].Value
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return v
}
func expansionSourceRuntime(values []RoutingResult) (bool, bool) {
	fs := expansionSourceFixtures()
	if len(values) != len(fs) {
		return false, false
	}
	missing := false
	for i, v := range values {
		f := fs[i]
		q := expansionSourceRouting(f)
		enabled := q.Request.Options["expandRelativeUrls"] == true
		opts := map[string]any{"accept": "application/did"}
		if enabled {
			opts["expandRelativeUrls"] = true
		}
		o, _ := json.Marshal(opts)
		if !reflect.DeepEqual(v.Request, q) || v.Operation != "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve" || v.Role != "root resolver/dereferencer library with literal example driver; not SAGE Source" || v.CaptureError != "" || len(v.ResolveInputs) != 1 || v.ResolveInputs[0] != "did:example:123" || len(v.DriverInputs) != 1 || v.DriverInputs[0] != "did:example:123" || len(v.ResolveOptions) != 1 || len(v.DriverOptions) != 1 || len(v.DriverResults) != 1 || len(v.Consumption) != 1 || v.Result.Native != nil || v.Result.Exchange != nil {
			return false, false
		}
		if !optionJSONEqual(v.Options, string(o)) || !optionJSONEqual(v.ResolveOptions[0], string(o)) || !optionJSONEqual(v.DriverOptions[0], `{"VersionID":"","VersionTime":null,"MediaType":"application/did","NoCache":false}`) {
			return false, false
		}
		read, e := parse(v.DriverResults[0])
		ct, _ := read.Get("ContentType")
		data, _ := read.Get("Data")
		body, e1 := base64.StdEncoding.DecodeString(data.Str)
		if e != nil || e1 != nil || ct.Str != "application/did" || !optionJSONEqual(body, string(f.Document)) {
			return false, false
		}
		c := v.Consumption[0]
		if c.Operation != pipelineConsumer || !bytes.Equal(c.Input, f.Document) || c.MediaType != "application/did" || c.Require != "unknown" || c.Expected != "unknown" || c.Strict || c.JSONLD || len(c.DroppedTerms) != 0 || c.Error != "" || c.CaptureError != "" || !optionJSONEqual(c.Model, string(f.Document)) || !optionJSONEqual(c.Entries, `{}`) {
			return false, false
		}
		if !v.Result.HasContent || v.Result.ReturnedID != "did:example:123" || v.Result.ContentKind != "document" || !optionJSONEqual(v.Result.Metadata, `{"contentType":"application/did"}`) || !optionJSONEqual(v.Result.ContentMetadata, `{}`) || !optionJSONEqual(v.Entries, `{}`) || !optionJSONEqual(v.ResolvedEntries, `{}`) || !optionJSONEqual(v.ResolvedMetadata, `{"contentType":"application/did"}`) || !optionJSONEqual(v.ResolvedDataModel, string(v.DataModel)) {
			return false, false
		}
		wire, wireError := core.ParseJSON(v.Result.Raw)
		model, modelError := core.ParseJSON(v.DataModel)
		if wireError != nil || modelError != nil || wire.Kind != core.KindObject {
			return false, false
		}
		if enabled {
			context, present := wire.Get("@context")
			if !present || context.Kind != core.KindString || context.Str != "https://www.w3.org/ns/did/v1.1" {
				return false, false
			}
			members := []core.Member{}
			for _, member := range wire.Object {
				if member.Name != "@context" {
					members = append(members, member)
				}
			}
			wire.Object = members
		}
		if !equalObserved(wire, model, "unknown") {
			return false, false
		}
		got, e := core.ParseJSON(v.DataModel)
		want, e1 := core.ParseJSON(f.Expected)
		original, e2 := core.ParseJSON(f.Document)
		if e != nil || e1 != nil || e2 != nil {
			return false, false
		}
		for _, path := range f.Paths {
			a, b, c := expansionNode(&got, path), expansionNode(&want, path), expansionNode(&original, path)
			if a == nil || b == nil || c == nil || a.Kind != core.KindString || b.Kind != core.KindString || c.Kind != core.KindString {
				return false, false
			}
			if a.Str == c.Str {
				missing = true
			} else if a.Str != b.Str {
				return false, false
			}
			*a = *b
		}
		if !equalObserved(got, want, "unknown") {
			return false, false
		}
	}
	return true, missing
}
func expansionSourceVerdict(a sourcearith.ServiceAudit, index int) core.Verdict {
	var w sourcearith.ServiceAudit
	if json.Unmarshal(expansionSourceWitness, &w) != nil || !reflect.DeepEqual(a.Roots, w.Roots) || !reflect.DeepEqual(a.Frames, w.Frames) || !reflect.DeepEqual(a.Roles, w.Roles) || !reflect.DeepEqual(a.CallPaths, w.CallPaths) || len(a.Unknown) != 0 || len(a.Steps) != 2 || index < 0 || index >= 2 {
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
func finishExpansionSource(ctx context.Context, e expansionSourceEvidence, obs []core.Observation) []core.Observation {
	if ctx.Err() != nil {
		e.Error = ctx.Err().Error()
		for i := range obs {
			obs[i].Verdict = core.Error
		}
	}
	raw, _ := json.Marshal(e)
	for i := range obs {
		obs[i].Observed = string(raw)
	}
	return obs
}
func judgeExpansionSource(ctx context.Context, e expansionSourceEvidence, input string) []core.Observation {
	obs := libraryUnavailable(expansionSourceIDs, core.Error, "Pinned typed resolver option guard and complete extension traversal, corroborated by fresh ordinary literal documents. Same-call consumer input/model precedes expansion; method, embedded-method and service Extra maps remain relative while relocated root maps expand. Complete traversal fails if an explicit extension map is skipped. Caller/helper frames and Go semantics are premises. No full RFC3986/media/JSON-LD, authority, physical trace, output conformance (.26) or per-item (.29) claim. Modified source controls are parse/type-check data only, never executed", input, e)
	v := e.Source
	q := expansionSourceRequest()
	if !reflect.DeepEqual(v.Request, q) || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Replaced || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return finishExpansionSource(ctx, e, obs)
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil || sum != IntegerSourceSum {
		e.Error = "unbound expansion source archive"
		return finishExpansionSource(ctx, e, obs)
	}
	selected := sourcearith.SourceFiles(files, q.Packages)
	if len(selected) != 39 || len(v.Files) != len(selected) {
		e.Error = "incomplete expansion source"
		return finishExpansionSource(ctx, e, obs)
	}
	for n, b := range selected {
		if !bytes.Equal(v.Files[n], b) {
			e.Error = "expansion cache differs from ZIP: " + n
			return finishExpansionSource(ctx, e, obs)
		}
	}
	p := sourcearith.NewProgram(ctx, IntegerSourceModule, v.Files)
	if _, err := p.Import(IntegerSourceModule + "/resolver"); err != nil {
		e.Error = err.Error()
		return finishExpansionSource(ctx, e, obs)
	}
	e.Compiler, e.Architecture = runtime.Version(), runtime.GOARCH
	e.Audit = p.ExpansionAudit()
	valid, missing := expansionSourceRuntime(e.Runtime)
	if !valid {
		e.Error = "missing or mismatched same-call expansion receipts"
		return finishExpansionSource(ctx, e, obs)
	}
	for i := range obs {
		obs[i].Verdict = expansionSourceVerdict(e.Audit, i)
		if i == 1 && (obs[i].Verdict == core.Pass) == missing {
			obs[i].Verdict = core.Error
		}
		obs[i].Expected = "Typed true-option guard and visitation of explicit normal method/service extension maps, with preserved pre-expansion consumer model and independent literal expected URLs"
	}
	return finishExpansionSource(ctx, e, obs)
}
func appendExpansionSourceCase(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/expansion-source-roles", Profile: p.Name, Statements: expansionSourceIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		q := expansionSourceRequest()
		input, _ := json.Marshal(q)
		if !ok || !ok1 {
			return libraryUnavailable(expansionSourceIDs, core.NotSupported, "no selected source/routing operations", string(input), nil)
		}
		e := expansionSourceEvidence{Runtime: []RoutingResult{}}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		fail := func(err error) []core.Observation {
			e.Error = err.Error()
			return libraryUnavailable(expansionSourceIDs, core.Error, err.Error(), string(input), e)
		}
		if err != nil {
			return fail(err)
		}
		for _, f := range expansionSourceFixtures() {
			v, err := routing.InspectRouting(ctx, expansionSourceRouting(f))
			e.Runtime = append(e.Runtime, v)
			if err != nil {
				return fail(err)
			}
		}
		return judgeExpansionSource(ctx, e, string(input))
	}})
}
