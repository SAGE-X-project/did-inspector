package sageresolution

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"reflect"
	"runtime"

	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
)

var fragmentSourceIDs = []string{"cid10#fragment-resolution.2", "cid10#fragment-resolution.3", "cid10#fragment-resolution.5"}

//go:embed fragment_source_witness.json
var fragmentWitnessBytes []byte

type fragmentSourceEvidence struct {
	Source       IntegerSourceResult       `json:"source"`
	Audit        sourcearith.FragmentAudit `json:"audit"`
	Runtime      [][]RoutingResult         `json:"runtime"`
	Compiler     string                    `json:"type_checker_compiler"`
	Architecture string                    `json:"type_checker_architecture"`
	Error        string                    `json:"analysis_error,omitempty"`
}

func fragmentSourceRequest() IntegerSourceRequest {
	return IntegerSourceRequest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Packages: []string{"dereferencer", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"}}
}
func fragmentFixtures() []resourceChoiceFixture {
	out := []resourceChoiceFixture{}
	for _, f := range resourceChoiceFixtures() {
		if f.Name == "nested-full" || f.Name == "nested-relative" {
			out = append(out, f)
		}
	}
	return out
}
func fragmentSourceVerdict(a sourcearith.FragmentAudit, index int) core.Verdict {
	var witness sourcearith.FragmentAudit
	if json.Unmarshal(fragmentWitnessBytes, &witness) != nil || a.Root != IntegerSourceModule+"/dereferencer.resolveFragment" || !reflect.DeepEqual(a.Frames, witness.Frames) || !reflect.DeepEqual(a.CallPaths, witness.CallPaths) || len(a.Unknown) != 0 || len(a.Steps) != 3 || index < 0 || index >= 3 {
		return core.Error
	}
	if !a.Steps[index].Correct {
		return core.Fail
	}
	return core.Pass
}
func fragmentRuntime(values [][]RoutingResult) core.Verdict {
	fixtures := fragmentFixtures()
	if len(values) != len(fixtures) {
		return core.Error
	}
	for i, f := range fixtures {
		if len(values[i]) != 2 {
			return core.Error
		}
		for j, v := range values[i] {
			if !resourceChoiceWitness(f, j, v) {
				return core.Error
			}
		}
		good, miss := values[i][0].Result, values[i][1].Result
		want, _ := core.ParseJSON(f.Content)
		got, e := parse(good.Raw)
		metadata, e1 := parse(good.Metadata)
		missing, e2 := parse(miss.Metadata)
		if e != nil || e1 != nil || e2 != nil {
			return core.Error
		}
		ct, _ := metadata.Get("contentType")
		_, hasError := metadata.Get("error")
		if errorName(missing) != "https://www.w3.org/ns/did#NOT_FOUND" {
			return core.Error
		}
		if !good.HasContent || good.ContentKind != "map" || good.ReturnedID != f.ID || ct.Kind != core.KindString || ct.Str != f.Media || !equalObserved(got.Value(), want, "unknown") || miss.HasContent || !bytes.Equal(miss.Raw, []byte("null")) || hasError {
			return core.Fail
		}
	}
	return core.Pass
}
func judgeFragmentSource(ctx context.Context, e fragmentSourceEvidence, input string) []core.Observation {
	obs := libraryUnavailable(fragmentSourceIDs, core.Error, "Fixed-source typed canonical DID/fragment construction and exact search-result return, paired with fresh selected full/relative nested-map and miss controls in the actual pinned root dereferencer. Normal typed-document branch without verificationRelationship only. Caller/getter/search/error-envelope source is independently bound. Not null initialization, every-map recursive coverage, operational authority or runtime/binary attestation.", input, e)
	v := e.Source
	q := fragmentSourceRequest()
	if !reflect.DeepEqual(v.Request, q) || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Replaced || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || runtime.Version() != v.Compiler || len(v.Diagnostics) != 0 {
		return finishFragmentSource(ctx, e, obs)
	}
	files, sum, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil || sum != IntegerSourceSum {
		e.Error = "unbound fragment source archive"
		return finishFragmentSource(ctx, e, obs)
	}
	selected := sourcearith.SourceFiles(files, q.Packages)
	if len(selected) != 38 || len(v.Files) != len(selected) {
		e.Error = "incomplete fragment source"
		return finishFragmentSource(ctx, e, obs)
	}
	for name, b := range selected {
		if !bytes.Equal(v.Files[name], b) {
			e.Error = "fragment cache differs from ZIP: " + name
			return finishFragmentSource(ctx, e, obs)
		}
	}
	program := sourcearith.NewProgram(ctx, IntegerSourceModule, v.Files)
	if _, err := program.Import(IntegerSourceModule + "/dereferencer"); err != nil {
		e.Error = err.Error()
		return finishFragmentSource(ctx, e, obs)
	}
	e.Audit = program.FragmentAudit(IntegerSourceModule + "/dereferencer.resolveFragment")
	corroboration := fragmentRuntime(e.Runtime)
	if corroboration == core.Error {
		e.Error = "missing or mismatched actual fragment controls"
		return finishFragmentSource(ctx, e, obs)
	}
	for i := range obs {
		obs[i].Verdict = fragmentSourceVerdict(e.Audit, i)
		if i == 2 && obs[i].Verdict == core.Pass && corroboration == core.Fail {
			obs[i].Verdict = core.Error
			obs[i].Detail += " Selected runtime payload differs, but no trace independently attributes it to the return step rather than search or capture. The player-specific NOT_FOUND code is a provenance prerequisite, not a CID MUST."
		}
		obs[i].Expected = "Bound document ID and fully qualified fragment, or the same search result in ContentStream with null no-match envelope, in the selected normal typed-document source phase"
	}
	return finishFragmentSource(ctx, e, obs)
}
func finishFragmentSource(ctx context.Context, e fragmentSourceEvidence, obs []core.Observation) []core.Observation {
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
func appendFragmentSourceCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/fragment-source-bindings", Profile: p.Name, Statements: fragmentSourceIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := fragmentSourceRequest()
		input, _ := json.Marshal(q)
		e := fragmentSourceEvidence{Compiler: runtime.Version(), Architecture: runtime.GOARCH, Runtime: [][]RoutingResult{}}
		source, ok := target.(IntegerSourceSubject)
		routing, ok1 := target.(RoutingSubject)
		if !ok || !ok1 {
			return libraryUnavailable(fragmentSourceIDs, core.NotSupported, "no source and actual fragment observers", string(input), e)
		}
		var err error
		e.Source, err = source.InspectIntegerSource(ctx, q)
		if err != nil {
			return libraryUnavailable(fragmentSourceIDs, core.Error, err.Error(), string(input), e)
		}
		for _, f := range fragmentFixtures() {
			values := []RoutingResult{}
			for i := range f.Requests {
				v, err := routing.InspectRouting(ctx, resourceChoiceRequest(f, i))
				values = append(values, v)
				if err != nil {
					e.Runtime = append(e.Runtime, values)
					return libraryUnavailable(fragmentSourceIDs, core.Error, err.Error(), string(input), e)
				}
			}
			e.Runtime = append(e.Runtime, values)
		}
		return judgeFragmentSource(ctx, e, string(input))
	}})
}
