package sageresolution

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
)

var integerSourceIDs = []string{"cid10#base-encode.1", "cid10#base-decode.1"}

func integerSourceRequest() IntegerSourceRequest {
	var selected codecFixture
	for _, f := range codecFixtures() {
		if f.Name == "Ed25519" && !f.Secret {
			selected = f
		}
	}
	return IntegerSourceRequest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Packages: []string{"vm", "did", "internal/multiformats"}, Diagnostics: codecRequests(selected)}
}

type integerSourceEvidence struct {
	Source       IntegerSourceResult `json:"source"`
	Audits       []sourcearith.Audit `json:"audits"`
	CallPaths    [][]string          `json:"call_paths"`
	Compiler     string              `json:"type_checker_compiler"`
	Architecture string              `json:"type_checker_architecture"`
	Error        string              `json:"analysis_error,omitempty"`
}

func sourceIdentity(v IntegerSourceResult) bool {
	if !reflect.DeepEqual(v.Request, integerSourceRequest()) || v.Operation != "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture" || v.Module != IntegerSourceModule || v.Version != IntegerSourceVersion || v.Sum != IntegerSourceSum || v.Replaced || v.Compiler != "go1.26.8" || v.EnvironmentCompiler != v.Compiler || len(v.Diagnostics) != len(v.Request.Diagnostics) {
		return false
	}
	for i, d := range v.Diagnostics {
		if d.Operation != "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey" || !reflect.DeepEqual(d.Request, v.Request.Diagnostics[i]) {
			return false
		}
	}
	return true
}
func judgeIntegerSource(ctx context.Context, v IntegerSourceResult, input string) []core.Observation {
	evidence := integerSourceEvidence{Source: v, Audits: []sourcearith.Audit{}, CallPaths: [][]string{}, Compiler: runtime.Version(), Architecture: runtime.GOARCH}
	obs := libraryUnavailable(integerSourceIDs, core.Error, "Static inspection of pinned module source. Go h1 ZIP content digest binds source identity to the reported dependency pin; cached production files must match ZIP bytes. Standard Go parser/types resolve public codec-to-base symbol paths and all selected algorithm helpers, used global initializers, argument arithmetic and numeric conversions. Reviewed text/error/buffer boundaries are explicit. This is fixed-source arithmetic compliance, not proof of verbatim compiled binary bytes, all runtime executions, overflow safety, capacity bounds, termination, reference steps or output equivalence. Public codec calls are diagnostic only.", input, evidence)
	if !sourceIdentity(v) || runtime.Version() != v.Compiler {
		return finishIntegerSource(ctx, evidence, obs)
	}
	files, sum, e := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if e != nil {
		evidence.Error = e.Error()
		return finishIntegerSource(ctx, evidence, obs)
	}
	if sum != IntegerSourceSum {
		evidence.Error = "module h1 mismatch"
		return finishIntegerSource(ctx, evidence, obs)
	}
	selected := sourcearith.SourceFiles(files, v.Request.Packages)
	if len(selected) != len(v.Files) {
		evidence.Error = "incomplete cache source"
		return finishIntegerSource(ctx, evidence, obs)
	}
	for name, b := range selected {
		if !bytes.Equal(v.Files[name], b) {
			evidence.Error = "cache source differs from ZIP: " + name
			return finishIntegerSource(ctx, evidence, obs)
		}
	}
	program := sourcearith.NewProgram(ctx, IntegerSourceModule, v.Files)
	if _, e := program.Import(IntegerSourceModule + "/vm"); e != nil {
		evidence.Error = e.Error()
		return finishIntegerSource(ctx, evidence, obs)
	}
	for i, operation := range []string{"Encode", "Decode"} {
		vm := IntegerSourceModule + "/vm." + operation + "Multikey"
		multi := IntegerSourceModule + "/internal/multiformats." + operation + "Multibase"
		root := IntegerSourceModule + "/internal/multiformats.Base" + operation
		if !program.Calls(vm, multi) || !program.Calls(multi, root) {
			evidence.Error = "unproven static codec symbol path"
			return finishIntegerSource(ctx, evidence, obs)
		}
		evidence.CallPaths = append(evidence.CallPaths, []string{vm, multi, root})
		a := program.IntegerAudit(root)
		evidence.Audits = append(evidence.Audits, a)
		obs[i].Verdict = integerAuditVerdict(a)
		obs[i].Expected = "All mathematical operations in the selected fixed-source algorithm closure have integer operand/result types, including numeric conversions and used package initializers"
	}
	return finishIntegerSource(ctx, evidence, obs)
}
func appendIntegerSourceCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/integer-source-arithmetic", Profile: p.Name, Statements: integerSourceIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := integerSourceRequest()
		input, _ := json.Marshal(q)
		s, ok := target.(IntegerSourceSubject)
		if !ok {
			return libraryUnavailable(integerSourceIDs, core.NotSupported, "no pinned source observer", string(input), nil)
		}
		v, e := s.InspectIntegerSource(ctx, q)
		if e != nil {
			return libraryUnavailable(integerSourceIDs, core.Error, e.Error(), string(input), v)
		}
		return judgeIntegerSource(ctx, v, string(input))
	}})
}

func integerAuditVerdict(a sourcearith.Audit) core.Verdict {
	for _, op := range a.Operations {
		if !op.Integer {
			return core.Fail
		}
	}
	if len(a.Unknown) > 0 || len(a.Operations) == 0 {
		return core.Error
	}
	return core.Pass
}

func finishIntegerSource(ctx context.Context, evidence integerSourceEvidence, obs []core.Observation) []core.Observation {
	if ctx.Err() != nil {
		evidence.Error = ctx.Err().Error()
		for i := range obs {
			obs[i].Verdict = core.Error
		}
	}
	raw, _ := json.Marshal(evidence)
	for i := range obs {
		obs[i].Observed = string(raw)
	}
	return obs
}
