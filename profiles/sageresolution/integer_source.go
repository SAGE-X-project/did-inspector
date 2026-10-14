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

var integerSourceIDs = []string{"cid10#base-encode.1", "cid10#base-decode.1", "cid10#base-encode.8", "cid10#base-encode.9", "cid10#base-encode.10", "cid10#base-decode.9", "cid10#base-decode.10", "cid10#base-decode.11", "cid10#base-encode.6", "cid10#base-encode.11", "cid10#base-decode.2", "cid10#base-decode.7", "cid10#base-decode.12", "cid10#base-decode.13"}

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
	Source       IntegerSourceResult      `json:"source"`
	Audits       []sourcearith.Audit      `json:"audits"`
	State        []sourcearith.StateAudit `json:"state"`
	Carry        []sourcearith.CarryAudit `json:"carry"`
	CallPaths    [][]string               `json:"call_paths"`
	Compiler     string                   `json:"type_checker_compiler"`
	Architecture string                   `json:"type_checker_architecture"`
	Error        string                   `json:"analysis_error,omitempty"`
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
	evidence := integerSourceEvidence{Source: v, Audits: []sourcearith.Audit{}, Carry: []sourcearith.CarryAudit{}, State: []sourcearith.StateAudit{}, CallPaths: [][]string{}, Compiler: runtime.Version(), Architecture: runtime.GOARCH}
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
		carry := program.CarryAudit(root)
		evidence.Carry = append(evidence.Carry, carry)
		for j := 0; j < 3; j++ {
			index := 2 + i*3 + j
			obs[index].Verdict = carryVerdict(carry, j)
			obs[index].Expected = "Selected fixed-source recurrence uses the bound carry, current buffer cell, alphabet-length base and specified multiply/remainder/integer-division operation. Reviewed surrounding context is a prerequisite, not an arithmetic verdict."
		}
		state := program.StateAudit(root)
		evidence.State = append(evidence.State, state)
		start, stepCount := 8, 2
		if i == 1 {
			start, stepCount = 10, 4
		}
		for j := 0; j < stepCount; j++ {
			obs[start+j].Verdict = stateVerdict(state, j)
			obs[start+j].Expected = "Selected fixed-source byte/alphabet initialization and local loop-state transition. Typed storage and real public ASCII selector are proved independently. Normal Go body-to-Post completion is an explicit language-semantic boundary; no whole algorithm, guard, overflow or runtime-trace claim."
		}
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

// A reviewed frame limits the operand proof to the selected source context.
// Different or missing context is unknown; equivalent alternative algorithms
// are not failed merely because their structure differs.
func carryVerdict(a sourcearith.CarryAudit, index int) core.Verdict {
	frame := ""
	switch a.Root {
	case IntegerSourceModule + "/internal/multiformats.BaseEncode":
		frame = "c043e4908d7fb16b464fe90b45fdc29ce59cf1d4053cb815c915ee27586d4990"
	case IntegerSourceModule + "/internal/multiformats.BaseDecode":
		frame = "efc1882f97b1fe4bdcb49831cc69a0a9a607310808a1071c8837ffd134af6526"
	}
	if frame == "" || a.Frame != frame || len(a.Unknown) > 0 || len(a.Steps) != 3 || index < 0 || index >= 3 {
		return core.Error
	}
	if !a.Steps[index].Correct || !a.Steps[index].Operation.Integer {
		return core.Fail
	}
	return core.Pass
}

// Reviewed context is only a prerequisite; each transition has its own proof.
func stateVerdict(a sourcearith.StateAudit, index int) core.Verdict {
	frame := ""
	count := 0
	switch a.Root {
	case IntegerSourceModule + "/internal/multiformats.BaseEncode":
		frame = "4b94ff9ac70dd5af838a92595d85f199f80598e4bfa88b764b6ab4717c41465f"
		count = 2
	case IntegerSourceModule + "/internal/multiformats.BaseDecode":
		frame = "945a2f0a3a496baad2db648d7319b940c520f729bc8e8dd9b5f8aae1d855ba45"
		count = 4
	}
	if frame == "" || a.Frame != frame || len(a.Unknown) != 0 || len(a.Steps) != count || index < 0 || index >= count {
		return core.Error
	}
	if !a.Steps[index].Correct {
		return core.Fail
	}
	return core.Pass
}
