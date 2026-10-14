package sageresolution

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"os"
	"testing"
)

func sourceControl(t *testing.T) IntegerSourceResult {
	t.Helper()
	archive, e := os.ReadFile("../../checks/sourcearith/testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	files, sum, e := sourcearith.ArchiveFiles(archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if e != nil || sum != IntegerSourceSum {
		t.Fatal(sum, e)
	}
	q := integerSourceRequest()
	v := IntegerSourceResult{Request: q, Operation: "debug.ReadBuildInfo + local go env + module cache/ZIP byte capture", Module: IntegerSourceModule, Version: IntegerSourceVersion, Sum: IntegerSourceSum, Compiler: "go1.26.8", EnvironmentCompiler: "go1.26.8", Archive: archive, Files: sourcearith.SourceFiles(files, q.Packages)}
	for _, r := range q.Diagnostics {
		v.Diagnostics = append(v.Diagnostics, CodecResult{Operation: "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey", Request: r})
	}
	return v
}
func TestPinnedIntegerSourceIdentityAndAudit(t *testing.T) {
	v := sourceControl(t)
	for _, o := range judgeIntegerSource(t.Context(), v, "unit") {
		if o.Verdict != core.Pass || o.Observed == "" {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	for _, change := range []func(*IntegerSourceResult){func(v *IntegerSourceResult) { v.Module = "other" }, func(v *IntegerSourceResult) { v.Version = "other" }, func(v *IntegerSourceResult) { v.Sum = "other" }, func(v *IntegerSourceResult) { v.Replaced = true }, func(v *IntegerSourceResult) { v.Compiler = "other" }, func(v *IntegerSourceResult) { v.EnvironmentCompiler = "other" }, func(v *IntegerSourceResult) { v.Operation = "other" }, func(v *IntegerSourceResult) { v.Request.Packages = nil }, func(v *IntegerSourceResult) { v.Diagnostics = nil }, func(v *IntegerSourceResult) { v.Diagnostics[0].Operation = "other" }, func(v *IntegerSourceResult) { v.Diagnostics[0].Request.Encoded = "other" }, func(v *IntegerSourceResult) { v.Archive = nil }, func(v *IntegerSourceResult) { v.Files = nil }, func(v *IntegerSourceResult) { v.Files["internal/multiformats/base.go"] = []byte("changed") }} {
		v := sourceControl(t)
		change(&v)
		for _, o := range judgeIntegerSource(t.Context(), v, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unbound source passed", o.Statement, o.Verdict)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, o := range judgeIntegerSource(ctx, sourceControl(t), "unit") {
		if o.Verdict != core.Error {
			t.Fatal("cancelled audit")
		}
	}
	// Actual codec output is archived separately and cannot substitute for source
	// integer types or contaminate this static arithmetic clause.
	v = sourceControl(t)
	v.Diagnostics[0].EncodeError = "different codec diagnostic"
	for _, o := range judgeIntegerSource(t.Context(), v, "unit") {
		if o.Verdict != core.Pass {
			t.Fatal("output diagnostic became arithmetic oracle")
		}
	}
}
func TestPerAlgorithmIntegerVerdict(t *testing.T) {
	for _, tt := range []struct {
		a    sourcearith.Audit
		want core.Verdict
	}{{sourcearith.Audit{}, core.Error}, {sourcearith.Audit{Unknown: []string{"unknown"}, Operations: []sourcearith.Operation{{Integer: true}}}, core.Error}, {sourcearith.Audit{Operations: []sourcearith.Operation{{Integer: false}}}, core.Fail}, {sourcearith.Audit{Operations: []sourcearith.Operation{{Integer: true}}}, core.Pass}} {
		if integerAuditVerdict(tt.a) != tt.want {
			t.Fatal(tt)
		}
	}
}

type sourceMock struct {
	noOperation
	v    IntegerSourceResult
	fail bool
}

func (s sourceMock) InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error) {
	if s.fail {
		return s.v, errors.New("capture unavailable")
	}
	return s.v, nil
}
func TestIntegerSourceDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendIntegerSourceCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendIntegerSourceCases(&p)
	if len(p.Cases) != 1 {
		t.Fatal("cases")
	}
	c := p.Cases[0]
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		s    core.Subject
		want core.Verdict
	}{{sourceMock{v: sourceControl(t)}, core.Pass}, {sourceMock{v: sourceControl(t), fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
		for _, o := range c.Run(t.Context(), tt.s) {
			if o.Verdict != tt.want {
				t.Fatal(o.Statement, o.Verdict)
			}
		}
	}
}

func TestSourceChecksumAndFinalCancellation(t *testing.T) {
	v := sourceControl(t)
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	entry, _ := w.Create(IntegerSourceModule + "@" + IntegerSourceVersion + "/other.go")
	_, _ = entry.Write([]byte("different source"))
	_ = w.Close()
	v.Archive = data.Bytes()
	for _, o := range judgeIntegerSource(t.Context(), v, "unit") {
		if o.Verdict != core.Error {
			t.Fatal("different valid ZIP accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	obs := finishIntegerSource(ctx, integerSourceEvidence{}, []core.Observation{{Statement: integerSourceIDs[0], Verdict: core.Pass}})
	if obs[0].Verdict != core.Error || obs[0].Observed == "" {
		t.Fatal("late cancellation ignored")
	}
}

func TestConfirmedFloatSurvivesUnknownPaths(t *testing.T) {
	a := sourcearith.Audit{Operations: []sourcearith.Operation{{Integer: false}}, Unknown: []string{"unreviewed call"}}
	if integerAuditVerdict(a) != core.Fail {
		t.Fatal("confirmed violation hidden by unknown path")
	}
}

func TestCarryVerdictsPreserveUnknownContext(t *testing.T) {
	v := sourceControl(t)
	observations := judgeIntegerSource(t.Context(), v, "unit")
	var evidence integerSourceEvidence
	if e := json.Unmarshal([]byte(observations[0].Observed), &evidence); e != nil {
		t.Fatal(e)
	}
	for _, a := range evidence.Carry {
		for i := 0; i < 3; i++ {
			if carryVerdict(a, i) != core.Pass {
				t.Fatal(a)
			}
		}
		a.Steps[0].Correct = false
		if carryVerdict(a, 0) != core.Fail || carryVerdict(a, 1) != core.Pass {
			t.Fatal("step verdicts coupled")
		}
		a.Steps[0].Correct = true
		a.Steps[0].Operation.Integer = false
		if carryVerdict(a, 0) != core.Fail {
			t.Fatal("float accepted")
		}
		a.Unknown = []string{"unreviewed context"}
		if carryVerdict(a, 0) != core.Error {
			t.Fatal("unknown accepted")
		}
		a.Unknown = nil
		a.Frame = "other"
		if carryVerdict(a, 0) != core.Error {
			t.Fatal("context drift accepted")
		}
	}
	for _, a := range []sourcearith.CarryAudit{{}, {Root: IntegerSourceModule + "/internal/multiformats.BaseEncode", Frame: "c043e4908d7fb16b464fe90b45fdc29ce59cf1d4053cb815c915ee27586d4990"}} {
		if carryVerdict(a, 0) != core.Error {
			t.Fatal("missing evidence")
		}
	}
	a := evidence.Carry[0]
	if carryVerdict(a, -1) != core.Error || carryVerdict(a, 3) != core.Error {
		t.Fatal("invalid step")
	}
}

func TestStateVerdictsAreIndependentAndBounded(t *testing.T) {
	observations := judgeIntegerSource(t.Context(), sourceControl(t), "unit")
	var v integerSourceEvidence
	if e := json.Unmarshal([]byte(observations[0].Observed), &v); e != nil {
		t.Fatal(e)
	}
	if len(v.State) != 2 {
		t.Fatal("missing state evidence")
	}
	for _, a := range v.State {
		for i := range a.Steps {
			if stateVerdict(a, i) != core.Pass {
				t.Fatal(a)
			}
		}
		a.Steps[0].Correct = false
		if stateVerdict(a, 0) != core.Fail || stateVerdict(a, 1) != core.Pass {
			t.Fatal("step verdict coupling")
		}
		a.Steps[0].Correct = true
		a.Unknown = []string{"unreviewed"}
		if stateVerdict(a, 0) != core.Error {
			t.Fatal("unknown accepted")
		}
		a.Unknown = nil
		a.Frame = "wrong"
		if stateVerdict(a, 0) != core.Error {
			t.Fatal("frame ignored")
		}
	}
	for _, a := range []sourcearith.StateAudit{{}, {Root: IntegerSourceModule + "/internal/multiformats.BaseEncode", Frame: "4b94ff9ac70dd5af838a92595d85f199f80598e4bfa88b764b6ab4717c41465f"}} {
		if stateVerdict(a, 0) != core.Error {
			t.Fatal("missing steps")
		}
	}
	a := v.State[1]
	if stateVerdict(a, -1) != core.Error || stateVerdict(a, 4) != core.Error {
		t.Fatal("invalid index")
	}
}

func TestCursorVerdictsKeepUnknownAndIndependentSteps(t *testing.T) {
	var v integerSourceEvidence
	obs := judgeIntegerSource(t.Context(), sourceControl(t), "unit")
	if e := json.Unmarshal([]byte(obs[0].Observed), &v); e != nil {
		t.Fatal(e)
	}
	if len(v.Cursor) != 2 {
		t.Fatal("missing cursor")
	}
	for _, a := range v.Cursor {
		for i := range a.Steps {
			if cursorVerdict(a, i) != core.Pass {
				t.Fatal(a)
			}
		}
		a.Steps[0].Correct = false
		if cursorVerdict(a, 0) != core.Fail {
			t.Fatal("wrong cursor accepted")
		}
		if len(a.Steps) == 2 && cursorVerdict(a, 1) != core.Pass {
			t.Fatal("coupled")
		}
		a.Unknown = []string{"unknown"}
		if cursorVerdict(a, 0) != core.Error {
			t.Fatal("unknown accepted")
		}
		a.Unknown = nil
		a.Frame = "wrong"
		if cursorVerdict(a, 0) != core.Error {
			t.Fatal("frame ignored")
		}
	}
	if cursorVerdict(sourcearith.CursorAudit{}, 0) != core.Error {
		t.Fatal("missing evidence")
	}
	a := v.Cursor[0]
	if cursorVerdict(a, -1) != core.Error || cursorVerdict(a, 2) != core.Error {
		t.Fatal("invalid index")
	}
	a.Steps = nil
	if cursorVerdict(a, 0) != core.Error {
		t.Fatal("missing steps")
	}
}

func TestPrefixVerdictsPreserveIndependentPredicates(t *testing.T) {
	var v integerSourceEvidence
	obs := judgeIntegerSource(t.Context(), sourceControl(t), "unit")
	if err := json.Unmarshal([]byte(obs[0].Observed), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Prefix) != 2 || len(obs) != 21 {
		t.Fatal("missing prefix observations")
	}
	for _, a := range v.Prefix {
		for i := range a.Steps {
			if prefixVerdict(a, i) != core.Pass {
				t.Fatal(a)
			}
		}
		a.Steps[0].Correct = false
		if prefixVerdict(a, 0) != core.Fail || prefixVerdict(a, 1) != core.Pass {
			t.Fatal("coupled prefix verdicts")
		}
		a.Unknown = []string{"missing phase"}
		if prefixVerdict(a, 0) != core.Error {
			t.Fatal("unknown accepted")
		}
		a.Unknown = nil
		a.Frame = "wrong"
		if prefixVerdict(a, 0) != core.Error {
			t.Fatal("frame ignored")
		}
	}
	if prefixVerdict(sourcearith.PrefixAudit{}, 0) != core.Error {
		t.Fatal("missing root")
	}
	a := v.Prefix[0]
	if prefixVerdict(a, -1) != core.Error || prefixVerdict(a, 2) != core.Error {
		t.Fatal("invalid index")
	}
	a.Steps = nil
	if prefixVerdict(a, 0) != core.Error {
		t.Fatal("missing steps")
	}
}
