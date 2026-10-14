package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
)

func fragmentControl(t *testing.T) fragmentSourceEvidence {
	t.Helper()
	v := sourceControl(t)
	v.Request = fragmentSourceRequest()
	v.Diagnostics = []CodecResult{}
	files, _, e := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if e != nil {
		t.Fatal(e)
	}
	v.Files = sourcearith.SourceFiles(files, v.Request.Packages)
	evi := fragmentSourceEvidence{Source: v, Runtime: [][]RoutingResult{}}
	for _, f := range fragmentFixtures() {
		evi.Runtime = append(evi.Runtime, resourceControls(f))
	}
	return evi
}
func TestFragmentPinnedSourceAndRuntime(t *testing.T) {
	e := fragmentControl(t)
	obs := judgeFragmentSource(t.Context(), e, "unit")
	for _, o := range obs {
		if o.Verdict != core.Pass || o.Observed == "" {
			t.Fatal(o.Statement, o.Verdict, o.Observed)
		}
	}
	var got fragmentSourceEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &got) != nil {
		t.Fatal("evidence")
	}
	for i := range fragmentSourceIDs {
		if fragmentSourceVerdict(got.Audit, i) != core.Pass {
			t.Fatal(i)
		}
		bad := got.Audit
		bad.Steps = append([]sourcearith.StateStep(nil), bad.Steps...)
		bad.Steps[i].Correct = false
		for j := range fragmentSourceIDs {
			want := core.Pass
			if i == j {
				want = core.Fail
			}
			if fragmentSourceVerdict(bad, j) != want {
				t.Fatal("coupled predicate", i, j)
			}
		}
	}
	for _, change := range []func(*fragmentSourceEvidence){
		func(e *fragmentSourceEvidence) { e.Source.Version = "other" },
		func(e *fragmentSourceEvidence) { e.Source.Archive = nil },
		func(e *fragmentSourceEvidence) { e.Source.Files = nil },
		func(e *fragmentSourceEvidence) { e.Source.Files["dereferencer/fragment.go"] = []byte("changed") },
		func(e *fragmentSourceEvidence) { e.Runtime = nil },
	} {
		e := fragmentControl(t)
		change(&e)
		for _, o := range judgeFragmentSource(t.Context(), e, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unbound source or runtime accepted", o)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, o := range judgeFragmentSource(ctx, fragmentControl(t), "unit") {
		if o.Verdict != core.Error {
			t.Fatal("cancelled analysis")
		}
	}
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	o := finishFragmentSource(ctx, fragmentSourceEvidence{}, []core.Observation{{Verdict: core.Pass}})
	if o[0].Verdict != core.Error || o[0].Observed == "" {
		t.Fatal("late cancellation")
	}
}
func TestFragmentReviewedContextAndRuntimeControls(t *testing.T) {
	var witness sourcearith.FragmentAudit
	if json.Unmarshal(fragmentWitnessBytes, &witness) != nil {
		t.Fatal("witness")
	}
	for _, change := range []func(*sourcearith.FragmentAudit){
		func(a *sourcearith.FragmentAudit) { a.Root = "other" },
		func(a *sourcearith.FragmentAudit) { a.Frames = nil },
		func(a *sourcearith.FragmentAudit) { a.CallPaths = nil },
		func(a *sourcearith.FragmentAudit) { a.Unknown = []string{"unreviewed"} },
		func(a *sourcearith.FragmentAudit) { a.Steps = nil },
	} {
		a := witness
		change(&a)
		if fragmentSourceVerdict(a, 0) != core.Error {
			t.Fatal("context accepted")
		}
	}
	for _, i := range []int{-1, 3} {
		if fragmentSourceVerdict(witness, i) != core.Error {
			t.Fatal("index")
		}
	}
	fixtures := fragmentFixtures()
	controls := func() [][]RoutingResult {
		out := [][]RoutingResult{}
		for _, f := range fixtures {
			out = append(out, resourceControls(f))
		}
		return out
	}
	if fragmentRuntime(controls()) != core.Pass || fragmentRuntime(nil) != core.Error {
		t.Fatal("baseline")
	}
	for _, change := range []func(*RoutingResult){func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.Request.Request.Input = "other" }, func(v *RoutingResult) { v.Result.Raw = []byte(`{`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{"contentType":"a","contentType":"b"}`) }} {
		v := controls()
		change(&v[0][0])
		if fragmentRuntime(v) != core.Error {
			t.Fatal("missing provenance/JSON")
		}
	}
	v := controls()
	v[0] = nil
	if fragmentRuntime(v) != core.Error {
		t.Fatal("missing call")
	}
	for _, change := range []func(*RoutingResult){func(v *RoutingResult) { v.Result.Raw = []byte(`{}`) }, func(v *RoutingResult) { v.Result.HasContent = false }, func(v *RoutingResult) { v.Result.ReturnedID = "other" }, func(v *RoutingResult) { v.Result.ContentKind = "other" }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{"contentType":"other"}`) }} {
		v := controls()
		change(&v[0][0])
		if fragmentRuntime(v) != core.Fail {
			t.Fatal("wrong actual content")
		}
	}
	v = controls()
	v[0][1].Result.HasContent = true
	if fragmentRuntime(v) != core.Fail {
		t.Fatal("wrong miss")
	}
	e := fragmentControl(t)
	e.Runtime[0][0].Result.Raw = []byte(`{}`)
	o := judgeFragmentSource(t.Context(), e, "unit")
	if o[0].Verdict != core.Pass || o[1].Verdict != core.Pass || o[2].Verdict != core.Error {
		t.Fatal("runtime contaminated independent construction", o)
	}
}

type fragmentMock struct {
	sourceMock
	values      [][]RoutingResult
	routingFail bool
}

func (s fragmentMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	if s.routingFail {
		return RoutingResult{}, errors.New("capture unavailable")
	}
	for i, f := range fragmentFixtures() {
		for j := range f.Requests {
			if q.Request.Input == f.Requests[j].Input {
				return s.values[i][j], nil
			}
		}
	}
	return RoutingResult{}, errors.New("unknown fixture")
}
func TestFragmentSourceDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendFragmentSourceCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendFragmentSourceCases(&p)
	if len(p.Cases) != 1 || p.Cases[0].Validate() != nil {
		t.Fatal("case")
	}
	e := fragmentControl(t)
	for _, tc := range []struct {
		s    core.Subject
		want core.Verdict
	}{
		{noOperation{}, core.NotSupported},
		{fragmentMock{sourceMock: sourceMock{v: e.Source, fail: true}}, core.Error},
		{fragmentMock{sourceMock: sourceMock{v: e.Source}, routingFail: true}, core.Error},
		{fragmentMock{sourceMock: sourceMock{v: e.Source}, values: e.Runtime}, core.Pass},
	} {
		for _, o := range p.Cases[0].Run(t.Context(), tc.s) {
			if o.Verdict != tc.want {
				t.Fatal(o.Statement, o.Verdict, tc.want)
			}
		}
	}
}
