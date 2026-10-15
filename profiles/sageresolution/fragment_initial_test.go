package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func TestFragmentInitialSemanticRoleContract(t *testing.T) {
	e := fragmentControl(t)
	obs := judgeFragmentInitial(t.Context(), e, "unit")
	if obs[0].Verdict != core.Pass {
		t.Fatal(obs)
	}
	var evidence fragmentInitialEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &evidence) != nil {
		t.Fatal("evidence")
	}
	if fragmentInitialVerdict(evidence.Initial) != core.Pass {
		t.Fatal("initial")
	}
	for _, change := range []func(*sourcearith.FragmentInitialAudit){
		func(a *sourcearith.FragmentInitialAudit) { a.Binding.Frames = nil }, func(a *sourcearith.FragmentInitialAudit) { a.Search = "other" }, func(a *sourcearith.FragmentInitialAudit) { a.ResultTypes = []string{"string", "bool"} }, func(a *sourcearith.FragmentInitialAudit) { a.ResultRoles = []string{"other", "ok"} }, func(a *sourcearith.FragmentInitialAudit) { a.InitialValues = []string{"empty map", "false"} }, func(a *sourcearith.FragmentInitialAudit) { a.LanguageRule = "untrusted" }, func(a *sourcearith.FragmentInitialAudit) { a.Unknown = []string{"unreviewed"} },
	} {
		a := evidence.Initial
		change(&a)
		if fragmentInitialVerdict(a) != core.Error {
			t.Fatal(a)
		}
	}
	// A later search failure does not change this entry's semantic zero state.
	a := evidence.Initial
	a.Binding.Steps = append([]sourcearith.StateStep(nil), a.Binding.Steps...)
	a.Binding.Steps[0].Correct = false
	a.Binding.Steps[1].Correct = false
	if fragmentInitialVerdict(a) != core.Pass {
		t.Fatal("construction contaminates initialization")
	}
	a.Binding.Steps[2].Correct = false
	if fragmentInitialVerdict(a) != core.Error {
		t.Fatal("unproven result-to-content role")
	}
	for _, change := range []func(*fragmentSourceEvidence){func(e *fragmentSourceEvidence) { e.Source.Version = "other" }, func(e *fragmentSourceEvidence) { e.Runtime = nil }} {
		bad := fragmentControl(t)
		change(&bad)
		if judgeFragmentInitial(t.Context(), bad, "unit")[0].Verdict != core.Error {
			t.Fatal("invalid premise")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeFragmentInitial(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("canceled")
	}
}

func TestFragmentInitialCaseDispatch(t *testing.T) {
	old := core.Profile{Name: "did-core-1.0"}
	appendFragmentInitialCase(&old)
	if len(old.Cases) != 0 {
		t.Fatal(old)
	}
	p := core.Profile{Name: "did-1.1"}
	appendFragmentInitialCase(&p)
	if len(p.Cases) != 1 || p.Cases[0].Validate() != nil {
		t.Fatal(p)
	}
	e := fragmentControl(t)
	for _, tc := range []struct {
		s    core.Subject
		want core.Verdict
	}{
		{noOperation{}, core.NotSupported}, {fragmentMock{sourceMock: sourceMock{v: e.Source, fail: true}}, core.Error}, {fragmentMock{sourceMock: sourceMock{v: e.Source}, routingFail: true}, core.Error}, {fragmentMock{sourceMock: sourceMock{v: e.Source}, values: e.Runtime}, core.Pass},
	} {
		if o := p.Cases[0].Run(t.Context(), tc.s)[0]; o.Verdict != tc.want {
			t.Fatal(o)
		}
	}
}

// A deterministic cancellation clock checks cancellation between the two
// independent source analyses and after the last semantic audit.
type fragmentCancelClock struct {
	context.Context
	count int
	after int
}

func (c *fragmentCancelClock) Err() error {
	c.count++
	if c.after > 0 && c.count > c.after {
		return context.Canceled
	}
	return nil
}
func TestFragmentInitialLateCancellation(t *testing.T) {
	e := fragmentControl(t)
	first := &fragmentCancelClock{Context: t.Context()}
	judgeFragmentSource(first, e, "unit")
	all := &fragmentCancelClock{Context: t.Context()}
	if judgeFragmentInitial(all, e, "unit")[0].Verdict != core.Pass {
		t.Fatal("baseline")
	}
	for _, n := range []int{first.count, all.count - 1} {
		ctx := &fragmentCancelClock{Context: t.Context(), after: n}
		if judgeFragmentInitial(ctx, e, "unit")[0].Verdict != core.Error {
			t.Fatal("late cancellation", n)
		}
	}
}

func TestFragmentInitialPreservesPartialCapture(t *testing.T) {
	e := fragmentControl(t)
	p := core.Profile{Name: "did-1.1"}
	appendFragmentInitialCase(&p)
	o := p.Cases[0].Run(t.Context(), fragmentMock{sourceMock: sourceMock{v: e.Source}, routingFail: true})[0]
	var capture fragmentSourceEvidence
	if o.Verdict != core.Error || json.Unmarshal([]byte(o.Observed), &capture) != nil || len(capture.Runtime) != 1 || len(capture.Runtime[0]) != 1 {
		t.Fatal("partial receipt lost", o)
	}
}
