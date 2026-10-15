package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"testing"
)

func relationshipControls(t *testing.T) relationshipEvidence {
	e := relationshipEvidence{Source: fragmentControl(t), Runtime: []RoutingResult{}}
	for _, f := range relationshipFixtures() {
		v := resourceControl(resourceChoiceFixture{Document: f.Document, Requests: []Request{f.Request}, Content: f.Content, Kind: f.Kind, Media: "application/ld+json"}, 0)
		v.Options, v.ResolveOptions[0] = relationshipOptions(f)
		v.DataModel = f.Document
		v.Entries = []byte(`{}`)
		if f.Error != "" {
			v.Result = Result{Metadata: []byte(`{"error":{"type":"https://w3id.org/security#` + f.Error + `"}}`), ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
		} else {
			want, _ := core.ParseJSON(f.Content)
			id, _ := want.Get("id")
			v.Result.ReturnedID = id.Str
		}
		e.Runtime = append(e.Runtime, v)
	}
	return e
}
func TestRelationshipIndependentRolesAndCapture(t *testing.T) {
	e := relationshipControls(t)
	obs := judgeRelationship(t.Context(), e, "unit")
	for _, o := range obs {
		if o.Verdict != core.Pass {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	var checked relationshipEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &checked) != nil {
		t.Fatal("capture")
	}
	for i := range fragmentRelationshipIDs {
		a := checked.Audit
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = false
		for j := range fragmentRelationshipIDs {
			want := core.Pass
			if i == j {
				want = core.Fail
			}
			if relationshipVerdict(a, j) != want {
				t.Fatal("coupled roles")
			}
		}
	}
	for _, i := range []int{-1, 2} {
		if relationshipVerdict(checked.Audit, i) != core.Error {
			t.Fatal(i)
		}
	}
	for _, change := range []func(*sourcearith.FragmentRelationshipAudit){func(a *sourcearith.FragmentRelationshipAudit) { a.Root = "other" }, func(a *sourcearith.FragmentRelationshipAudit) { a.Frame = "other" }, func(a *sourcearith.FragmentRelationshipAudit) { a.Roles = nil }, func(a *sourcearith.FragmentRelationshipAudit) { a.Unknown = []string{"lost"} }, func(a *sourcearith.FragmentRelationshipAudit) { a.Steps = nil }, func(a *sourcearith.FragmentRelationshipAudit) {
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[0].Kind = "other"
	}} {
		a := checked.Audit
		change(&a)
		if relationshipVerdict(a, 0) != core.Error {
			t.Fatal(a)
		}
	}
	for _, change := range []func(*relationshipEvidence){func(e *relationshipEvidence) { e.Source.Source.Version = "other" }, func(e *relationshipEvidence) { e.Runtime = nil }, func(e *relationshipEvidence) { e.Runtime[0].Request.Request.Relationship = "other" }, func(e *relationshipEvidence) { e.Runtime[0].DataModel = []byte(`{}`) }, func(e *relationshipEvidence) { e.Runtime[0].DriverResults[0] = []byte(`{`) }, func(e *relationshipEvidence) {
		e.Runtime[0].DriverResults[0] = []byte(`{"Data":"%","ContentType":"application/did"}`)
	}, func(e *relationshipEvidence) { e.Runtime[0].Result.Metadata = []byte(`{`) }, func(e *relationshipEvidence) { e.Runtime[0].Result.HasContent = false }, func(e *relationshipEvidence) { e.Runtime[2].Result.HasContent = true }, func(e *relationshipEvidence) { e.Runtime[0].Result.Raw = []byte(`{}`) }} {
		bad := relationshipControls(t)
		change(&bad)
		for _, o := range judgeRelationship(t.Context(), bad, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unbound evidence")
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeRelationship(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}

type relationshipMock struct {
	fragmentMock
	runtime  []RoutingResult
	lateFail bool
}

func (s relationshipMock) InspectRouting(ctx context.Context, q RoutingRequest) (RoutingResult, error) {
	for i, f := range relationshipFixtures() {
		if reflect.DeepEqual(q, relationshipRequest(f)) {
			if s.lateFail {
				return s.runtime[i], errors.New("lost receipt")
			}
			return s.runtime[i], nil
		}
	}
	return s.fragmentMock.InspectRouting(ctx, q)
}
func TestRelationshipCaseDispatchAndPartialErrors(t *testing.T) {
	old := core.Profile{Name: "did-core-1.0"}
	appendFragmentRelationshipCase(&old)
	if len(old.Cases) != 0 {
		t.Fatal(old)
	}
	p := core.Profile{Name: "did-1.1"}
	appendFragmentRelationshipCase(&p)
	if len(p.Cases) != 1 || p.Cases[0].Validate() != nil {
		t.Fatal(p)
	}
	e := relationshipControls(t)
	good := relationshipMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, values: e.Source.Runtime}, runtime: e.Runtime}
	for _, tc := range []struct {
		s    core.Subject
		want core.Verdict
	}{{noOperation{}, core.NotSupported}, {good, core.Pass}, {relationshipMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source, fail: true}}}, core.Error}, {relationshipMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, routingFail: true}}, core.Error}} {
		if o := p.Cases[0].Run(t.Context(), tc.s)[0]; o.Verdict != tc.want {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	good.lateFail = true
	o := p.Cases[0].Run(t.Context(), good)[0]
	var partial relationshipEvidence
	if o.Verdict != core.Error || json.Unmarshal([]byte(o.Observed), &partial) != nil || len(partial.Runtime) != 1 {
		t.Fatal("partial receipt lost")
	}
	first := &fragmentCancelClock{Context: t.Context()}
	judgeFragmentSource(first, e.Source, "unit")
	all := &fragmentCancelClock{Context: t.Context()}
	if judgeRelationship(all, e, "unit")[0].Verdict != core.Pass {
		t.Fatal("baseline")
	}
	for _, n := range []int{first.count, all.count - 1} {
		ctx := &fragmentCancelClock{Context: t.Context(), after: n}
		if judgeRelationship(ctx, e, "unit")[0].Verdict != core.Error {
			t.Fatal("late cancel")
		}
	}
}
