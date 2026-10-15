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

func serviceControls(t *testing.T) serviceEvidence {
	e := serviceEvidence{Source: fragmentControl(t), Runtime: []RoutingResult{}}
	for _, f := range serviceFixtures() {
		v := resourceControl(resourceChoiceFixture{Document: f.Document, Requests: []Request{f.Request}, Content: f.Content, Kind: f.Kind, Media: "text/uri-list"}, 0)
		v.Options = []byte(`{"accept":"` + f.Request.Accept + `"}`)
		v.ResolveOptions[0] = serviceOptionsControl(f)
		v.DataModel = f.Document
		v.Entries = []byte(`{}`)
		if f.Error != "" {
			v.Result = Result{Metadata: []byte(`{"error":{"type":"https://www.w3.org/ns/did#` + f.Error + `"}}`), ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
		} else {
			want, _ := core.ParseJSON(f.Content)
			id, _ := want.Get("id")
			v.Result.ReturnedID = id.Str
			if f.Kind == "uri-list" {
				v.Result.ContentMetadata = []byte(`{"contentType":"text/uri-list"}`)
			} else {
				v.Result.Metadata = []byte(`{"contentType":"application/did"}`)
			}
		}
		e.Runtime = append(e.Runtime, v)
	}
	return e
}
func TestServiceIndependentRolesAndCapture(t *testing.T) {
	e := serviceControls(t)
	obs := judgeServiceSource(t.Context(), e, "unit")
	for _, o := range obs {
		if o.Verdict != core.Pass {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	var checked serviceEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &checked) != nil {
		t.Fatal("capture")
	}
	for i := range serviceSourceIDs {
		a := checked.Audit
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = false
		for j := range serviceSourceIDs {
			want := core.Pass
			if i == j {
				want = core.Fail
			}
			if serviceVerdict(a, j) != want {
				t.Fatal("coupled roles")
			}
		}
	}
	for _, i := range []int{-1, 4} {
		if serviceVerdict(checked.Audit, i) != core.Error {
			t.Fatal(i)
		}
	}
	for _, change := range []func(*sourcearith.ServiceAudit){func(a *sourcearith.ServiceAudit) { a.Roots = nil }, func(a *sourcearith.ServiceAudit) { a.Frames = nil }, func(a *sourcearith.ServiceAudit) { a.Roles = nil }, func(a *sourcearith.ServiceAudit) { a.Unknown = []string{"lost"} }, func(a *sourcearith.ServiceAudit) { a.Steps = nil }, func(a *sourcearith.ServiceAudit) {
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[0].Kind = "other"
	}} {
		a := checked.Audit
		change(&a)
		if serviceVerdict(a, 0) != core.Error {
			t.Fatal(a)
		}
	}
	for _, change := range []func(*serviceEvidence){func(e *serviceEvidence) { e.Source.Source.Version = "other" }, func(e *serviceEvidence) { e.Runtime = nil }, func(e *serviceEvidence) { e.Runtime[0].Request.Request.Input = "other" }, func(e *serviceEvidence) { e.Runtime[0].DataModel = []byte(`{}`) }, func(e *serviceEvidence) { e.Runtime[0].DriverResults[0] = []byte(`{`) }, func(e *serviceEvidence) {
		e.Runtime[0].DriverResults[0] = []byte(`{"Data":"%","ContentType":"application/did"}`)
	}, func(e *serviceEvidence) { e.Runtime[0].Result.Metadata = []byte(`{`) }, func(e *serviceEvidence) { e.Runtime[0].Result.HasContent = false }, func(e *serviceEvidence) { e.Runtime[6].Result.HasContent = true }, func(e *serviceEvidence) { e.Runtime[0].Result.Raw = []byte(`{}`) }} {
		bad := serviceControls(t)
		change(&bad)
		for _, o := range judgeServiceSource(t.Context(), bad, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unbound evidence")
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeServiceSource(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}

type serviceMock struct {
	fragmentMock
	runtime  []RoutingResult
	lateFail bool
}

func (s serviceMock) InspectRouting(ctx context.Context, q RoutingRequest) (RoutingResult, error) {
	for i, f := range serviceFixtures() {
		if reflect.DeepEqual(q, serviceRequest(f)) {
			if s.lateFail {
				return s.runtime[i], errors.New("lost receipt")
			}
			return s.runtime[i], nil
		}
	}
	return s.fragmentMock.InspectRouting(ctx, q)
}
func TestServiceCaseDispatchAndPartialErrors(t *testing.T) {
	old := core.Profile{Name: "did-core-1.0"}
	appendServiceSourceCase(&old)
	if len(old.Cases) != 0 {
		t.Fatal(old)
	}
	p := core.Profile{Name: "did-1.1"}
	appendServiceSourceCase(&p)
	if len(p.Cases) != 1 || p.Cases[0].Validate() != nil {
		t.Fatal(p)
	}
	e := serviceControls(t)
	good := serviceMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, values: e.Source.Runtime}, runtime: e.Runtime}
	for _, tc := range []struct {
		s    core.Subject
		want core.Verdict
	}{{noOperation{}, core.NotSupported}, {good, core.Pass}, {serviceMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source, fail: true}}}, core.Error}, {serviceMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, routingFail: true}}, core.Error}} {
		if o := p.Cases[0].Run(t.Context(), tc.s)[0]; o.Verdict != tc.want {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	good.lateFail = true
	o := p.Cases[0].Run(t.Context(), good)[0]
	var partial serviceEvidence
	if o.Verdict != core.Error || json.Unmarshal([]byte(o.Observed), &partial) != nil || len(partial.Runtime) != 1 {
		t.Fatal("partial receipt lost")
	}
	first := &fragmentCancelClock{Context: t.Context()}
	judgeFragmentSource(first, e.Source, "unit")
	all := &fragmentCancelClock{Context: t.Context()}
	if judgeServiceSource(all, e, "unit")[0].Verdict != core.Pass {
		t.Fatal("baseline")
	}
	for _, n := range []int{first.count, all.count - 1} {
		ctx := &fragmentCancelClock{Context: t.Context(), after: n}
		if judgeServiceSource(ctx, e, "unit")[0].Verdict != core.Error {
			t.Fatal("late cancel")
		}
	}
}

func serviceOptionsControl(f serviceFixture) []byte {
	m := map[string]any{}
	if f.Request.Accept == "application/did" {
		m["accept"] = "application/did"
	}
	for k, v := range f.Parameters {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}
