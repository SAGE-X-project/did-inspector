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

func dispatchControls(t *testing.T) dispatchEvidence {
	e := dispatchEvidence{Source: fragmentControl(t), Runtime: []RoutingResult{}}
	for _, f := range dispatchFixtures() {
		v := resourceControl(resourceChoiceFixture{Document: f.Document, Requests: []Request{f.Request}, Content: f.Content, Kind: f.Kind, Media: f.Media}, 0)
		if f.Request.Accept != "" {
			v.Options = []byte(`{"accept":"` + f.Request.Accept + `"}`)
		} else {
			v.Options = []byte(`{}`)
		}
		media := "application/did"
		driverMedia := ""
		if f.Request.Accept == "application/did" {
			media = f.Request.Accept
			if f.Request.Accept == "application/did" {
				driverMedia = f.Request.Accept
			}
		}
		v.DriverOptions[0], _ = json.Marshal(map[string]any{"VersionID": "", "VersionTime": nil, "MediaType": driverMedia, "NoCache": false})
		v.ResolvedDataModel = f.Document
		v.ResolvedEntries = []byte(`{}`)
		v.ResolvedMetadata, _ = json.Marshal(map[string]any{"contentType": media})
		if f.Request.Relationship != "" {
			v.Options, _ = json.Marshal(map[string]any{"accept": f.Request.Accept, "verificationRelationship": f.Request.Relationship})
		}
		v.ResolveOptions[0] = dispatchOptionsControl(f)
		if f.Kind == "document" && f.Error == "" {
			v.DataModel = f.Content
		} else {
			v.DataModel = f.Document
		}
		v.Entries = []byte(`{}`)
		if f.Error != "" {
			v.Result = Result{Metadata: []byte(`{"error":{"type":"` + f.Error + `"}}`), ContentMetadata: []byte(`{}`), Raw: []byte(`null`)}
		} else {
			v.Result.Metadata, _ = json.Marshal(map[string]any{"contentType": f.Media})
			want, _ := core.ParseJSON(f.Content)
			id, _ := want.Get("id")
			v.Result.ReturnedID = id.Str
			if f.Kind == "uri-list" {
				v.Result.ContentMetadata = []byte(`{"contentType":"text/uri-list"}`)
			} else {
				v.Result.ContentMetadata = []byte(`{}`)
			}
		}
		e.Runtime = append(e.Runtime, v)
	}
	return e
}
func TestDispatchIndependentRolesAndCapture(t *testing.T) {
	e := dispatchControls(t)
	obs := judgeDispatch(t.Context(), e, "unit")
	for _, o := range obs {
		if o.Verdict != core.Pass {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	var checked dispatchEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &checked) != nil {
		t.Fatal("capture")
	}
	for i := range dispatchIDs {
		a := checked.Audit
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = false
		for j := range dispatchIDs {
			want := core.Pass
			if i == j {
				want = core.Fail
			}
			if dispatchVerdict(a, j) != want {
				t.Fatal("coupled roles")
			}
		}
	}
	for _, i := range []int{-1, 3} {
		if dispatchVerdict(checked.Audit, i) != core.Error {
			t.Fatal(i)
		}
	}
	for _, change := range []func(*sourcearith.ServiceAudit){func(a *sourcearith.ServiceAudit) { a.Roots = nil }, func(a *sourcearith.ServiceAudit) { a.Frames = nil }, func(a *sourcearith.ServiceAudit) { a.Roles = nil }, func(a *sourcearith.ServiceAudit) { a.Unknown = []string{"lost"} }, func(a *sourcearith.ServiceAudit) { a.Steps = nil }, func(a *sourcearith.ServiceAudit) {
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[0].Kind = "other"
	}} {
		a := checked.Audit
		change(&a)
		if dispatchVerdict(a, 0) != core.Error {
			t.Fatal(a)
		}
	}
	for _, change := range []func(*dispatchEvidence){func(e *dispatchEvidence) { e.Source.Source.Version = "other" }, func(e *dispatchEvidence) { e.Runtime = nil }, func(e *dispatchEvidence) { e.Runtime[0].Request.Request.Input = "other" }, func(e *dispatchEvidence) { e.Runtime[0].ResolvedDataModel = []byte(`{}`) }, func(e *dispatchEvidence) { e.Runtime[0].DataModel = []byte(`{}`) }, func(e *dispatchEvidence) { e.Runtime[0].ResolvedMetadata = []byte(`{}`) }, func(e *dispatchEvidence) { e.Runtime[0].ResolvedEntries = []byte(`{"extra":true}`) }, func(e *dispatchEvidence) { e.Runtime[0].DriverResults[0] = []byte(`{`) }, func(e *dispatchEvidence) {
		e.Runtime[0].DriverResults[0] = []byte(`{"Data":"%","ContentType":"application/did"}`)
	}, func(e *dispatchEvidence) { e.Runtime[0].Result.Metadata = []byte(`{`) }, func(e *dispatchEvidence) { e.Runtime[0].Result.HasContent = false }, func(e *dispatchEvidence) { e.Runtime[3].Result.HasContent = true }, func(e *dispatchEvidence) { e.Runtime[0].Result.Raw = []byte(`{}`) }} {
		bad := dispatchControls(t)
		change(&bad)
		for _, o := range judgeDispatch(t.Context(), bad, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unbound evidence")
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeDispatch(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}

type dispatchMock struct {
	fragmentMock
	runtime  []RoutingResult
	lateFail bool
}

func (s dispatchMock) InspectRouting(ctx context.Context, q RoutingRequest) (RoutingResult, error) {
	for i, f := range dispatchFixtures() {
		if reflect.DeepEqual(q, dispatchRequest(f)) {
			if s.lateFail {
				return s.runtime[i], errors.New("lost receipt")
			}
			return s.runtime[i], nil
		}
	}
	return s.fragmentMock.InspectRouting(ctx, q)
}
func TestDispatchCaseDispatchAndPartialErrors(t *testing.T) {
	old := core.Profile{Name: "did-core-1.0"}
	appendDispatchCase(&old)
	if len(old.Cases) != 0 {
		t.Fatal(old)
	}
	p := core.Profile{Name: "did-1.1"}
	appendDispatchCase(&p)
	if len(p.Cases) != 1 || p.Cases[0].Validate() != nil {
		t.Fatal(p)
	}
	e := dispatchControls(t)
	good := dispatchMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, values: e.Source.Runtime}, runtime: e.Runtime}
	for _, tc := range []struct {
		s    core.Subject
		want core.Verdict
	}{{noOperation{}, core.NotSupported}, {good, core.Pass}, {dispatchMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source, fail: true}}}, core.Error}, {dispatchMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, routingFail: true}}, core.Error}} {
		if o := p.Cases[0].Run(t.Context(), tc.s)[0]; o.Verdict != tc.want {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	good.lateFail = true
	o := p.Cases[0].Run(t.Context(), good)[0]
	var partial dispatchEvidence
	if o.Verdict != core.Error || json.Unmarshal([]byte(o.Observed), &partial) != nil || len(partial.Runtime) != 1 {
		t.Fatal("partial receipt lost")
	}
	first := &fragmentCancelClock{Context: t.Context()}
	judgeFragmentSource(first, e.Source, "unit")
	all := &fragmentCancelClock{Context: t.Context()}
	if judgeDispatch(all, e, "unit")[0].Verdict != core.Pass {
		t.Fatal("baseline")
	}
	for _, n := range []int{first.count, all.count - 1} {
		ctx := &fragmentCancelClock{Context: t.Context(), after: n}
		if judgeDispatch(ctx, e, "unit")[0].Verdict != core.Error {
			t.Fatal("late cancel")
		}
	}
}

func dispatchOptionsControl(f dispatchFixture) []byte {
	m := map[string]any{}
	if f.Request.Accept == "application/did" {
		m["accept"] = f.Request.Accept
	}
	if f.Request.Relationship != "" {
		m["verificationRelationship"] = f.Request.Relationship
	}
	for k, v := range f.Parameters {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}
