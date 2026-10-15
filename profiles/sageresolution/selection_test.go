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

func selectionControls(t *testing.T) selectionEvidence {
	e := selectionEvidence{Source: fragmentControl(t), Runtime: []RoutingResult{}}
	for _, f := range selectionFixtures() {
		v := resourceControl(resourceChoiceFixture{Document: f.Document, Requests: []Request{f.Request}, Content: f.Content, Kind: f.Kind, Media: "text/uri-list"}, 0)
		if f.Request.Accept != "" {
			v.Options = []byte(`{"accept":"` + f.Request.Accept + `"}`)
		} else {
			v.Options = []byte(`{}`)
		}
		media := "application/did"
		driverMedia := ""
		if selectionMedia(f.Request.Accept) {
			media = f.Request.Accept
			if f.Request.Accept == "application/did" {
				driverMedia = f.Request.Accept
			}
		}
		v.DriverOptions[0], _ = json.Marshal(map[string]any{"VersionID": "", "VersionTime": nil, "MediaType": driverMedia, "NoCache": false})
		v.ResolvedDataModel = f.Document
		v.ResolvedEntries = []byte(`{}`)
		v.ResolvedMetadata, _ = json.Marshal(map[string]any{"contentType": media})
		v.ResolveOptions[0] = selectionOptionsControl(f)
		if f.Kind == "document" && f.Error == "" {
			v.DataModel = f.Content
		} else {
			v.DataModel = f.Document
		}
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
				v.Result.Metadata, _ = json.Marshal(map[string]any{"contentType": media})
			}
		}
		e.Runtime = append(e.Runtime, v)
	}
	return e
}
func TestSelectionIndependentRolesAndCapture(t *testing.T) {
	e := selectionControls(t)
	obs := judgeSelection(t.Context(), e, "unit")
	for _, o := range obs {
		if o.Verdict != core.Pass {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	var checked selectionEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &checked) != nil {
		t.Fatal("capture")
	}
	for i := range selectionIDs {
		a := checked.Audit
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = false
		for j := range selectionIDs {
			want := core.Pass
			if i == j {
				want = core.Fail
			}
			if selectionVerdict(a, j) != want {
				t.Fatal("coupled roles")
			}
		}
	}
	for _, i := range []int{-1, 4} {
		if selectionVerdict(checked.Audit, i) != core.Error {
			t.Fatal(i)
		}
	}
	for _, change := range []func(*sourcearith.ServiceAudit){func(a *sourcearith.ServiceAudit) { a.Roots = nil }, func(a *sourcearith.ServiceAudit) { a.Frames = nil }, func(a *sourcearith.ServiceAudit) { a.Roles = nil }, func(a *sourcearith.ServiceAudit) { a.Unknown = []string{"lost"} }, func(a *sourcearith.ServiceAudit) { a.Steps = nil }, func(a *sourcearith.ServiceAudit) {
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[0].Kind = "other"
	}} {
		a := checked.Audit
		change(&a)
		if selectionVerdict(a, 0) != core.Error {
			t.Fatal(a)
		}
	}
	for _, change := range []func(*selectionEvidence){func(e *selectionEvidence) { e.Source.Source.Version = "other" }, func(e *selectionEvidence) { e.Runtime = nil }, func(e *selectionEvidence) { e.Runtime[0].Request.Request.Input = "other" }, func(e *selectionEvidence) { e.Runtime[0].ResolvedDataModel = []byte(`{}`) }, func(e *selectionEvidence) { e.Runtime[0].DataModel = []byte(`{}`) }, func(e *selectionEvidence) { e.Runtime[0].ResolvedMetadata = []byte(`{}`) }, func(e *selectionEvidence) { e.Runtime[0].ResolvedEntries = []byte(`{"extra":true}`) }, func(e *selectionEvidence) { e.Runtime[0].DriverResults[0] = []byte(`{`) }, func(e *selectionEvidence) {
		e.Runtime[0].DriverResults[0] = []byte(`{"Data":"%","ContentType":"application/did"}`)
	}, func(e *selectionEvidence) { e.Runtime[0].Result.Metadata = []byte(`{`) }, func(e *selectionEvidence) { e.Runtime[0].Result.HasContent = false }, func(e *selectionEvidence) { e.Runtime[3].Result.HasContent = true }, func(e *selectionEvidence) { e.Runtime[0].Result.Raw = []byte(`{}`) }} {
		bad := selectionControls(t)
		change(&bad)
		for _, o := range judgeSelection(t.Context(), bad, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unbound evidence")
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeSelection(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}

type selectionMock struct {
	fragmentMock
	runtime  []RoutingResult
	lateFail bool
}

func (s selectionMock) InspectRouting(ctx context.Context, q RoutingRequest) (RoutingResult, error) {
	for i, f := range selectionFixtures() {
		if reflect.DeepEqual(q, selectionRequest(f)) {
			if s.lateFail {
				return s.runtime[i], errors.New("lost receipt")
			}
			return s.runtime[i], nil
		}
	}
	return s.fragmentMock.InspectRouting(ctx, q)
}
func TestSelectionCaseDispatchAndPartialErrors(t *testing.T) {
	old := core.Profile{Name: "did-core-1.0"}
	appendSelectionCase(&old)
	if len(old.Cases) != 0 {
		t.Fatal(old)
	}
	p := core.Profile{Name: "did-1.1"}
	appendSelectionCase(&p)
	if len(p.Cases) != 1 || p.Cases[0].Validate() != nil {
		t.Fatal(p)
	}
	e := selectionControls(t)
	good := selectionMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, values: e.Source.Runtime}, runtime: e.Runtime}
	for _, tc := range []struct {
		s    core.Subject
		want core.Verdict
	}{{noOperation{}, core.NotSupported}, {good, core.Pass}, {selectionMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source, fail: true}}}, core.Error}, {selectionMock{fragmentMock: fragmentMock{sourceMock: sourceMock{v: e.Source.Source}, routingFail: true}}, core.Error}} {
		if o := p.Cases[0].Run(t.Context(), tc.s)[0]; o.Verdict != tc.want {
			t.Fatal(o.Statement, o.Verdict)
		}
	}
	good.lateFail = true
	o := p.Cases[0].Run(t.Context(), good)[0]
	var partial selectionEvidence
	if o.Verdict != core.Error || json.Unmarshal([]byte(o.Observed), &partial) != nil || len(partial.Runtime) != 1 {
		t.Fatal("partial receipt lost")
	}
	first := &fragmentCancelClock{Context: t.Context()}
	judgeFragmentSource(first, e.Source, "unit")
	all := &fragmentCancelClock{Context: t.Context()}
	if judgeSelection(all, e, "unit")[0].Verdict != core.Pass {
		t.Fatal("baseline")
	}
	for _, n := range []int{first.count, all.count - 1} {
		ctx := &fragmentCancelClock{Context: t.Context(), after: n}
		if judgeSelection(ctx, e, "unit")[0].Verdict != core.Error {
			t.Fatal("late cancel")
		}
	}
}

func selectionOptionsControl(f selectionFixture) []byte {
	m := map[string]any{}
	if selectionMedia(f.Request.Accept) {
		m["accept"] = f.Request.Accept
	}
	for k, v := range f.Parameters {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}
