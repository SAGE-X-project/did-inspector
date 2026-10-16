package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func applicationControls() []RoutingResult {
	out := []RoutingResult{}
	for i, q := range applicationRequests() {
		read, _ := json.Marshal(map[string]any{"ContentType": "application/did", "Data": q.Document.Data})
		v := RoutingResult{Request: q, Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: IntegerSourceModule + "/dereferencer.Dereferencer.Dereference", Options: []byte(`{}`), ResolveInputs: []string{applicationDID}, ResolveOptions: [][]byte{[]byte(`{}`)}, DriverInputs: []string{applicationDID}, DriverOptions: [][]byte{[]byte(`{"VersionID":"","VersionTime":null,"MediaType":"","NoCache":false}`)}, DriverResults: [][]byte{read}, DataModel: []byte(applicationModel), Entries: []byte(applicationEntries), ResolvedDataModel: []byte(applicationModel), ResolvedEntries: []byte(applicationEntries), ResolvedMetadata: []byte(`{"contentType":"application/did"}`), Consumption: []ConsumptionCapture{{Operation: pipelineConsumer, Input: []byte(applicationDocument), MediaType: "application/did", Require: "unknown", Expected: "unknown", Version: "1.1", JSONLD: true, Model: []byte(applicationModel), Entries: []byte(applicationEntries)}}}
		result := Result{HasContent: true, ContentKind: "map", ReturnedID: applicationURL, Raw: []byte(applicationResource), Snapshot: []byte(applicationResource), Metadata: []byte(`{"contentType":"application/json"}`), ContentMetadata: []byte(`{"versionId":"application-1"}`)}
		if i < 2 {
			h := ApplicationResourceCapture{Input: ResourceHandlerCapture{Operation: IntegerSourceModule + "/dereferencer.ResourceHandler", Role: "explicit controlled application callback; not SAGE method support", URL: URLParts{Input: applicationURL, Primary: applicationURL, Path: "/public-resource"}, Options: []byte(`{}`), Model: []byte(applicationModel), Entries: []byte(applicationEntries), Metadata: []byte(`{"contentType":"application/did"}`)}, Handled: i == 0, Returned: result}
			if i == 1 {
				h.Returned = Result{Raw: []byte(`null`), Metadata: []byte(`{}`), ContentMetadata: []byte(`{}`)}
			}
			v.ApplicationHandler = []ApplicationResourceCapture{h}
		}
		v.Result = result
		if i == 1 || i == 2 {
			v.Result = Result{Raw: []byte(`null`), Metadata: []byte(`{"error":{"type":"https://www.w3.org/ns/did#NOT_FOUND"}}`), ContentMetadata: []byte(`{}`)}
		}
		if i == 3 {
			v.Result = Result{HasContent: true, ContentKind: "document", ReturnedID: applicationDID, Metadata: []byte(`{"contentType":"application/did"}`), ContentMetadata: []byte(`{}`)}
		}
		out = append(out, v)
	}
	return out
}
func TestApplicationEvidenceBoundaries(t *testing.T) {
	if judgeApplication(applicationControls(), "unit")[0].Verdict != core.Pass || judgeApplication(nil, "unit")[0].Verdict != core.Error {
		t.Fatal("controls")
	}
	for _, change := range []func(*RoutingResult){
		func(v *RoutingResult) { v.Request.ApplicationHandler = "other" }, func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.Operation = "other" }, func(v *RoutingResult) { v.CaptureError = "lost" }, func(v *RoutingResult) { v.ResolveInputs = nil }, func(v *RoutingResult) { v.DriverInputs = nil }, func(v *RoutingResult) { v.Consumption = nil }, func(v *RoutingResult) { v.Options = []byte(`{`) }, func(v *RoutingResult) { v.ResolveOptions[0] = []byte(`{"other":true}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{`) }, func(v *RoutingResult) { v.Consumption[0].Error = "lost" }, func(v *RoutingResult) { v.Consumption[0].Model = nil }, func(v *RoutingResult) { v.ApplicationHandler = nil }, func(v *RoutingResult) { v.Result.Metadata = []byte(`[]`) }, func(v *RoutingResult) { v.Result.ContentMetadata = []byte(`{`) }, func(v *RoutingResult) { v.ApplicationHandler[0].Input.Role = "other" }, func(v *RoutingResult) { v.ApplicationHandler[0].Input.URL.Path = "other" }, func(v *RoutingResult) { v.ApplicationHandler[0].Handled = false }, func(v *RoutingResult) { v.ApplicationHandler[0].Returned.Raw = []byte(`{}`) }, func(v *RoutingResult) { v.Result.Raw = []byte(`{}`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{"error":{}}`) },
	} {
		values := applicationControls()
		change(&values[0])
		if judgeApplication(values, "unit")[0].Verdict != core.Error {
			t.Fatal(values[0])
		}
	}
	for _, change := range []func([]RoutingResult){func(v []RoutingResult) { v[1].ApplicationHandler[0].Returned.HasContent = true }, func(v []RoutingResult) { v[1].Result.HasContent = true }, func(v []RoutingResult) { v[2].Result.Metadata = []byte(`{}`) }, func(v []RoutingResult) { v[2].Result.Metadata = []byte(`{"error":{"type":"other"}}`) }, func(v []RoutingResult) { v[3].Result.HasContent = false }, func(v []RoutingResult) { v[3].ApplicationHandler = v[0].ApplicationHandler }} {
		v := applicationControls()
		change(v)
		if judgeApplication(v, "unit")[0].Verdict != core.Error {
			t.Fatal(v)
		}
	}
}

type applicationMock struct {
	noOperation
	calls, failAt int
}

func (s *applicationMock) InspectRouting(_ context.Context, _ RoutingRequest) (RoutingResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return RoutingResult{}, errors.New("lost")
	}
	return applicationControls()[s.calls-1], nil
}
func TestApplicationDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendApplicationCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendApplicationCase(&p)
	if len(p.Cases) != 1 {
		t.Fatal("case")
	}
	if e := p.Cases[0].Validate(); e != nil {
		t.Fatal(e)
	}
	for _, tt := range []struct {
		s    core.Subject
		want core.Verdict
	}{{&applicationMock{}, core.Pass}, {&applicationMock{failAt: 1}, core.Error}, {&applicationMock{failAt: 4}, core.Error}, {noOperation{}, core.Error}} {
		for _, o := range p.Cases[0].Run(t.Context(), tt.s) {
			if o.Verdict != tt.want || o.Input == "" || o.Observed == "" {
				t.Fatal(o)
			}
		}
	}
}
