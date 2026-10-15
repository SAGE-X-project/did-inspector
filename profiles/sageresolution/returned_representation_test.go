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

func returnedRepresentationControls(t *testing.T) returnedRepresentationEvidence {
	t.Helper()
	source := sourceControl(t)
	source.Request = returnedRepresentationSourceRequest()
	source.Diagnostics = nil
	files, _, err := sourcearith.ArchiveFiles(source.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	source.Files = sourcearith.SourceFiles(files, source.Request.Packages)
	e := returnedRepresentationEvidence{Source: source, Runtime: []RoutingResult{}}
	for _, q := range returnedRepresentationRequests() {
		model, empty, opts, md := []byte(`{"id":"did:example:123"}`), []byte(`{}`), []byte(`{"accept":"application/did+json"}`), []byte(`{"contentType":"application/did+json"}`)
		driver, _ := json.Marshal(struct {
			Data        []byte
			ContentType string
			Metadata    map[string]any
		}{q.Document.Data, "application/did", map[string]any{}})
		v := RoutingResult{Request: q, Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: IntegerSourceModule + "/resolver.DefaultResolver.Resolve", Options: opts, ResolveInputs: []string{"did:example:123"}, DriverInputs: []string{"did:example:123"}, ResolveOptions: [][]byte{opts}, DriverOptions: [][]byte{[]byte(`{"VersionID":"","VersionTime":null,"MediaType":"","NoCache":false}`)}, DriverResults: [][]byte{driver}, DataModel: model, Entries: empty, ResolvedDataModel: model, ResolvedEntries: empty, ResolvedMetadata: md,
			Consumption: []ConsumptionCapture{{Operation: pipelineConsumer, Input: q.Document.Data, MediaType: "application/did", Require: "unknown", Expected: "unknown", Version: "1.1", Model: model, Entries: empty}},
			Production:  []ProductionCapture{{Operation: "github.com/sage-x-project/did-go/producer.Producer.Produce", Version: "1.0", Model: model, Entries: empty, Output: model, MediaType: "application/did+json"}},
			Result:      Result{Metadata: md, ContentMetadata: empty, HasContent: true, ReturnedID: "did:example:123", ContentKind: "document", Snapshot: model, Raw: model}}
		e.Runtime = append(e.Runtime, v)
	}
	return e
}
func TestReturnedRepresentationCompleteMinimalClass(t *testing.T) {
	for _, tc := range []struct {
		data string
		want core.Verdict
	}{{`{"id":"did:example:123"}`, core.Pass}, {" {\n\"id\":\"did:example:123\" } ", core.Pass}, {`{`, core.Fail}, {`[]`, core.Fail}, {`{}`, core.Fail}, {`{"id":7}`, core.Fail}, {`{"id":"relative"}`, core.Fail}, {`{"id":"did:example:other"}`, core.Error}, {`{"id":"did:example:123","controller":"did:example:123"}`, core.NotSupported}, {`{"id":"did:example:123","id":"did:example:123"}`, core.NotSupported}, {`{"id":"did:example:123"} null`, core.Fail}} {
		if got := returnedRepresentationJSON([]byte(tc.data)); got != tc.want {
			t.Fatal(tc.data, got, tc.want)
		}
	}
	e := returnedRepresentationControls(t)
	if o := judgeReturnedRepresentation(t.Context(), e, "unit"); len(o) != 1 || o[0].Verdict != core.Pass {
		t.Fatal(o)
	}
	for _, raw := range []string{`{`, `[]`, `{}`, `{"id":7}`, `{"id":"relative"}`} {
		v := returnedRepresentationControls(t).Runtime[0]
		v.Result.Raw = []byte(raw)
		v.Production[0].Output = v.Result.Raw
		if got := returnedRepresentationVerdict(v.Request, v); got != core.Fail {
			t.Fatal(raw, got)
		}
	}
	for _, raw := range []string{`{"id":"did:example:123","extra":true}`, `{"id":"did:example:123","id":"did:example:123"}`} {
		v := returnedRepresentationControls(t).Runtime[0]
		v.Result.Raw = []byte(raw)
		v.Production[0].Output = v.Result.Raw
		if got := returnedRepresentationVerdict(v.Request, v); got != core.NotSupported {
			t.Fatal(raw, got)
		}
	}
}
func TestReturnedRepresentationAttributionBoundaries(t *testing.T) {
	changes := []func(*RoutingResult){
		func(v *RoutingResult) { v.Request.ObserveProduction = false }, func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.Consumption = nil }, func(v *RoutingResult) { v.Production = nil }, func(v *RoutingResult) { v.Result.HasContent = false }, func(v *RoutingResult) { v.CaptureError = "lost" },
		func(v *RoutingResult) { v.ResolveInputs = nil }, func(v *RoutingResult) { v.Options = []byte(`{}`) }, func(v *RoutingResult) { v.ResolveOptions[0] = []byte(`{}`) }, func(v *RoutingResult) { v.DriverOptions[0] = []byte(`{}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{`) },
		func(v *RoutingResult) { v.Consumption[0].Version = "1.0" }, func(v *RoutingResult) { v.Consumption[0].Input = nil }, func(v *RoutingResult) { v.Production[0].Version = "1.1" }, func(v *RoutingResult) { v.Production[0].Error = "lost" },
		func(v *RoutingResult) { v.DataModel = []byte(`{}`) }, func(v *RoutingResult) { v.Entries = []byte(`{"extra":1}`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{`) }, func(v *RoutingResult) { v.ResolvedMetadata = []byte(`{}`) }, func(v *RoutingResult) { v.Production[0].Output = nil },
		func(v *RoutingResult) {
			v.Result.Metadata = []byte(`{"contentType":"application/did+json","error":{}}`)
			v.ResolvedMetadata = v.Result.Metadata
		},
	}
	for i, change := range changes {
		v := returnedRepresentationControls(t).Runtime[0]
		q := v.Request
		change(&v)
		if got := returnedRepresentationVerdict(q, v); got != core.Error {
			t.Fatal(i, got)
		}
	}
	v := returnedRepresentationControls(t).Runtime[0]
	v.Result.Metadata = []byte(`{"contentType":"application/did"}`)
	v.ResolvedMetadata = v.Result.Metadata
	v.Production[0].MediaType = "application/did"
	if got := returnedRepresentationVerdict(v.Request, v); got != core.NotSupported {
		t.Fatal(got)
	}
}
func TestReturnedRepresentationSourceAndCaseBoundaries(t *testing.T) {
	for _, change := range []func(*returnedRepresentationEvidence){func(e *returnedRepresentationEvidence) { e.Source.Replaced = true }, func(e *returnedRepresentationEvidence) { e.Source.Archive = nil }, func(e *returnedRepresentationEvidence) { e.Source.Files = nil }, func(e *returnedRepresentationEvidence) { e.Source.Files["resolver/resolver.go"] = []byte("different") }, func(e *returnedRepresentationEvidence) { e.Runtime = nil }} {
		e := returnedRepresentationControls(t)
		change(&e)
		if o := judgeReturnedRepresentation(t.Context(), e, "unit"); o[0].Verdict != core.Error {
			t.Fatal(o)
		}
	}
	e := returnedRepresentationControls(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeReturnedRepresentation(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancellation")
	}
	p := core.Profile{Name: "did-core-1.0"}
	appendReturnedRepresentationCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("scope")
	}
	p.Name = "did-1.1"
	appendReturnedRepresentationCase(&p)
	if p.Cases[0].Run(t.Context(), noOperation{})[0].Verdict != core.NotSupported {
		t.Fatal("unsupported")
	}
	for _, tc := range []struct {
		s    returnedRepresentationMock
		want core.Verdict
	}{{returnedRepresentationMock{e: e}, core.Pass}, {returnedRepresentationMock{e: e, sourceError: true}, core.Error}, {returnedRepresentationMock{e: e, callError: true}, core.Error}} {
		if o := p.Cases[0].Run(t.Context(), tc.s); o[0].Verdict != tc.want {
			t.Fatal(o)
		}
	}
}

type returnedRepresentationMock struct {
	noOperation
	e                      returnedRepresentationEvidence
	sourceError, callError bool
}

func (s returnedRepresentationMock) InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error) {
	if s.sourceError {
		return s.e.Source, errors.New("source lost")
	}
	return s.e.Source, nil
}
func (s returnedRepresentationMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	for _, v := range s.e.Runtime {
		if reflect.DeepEqual(v.Request, q) {
			if s.callError {
				return v, errors.New("call lost")
			}
			return v, nil
		}
	}
	return RoutingResult{}, errors.New("unknown input")
}
