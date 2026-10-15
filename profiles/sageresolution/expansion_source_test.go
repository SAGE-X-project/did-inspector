package sageresolution

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"testing"
)

func expansionSourceControls(t *testing.T) expansionSourceEvidence {
	v := sourceControl(t)
	v.Request = expansionSourceRequest()
	v.Diagnostics = []CodecResult{}
	files, _, e := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if e != nil {
		t.Fatal(e)
	}
	v.Files = sourcearith.SourceFiles(files, v.Request.Packages)
	out := expansionSourceEvidence{Source: v, Runtime: []RoutingResult{}}
	for _, f := range expansionSourceFixtures() {
		q := expansionSourceRouting(f)
		opts := map[string]any{"accept": "application/did"}
		enabled := q.Request.Options["expandRelativeUrls"] == true
		if enabled {
			opts["expandRelativeUrls"] = true
		}
		options, _ := json.Marshal(opts)
		doc := f.Expected
		if len(f.Paths) > 0 {
			value, _ := core.ParseJSON(doc)
			original, _ := core.ParseJSON(f.Document)
			for _, path := range f.Paths {
				*expansionNode(&value, path) = *expansionNode(&original, path)
			}
			doc, _ = json.Marshal(value)
		}
		raw := doc
		if enabled {
			var m map[string]json.RawMessage
			_ = json.Unmarshal(doc, &m)
			m["@context"] = json.RawMessage(`"https://www.w3.org/ns/did/v1.1"`)
			raw, _ = json.Marshal(m)
		}
		read, _ := json.Marshal(map[string]any{"ContentType": "application/did", "Data": base64.StdEncoding.EncodeToString(f.Document)})
		out.Runtime = append(out.Runtime, RoutingResult{Request: q, Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve", Options: options, ResolveInputs: []string{"did:example:123"}, ResolveOptions: [][]byte{options}, DriverInputs: []string{"did:example:123"}, DriverOptions: [][]byte{[]byte(`{"VersionID":"","VersionTime":null,"MediaType":"application/did","NoCache":false}`)}, DriverResults: [][]byte{read}, Consumption: []ConsumptionCapture{{Operation: pipelineConsumer, Input: f.Document, MediaType: "application/did", Require: "unknown", Expected: "unknown", Version: "1.1", Model: f.Document, Entries: []byte(`{}`)}}, DataModel: doc, Entries: []byte(`{}`), ResolvedDataModel: doc, ResolvedEntries: []byte(`{}`), ResolvedMetadata: []byte(`{"contentType":"application/did"}`), Result: Result{HasContent: true, ContentKind: "document", ReturnedID: "did:example:123", Raw: raw, Metadata: []byte(`{"contentType":"application/did"}`), ContentMetadata: []byte(`{}`)}})
	}
	return out
}
func TestExpansionSourceReceiptsAndIndependentVerdicts(t *testing.T) {
	e := expansionSourceControls(t)
	obs := judgeExpansionSource(t.Context(), e, "unit")
	if len(obs) != 2 || obs[0].Verdict != core.Pass || obs[1].Verdict != core.Fail {
		t.Fatal(obs[0].Verdict, obs[1].Verdict, obs[0].Observed)
	}
	var got expansionSourceEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &got) != nil {
		t.Fatal("capture")
	}
	for i := range expansionSourceIDs {
		a := got.Audit
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = !a.Steps[i].Correct
		want := core.Fail
		if i == 1 {
			want = core.Pass
		}
		if expansionSourceVerdict(a, i) != want {
			t.Fatal(i)
		}
		a.Steps[i].Kind = "unreviewed"
		if expansionSourceVerdict(a, i) != core.Error {
			t.Fatal("kind")
		}
	}
	for _, i := range []int{-1, 2} {
		if expansionSourceVerdict(got.Audit, i) != core.Error {
			t.Fatal("index")
		}
	}
	for _, mutate := range []func(*expansionSourceEvidence){func(e *expansionSourceEvidence) { e.Audit.Frames = nil }, func(e *expansionSourceEvidence) { e.Audit.Roles = nil }, func(e *expansionSourceEvidence) { e.Audit.CallPaths = nil }, func(e *expansionSourceEvidence) { e.Audit.Unknown = []string{"lost"} }} {
		a := got
		mutate(&a)
		if expansionSourceVerdict(a.Audit, 0) != core.Error {
			t.Fatal("missing audit")
		}
	}
	e = expansionSourceControls(t)
	e.Runtime[2].DataModel = expansionSourceFixtures()[2].Expected
	e.Runtime[2].ResolvedDataModel = e.Runtime[2].DataModel
	var m map[string]json.RawMessage
	_ = json.Unmarshal(e.Runtime[2].DataModel, &m)
	m["@context"] = json.RawMessage(`"https://www.w3.org/ns/did/v1.1"`)
	e.Runtime[2].Result.Raw, _ = json.Marshal(m)
	if o := judgeExpansionSource(t.Context(), e, "unit"); o[0].Verdict != core.Pass || o[1].Verdict != core.Error {
		t.Fatal("source/runtime contradiction", o)
	}
}
func TestExpansionSourceMissingEvidence(t *testing.T) {
	for _, mutate := range []func(*expansionSourceEvidence){func(e *expansionSourceEvidence) { e.Source.Version = "other" }, func(e *expansionSourceEvidence) { e.Source.Archive = nil }, func(e *expansionSourceEvidence) { delete(e.Source.Files, "resolver/expand.go") }, func(e *expansionSourceEvidence) { e.Source.Files["resolver/expand.go"] = []byte("changed") }, func(e *expansionSourceEvidence) { e.Runtime = nil }} {
		e := expansionSourceControls(t)
		mutate(&e)
		for _, o := range judgeExpansionSource(t.Context(), e, "unit") {
			if o.Verdict != core.Error {
				t.Fatal(o.Verdict)
			}
		}
	}
	e := expansionSourceControls(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, o := range judgeExpansionSource(ctx, e, "unit") {
		if o.Verdict != core.Error {
			t.Fatal(o)
		}
	}
}
func TestExpansionSourceRuntimeGuards(t *testing.T) {
	if good, _ := expansionSourceRuntime(nil); good {
		t.Fatal("missing")
	}
	for _, mutate := range []func(*RoutingResult){func(v *RoutingResult) { v.Request.Request.Input = "other" }, func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.DriverOptions[0] = []byte(`{}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{`) }, func(v *RoutingResult) { v.Consumption = nil }, func(v *RoutingResult) { v.Consumption[0].Model = []byte(`{}`) }, func(v *RoutingResult) { v.Consumption[0].CaptureError = "lost" }, func(v *RoutingResult) { v.Result.HasContent = false }, func(v *RoutingResult) { v.Result.Raw = []byte(`{`) }, func(v *RoutingResult) { v.Result.Raw = []byte(`[]`) }, func(v *RoutingResult) { v.Result.Raw = []byte(`{}`) }, func(v *RoutingResult) { v.DataModel = []byte(`{`) }, func(v *RoutingResult) { v.ResolvedDataModel = []byte(`{}`) }} {
		e := expansionSourceControls(t)
		mutate(&e.Runtime[2])
		if ok, _ := expansionSourceRuntime(e.Runtime); ok {
			t.Fatal("bad capture")
		}
	}
	for _, tc := range []struct {
		v    core.Value
		path []string
	}{{core.Null(), []string{"id"}}, {core.Object(), []string{"lost"}}, {core.Array(), []string{"bad"}}, {core.Array(), []string{"-1"}}, {core.Array(), []string{"0"}}} {
		if expansionNode(&tc.v, tc.path) != nil {
			t.Fatal("bad path")
		}
	}
}

type expansionSourceMock struct {
	noOperation
	e                       expansionSourceEvidence
	failSource, failRouting bool
}

func (s expansionSourceMock) InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error) {
	if s.failSource {
		return s.e.Source, errors.New("source lost")
	}
	return s.e.Source, nil
}
func (s expansionSourceMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	for _, v := range s.e.Runtime {
		if reflect.DeepEqual(q, v.Request) {
			if s.failRouting {
				return v, errors.New("routing lost")
			}
			return v, nil
		}
	}
	return RoutingResult{}, errors.New("unknown request")
}
func TestExpansionSourceDispatch(t *testing.T) {
	e := expansionSourceControls(t)
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendExpansionSourceCase(&p)
		if name != "did-1.1" {
			if len(p.Cases) != 0 {
				t.Fatal("wrong profile")
			}
			continue
		}
		for _, tc := range []struct {
			s core.Subject
			v core.Verdict
		}{{noOperation{}, core.NotSupported}, {expansionSourceMock{e: e}, core.Pass}, {expansionSourceMock{e: e, failSource: true}, core.Error}, {expansionSourceMock{e: e, failRouting: true}, core.Error}} {
			o := p.Cases[0].Run(t.Context(), tc.s)
			if len(o) != 2 || o[0].Verdict != tc.v {
				t.Fatal(o)
			}
			if tc.v == core.Error {
				var captured expansionSourceEvidence
				_ = json.Unmarshal([]byte(o[0].Observed), &captured)
				if captured.Error == "" {
					t.Fatal("lost error")
				}
			}
		}
	}
}
