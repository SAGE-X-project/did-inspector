package sageresolution

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"reflect"
	"testing"
)

func urlRoleControls(t *testing.T) urlRoleEvidence {
	v := sourceControl(t)
	v.Request = urlRoleRequest()
	v.Diagnostics = []CodecResult{}
	files, _, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	v.Files = sourcearith.SourceFiles(files, v.Request.Packages)
	e := urlRoleEvidence{Source: v, Handler: []RoutingResult{}, Retrieval: []RetrievalResult{}}
	fs := urlRoleFixtures()
	for _, f := range fs.Handlers {
		opts := []byte(`{"accept":"application/did"}`)
		nested := map[string]any{"accept": "application/did"}
		if f.Parts.HasQuery {
			nested["relativeRef"] = "next"
		}
		no, _ := json.Marshal(nested)
		read, _ := json.Marshal(map[string]any{"ContentType": "application/did", "Data": base64.StdEncoding.EncodeToString(f.Document)})
		result := Result{Raw: f.Content, ContentKind: f.Kind, ContentMetadata: []byte(`{}`)}
		if f.Error != "" {
			result.Metadata, _ = json.Marshal(map[string]any{"error": map[string]any{"type": f.Error}})
		} else {
			result.HasContent = true
			result.Metadata = []byte(`{"contentType":"application/ld+json"}`)
		}
		value := RoutingResult{Request: urlRoleRouting(f), Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: IntegerSourceModule + "/dereferencer.Dereferencer.Dereference", Options: opts, ResolveInputs: []string{"did:example:resources"}, ResolveOptions: [][]byte{no}, DriverInputs: []string{"did:example:resources"}, DriverOptions: [][]byte{[]byte(`{"VersionID":"","VersionTime":null,"MediaType":"application/did","NoCache":false}`)}, DriverResults: [][]byte{read}, DataModel: f.Document, Entries: []byte(`{}`), ResolvedDataModel: f.Document, ResolvedEntries: []byte(`{}`), ResolvedMetadata: []byte(`{"contentType":"application/did"}`), Consumption: []ConsumptionCapture{{Operation: pipelineConsumer, Input: f.Document, MediaType: "application/did", Require: "unknown", Expected: "unknown", Model: f.Document, Entries: []byte(`{}`)}}, Result: result}
		if f.Calls != 0 {
			value.ResourceHandler = []ResourceHandlerCapture{{Operation: IntegerSourceModule + "/dereferencer.ResourceHandler", Role: "literal passive resource handler; records actual values and returns unhandled", URL: f.Parts, Options: opts, Model: f.Document, Entries: []byte(`{}`), Metadata: []byte(`{"contentType":"application/did"}`)}}
		}
		e.Handler = append(e.Handler, value)
	}
	for _, f := range fs.Retrieval {
		parts := f.Parts
		v := RetrievalResult{Clock: 1800000000, Operation: IntegerSourceModule + "/relyingparty.RelyingParty.VerificationMethod", Reference: f.Request.Reference, Purpose: f.Request.Purpose, ParsedURL: &parts, Calls: []RetrievalCall{}}
		if f.Calls != 0 {
			snapshot, _ := json.Marshal(map[string]any{"id": f.Record.DID, "verificationMethod": []json.RawMessage{f.Method}, f.Request.Purpose: []string{f.Request.Reference}})
			v.Calls = []RetrievalCall{{Input: f.Parts.Primary, Options: []byte(`{}`), Result: Result{HasContent: true, ReturnedID: f.Record.DID, ContentKind: "document", Snapshot: snapshot}}}
		}
		if string(f.Method) == "null" {
			v.Error = "unchanged diagnostic"
		} else {
			v.Method = f.Method
		}
		e.Retrieval = append(e.Retrieval, v)
	}
	return e
}
func TestURLRolesIndependentVerdicts(t *testing.T) {
	e := urlRoleControls(t)
	obs := judgeURLRoles(t.Context(), e, "unit")
	if len(obs) != 2 || obs[0].Verdict != core.Fail || obs[1].Verdict != core.Pass {
		t.Fatal(obs[0].Verdict, obs[1].Verdict, obs[0].Observed)
	}
	var got urlRoleEvidence
	if json.Unmarshal([]byte(obs[0].Observed), &got) != nil {
		t.Fatal("capture")
	}
	for i := range urlRoleIDs {
		a := got.Audit
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = !a.Steps[i].Correct
		want := core.Pass
		if i == 1 {
			want = core.Fail
		}
		if urlRoleVerdict(a, i) != want {
			t.Fatal(i)
		}
		a.Steps[i].Kind = "other"
		if urlRoleVerdict(a, i) != core.Error {
			t.Fatal("kind")
		}
	}
	for _, i := range []int{-1, 2} {
		if urlRoleVerdict(got.Audit, i) != core.Error {
			t.Fatal(i)
		}
	}
	for _, mutate := range []func(*sourcearith.ServiceAudit){func(a *sourcearith.ServiceAudit) { a.Roots = nil }, func(a *sourcearith.ServiceAudit) { a.Frames = nil }, func(a *sourcearith.ServiceAudit) { a.Roles = nil }, func(a *sourcearith.ServiceAudit) { a.CallPaths = nil }, func(a *sourcearith.ServiceAudit) { a.Unknown = []string{"lost"} }} {
		a := got.Audit
		mutate(&a)
		if urlRoleVerdict(a, 0) != core.Error {
			t.Fatal(a)
		}
	}
	for _, tc := range []struct {
		change func(*urlRoleEvidence)
		want   []core.Verdict
	}{
		{func(e *urlRoleEvidence) { e.Handler = nil }, []core.Verdict{core.Error, core.Pass}},
		{func(e *urlRoleEvidence) { e.Retrieval = nil }, []core.Verdict{core.Fail, core.Error}},
		{func(e *urlRoleEvidence) { e.HandlerErrors = []string{"lost"} }, []core.Verdict{core.Error, core.Pass}},
		{func(e *urlRoleEvidence) { e.RetrievalErrors = []string{"lost"} }, []core.Verdict{core.Fail, core.Error}},
		{func(e *urlRoleEvidence) {
			for i, f := range urlRoleFixtures().Handlers {
				if f.Calls != 0 {
					e.Handler[i].ResourceHandler[0].URL = f.Adjusted
				}
			}
		}, []core.Verdict{core.Error, core.Pass}},
	} {
		e := urlRoleControls(t)
		tc.change(&e)
		o := judgeURLRoles(t.Context(), e, "unit")
		for i, v := range tc.want {
			if o[i].Verdict != v {
				t.Fatal(i, o[i].Verdict, v)
			}
		}
	}
	// Parser diagnostics are retained, not used as an RP output/refusal oracle.
	e = urlRoleControls(t)
	for i := 2; i < len(e.Retrieval); i++ {
		e.Retrieval[i].Error = ""
		e.Retrieval[i].Method = []byte(`{"diagnostic":"different downstream output"}`)
		e.Retrieval[i].Calls = nil
	}
	if o := judgeURLRoles(t.Context(), e, "unit"); o[0].Verdict != core.Fail || o[1].Verdict != core.Pass {
		t.Fatal("diagnostic leakage", o[0].Verdict, o[1].Verdict)
	}
}
func TestURLRolesMissingSource(t *testing.T) {
	for _, mutate := range []func(*urlRoleEvidence){func(e *urlRoleEvidence) { e.Error = "source failed" }, func(e *urlRoleEvidence) { e.Source.Version = "other" }, func(e *urlRoleEvidence) { e.Source.Archive = nil }, func(e *urlRoleEvidence) { delete(e.Source.Files, "relyingparty/relyingparty.go") }, func(e *urlRoleEvidence) { e.Source.Files["relyingparty/relyingparty.go"] = []byte("different") }} {
		e := urlRoleControls(t)
		mutate(&e)
		for _, o := range judgeURLRoles(t.Context(), e, "unit") {
			if o.Verdict != core.Error {
				t.Fatal(o.Verdict)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, o := range judgeURLRoles(ctx, urlRoleControls(t), "unit") {
		if o.Verdict != core.Error {
			t.Fatal(o.Verdict)
		}
	}
}
func TestURLHandlerReceiptGuards(t *testing.T) {
	if ok, _ := urlHandlerRuntime(nil); ok {
		t.Fatal("missing")
	}
	for _, change := range []func(*RoutingResult){
		func(v *RoutingResult) { v.Request.Request.Input = "other" }, func(v *RoutingResult) { v.Role = "other" }, func(v *RoutingResult) { v.ResourceHandler = nil }, func(v *RoutingResult) { v.Options = []byte(`{}`) }, func(v *RoutingResult) { v.ResolveOptions[0] = []byte(`{}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{`) }, func(v *RoutingResult) { v.Consumption[0].Input = nil }, func(v *RoutingResult) { v.ResourceHandler[0].Operation = "other" }, func(v *RoutingResult) { v.ResourceHandler[0].URL.Fragment = "other" }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.HasContent = true }, func(v *RoutingResult) { v.Result.ContentMetadata = []byte(`{`) }, func(v *RoutingResult) { v.Result.Raw = []byte(`{`) },
	} {
		e := urlRoleControls(t)
		change(&e.Handler[1])
		if ok, _ := urlHandlerRuntime(e.Handler); ok {
			t.Fatal("changed evidence accepted")
		}
	}
	e := urlRoleControls(t)
	e.Handler[6].Result.Raw = []byte(`{}`)
	if ok, _ := urlHandlerRuntime(e.Handler); ok {
		t.Fatal("document control")
	}
}
func TestURLRetrievalReceiptGuards(t *testing.T) {
	if urlRetrievalRuntime(nil) {
		t.Fatal("missing")
	}
	for _, change := range []func(*RetrievalResult){
		func(v *RetrievalResult) { v.ParsedURL = nil }, func(v *RetrievalResult) { v.ParsedURL.Fragment = "wrong" }, func(v *RetrievalResult) { v.Calls[0].Input = "other" }, func(v *RetrievalResult) { v.Calls[0].Options = []byte(`{`) }, func(v *RetrievalResult) { v.Calls = nil }, func(v *RetrievalResult) { v.Error = "lost" }, func(v *RetrievalResult) { v.Calls[0].Result.HasContent = false }, func(v *RetrievalResult) { v.Calls[0].Result.Snapshot = []byte(`{`) }, func(v *RetrievalResult) {
			v.Calls[0].Result.Snapshot = []byte(`{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[],"authentication":[]}`)
		},
	} {
		e := urlRoleControls(t)
		change(&e.Retrieval[0])
		if urlRetrievalRuntime(e.Retrieval) {
			t.Fatal("changed evidence accepted")
		}
	}
}

type urlRoleMock struct {
	noOperation
	e                                      urlRoleEvidence
	failSource, failHandler, failRetrieval bool
}

func (s urlRoleMock) InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error) {
	if s.failSource {
		return s.e.Source, errors.New("source lost")
	}
	return s.e.Source, nil
}
func (s urlRoleMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	for _, v := range s.e.Handler {
		if reflect.DeepEqual(q, v.Request) {
			if s.failHandler {
				return v, errors.New("handler lost")
			}
			return v, nil
		}
	}
	return RoutingResult{}, errors.New("unknown")
}
func (s urlRoleMock) InspectRetrieval(_ context.Context, _ sageprojection.Record, q RetrievalRequest) (RetrievalResult, error) {
	for i, f := range urlRoleFixtures().Retrieval {
		if reflect.DeepEqual(q, f.Request) {
			if s.failRetrieval {
				return s.e.Retrieval[i], errors.New("retrieval lost")
			}
			return s.e.Retrieval[i], nil
		}
	}
	return RetrievalResult{}, errors.New("unknown")
}
func TestURLRolesProfileDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendURLRolesCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendURLRolesCase(&p)
	for _, tc := range []struct {
		s    core.Subject
		want []core.Verdict
	}{
		{noOperation{}, []core.Verdict{core.NotSupported, core.NotSupported}},
		{urlRoleMock{e: urlRoleControls(t)}, []core.Verdict{core.Fail, core.Pass}},
		{urlRoleMock{e: urlRoleControls(t), failSource: true}, []core.Verdict{core.Error, core.Error}},
		{urlRoleMock{e: urlRoleControls(t), failHandler: true}, []core.Verdict{core.Error, core.Pass}},
		{urlRoleMock{e: urlRoleControls(t), failRetrieval: true}, []core.Verdict{core.Fail, core.Error}},
	} {
		o := p.Cases[0].Run(t.Context(), tc.s)
		if len(o) != 2 {
			t.Fatal(len(o))
		}
		for i, want := range tc.want {
			if o[i].Verdict != want {
				t.Fatal(i, o[i].Verdict, want)
			}
		}
	}
}
