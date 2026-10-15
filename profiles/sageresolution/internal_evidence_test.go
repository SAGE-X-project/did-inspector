package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"runtime"
	"testing"
)

func capacityControl(t *testing.T) capacityEvidence {
	s := multihashControls(t).Source
	e := capacityEvidence{Source: s, Calls: []CapacityResult{}, Compiler: runtime.Version(), Architecture: runtime.GOARCH}
	for _, f := range capacityFixtures() {
		op := "EncodeMultibase"
		if f.Request.Operation == "decode" {
			op = "DecodeMultibase"
		}
		e.Calls = append(e.Calls, CapacityResult{Request: f.Request, Observer: ComponentObserver{Module: ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", Compiler: "go1.26.8"}, Operation: IntegerSourceModule + "/internal/multiformats." + op, Role: MultihashRole, Encoded: f.Encoded, Header: 'u', Data: f.Data})
	}
	return e
}
func injectionControl() TypedProductionResult {
	q := contextInjectionRequest()
	return TypedProductionResult{ID: q.ID, Controllers: q.Controllers, ControllerShape: "set", Fields: []TypedMember{}, Entries: []TypedMember{}, Calls: []ProductionCapture{{Operation: pipelineProducer, Version: "1.1", JSONLD: true, Model: []byte(injectionModel), Entries: []byte(`{}`), Output: []byte(injectionWire), MediaType: "application/did"}}}
}
func mediaControl(t *testing.T) fragmentMediaEvidence {
	s := sourceControl(t)
	s.Request = fragmentSourceRequest()
	s.Diagnostics = nil
	files, _, err := sourcearith.ArchiveFiles(s.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	s.Files = sourcearith.SourceFiles(files, s.Request.Packages)
	e := fragmentMediaEvidence{Source: s, Runtime: []RoutingResult{}}
	var f struct {
		Method json.RawMessage `json:"method"`
	}
	_ = json.Unmarshal(fragmentMediaBytes, &f)
	for i, q := range fragmentMediaRequests() {
		opts := []byte(`{"accept":"application/did+json","verificationRelationship":"authentication"}`)
		empty := []byte(`{}`)
		driver, _ := json.Marshal(struct {
			Data        []byte
			ContentType string
			Metadata    map[string]any
		}{q.Document.Data, "application/did+json", map[string]any{}})
		result := Result{HasContent: true, ReturnedID: "did:example:resources#sign", ContentKind: "verification-method", Raw: f.Method, Snapshot: f.Method, ContentMetadata: empty, Metadata: []byte(`{"contentType":"application/json"}`)}
		if i == 1 {
			result = Result{Raw: []byte(`null`), ContentMetadata: empty, Metadata: []byte(`{"error":{"type":"https://w3id.org/security#INVALID_VERIFICATION_METHOD"}}`)}
		}
		e.Runtime = append(e.Runtime, RoutingResult{Request: q, Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: IntegerSourceModule + "/dereferencer.Dereferencer.Dereference", Options: opts, ResolveInputs: []string{"did:example:resources"}, DriverInputs: []string{"did:example:resources"}, ResolveOptions: [][]byte{opts}, DriverOptions: [][]byte{[]byte(`{"VersionID":"","VersionTime":null,"MediaType":"application/did+json","NoCache":false}`)}, DriverResults: [][]byte{driver}, DataModel: q.Document.Data, ResolvedDataModel: q.Document.Data, Entries: empty, ResolvedEntries: empty, ResolvedMetadata: []byte(`{"contentType":"application/did+json"}`), Consumption: []ConsumptionCapture{{Operation: pipelineConsumer, Input: q.Document.Data, MediaType: "application/did+json", Require: "unknown", Expected: "unknown", Version: "1.0", Model: q.Document.Data, Entries: empty}}, Result: result})
	}
	return e
}
func TestCapacityIndependentSourceAndCalls(t *testing.T) {
	e := capacityControl(t)
	for _, o := range judgeCapacity(t.Context(), e, "unit") {
		if o.Verdict != core.Pass {
			t.Fatal(o.Verdict)
		}
	}
	for i, f := range capacityFixtures() {
		v := e.Calls[i]
		if capacityCallVerdict(f, v) != core.Pass {
			t.Fatal(f.Name)
		}
		v.Error = "rejected"
		if capacityCallVerdict(f, v) != core.Error {
			t.Fatal("call error")
		}
		v = e.Calls[i]
		v.Role = "other"
		if capacityCallVerdict(f, v) != core.Error {
			t.Fatal("role")
		}
		v = e.Calls[i]
		v.Data = nil
		v.Encoded = "other"
		if f.Request.Operation == "decode" && len(f.Data) == 0 {
			v.Header = 'z'
		}
		if capacityCallVerdict(f, v) != core.Error {
			t.Fatal("output corroboration", f.Name)
		}
	}
	var audit sourcearith.CapacityAudit
	_ = json.Unmarshal(capacityWitness, &audit)
	for _, i := range []int{-1, 0, 1, 2} {
		a := audit
		if i < 0 || i > 1 {
			if capacityAuditVerdict(a, i) != core.Error {
				t.Fatal("index")
			}
			continue
		}
		a.Steps = append([]sourcearith.StateStep(nil), a.Steps...)
		a.Steps[i].Correct = false
		if capacityAuditVerdict(a, i) != core.Error {
			t.Fatal("alternative formula is not normative FAIL")
		}
	}
	for _, change := range []func(*capacityEvidence){func(e *capacityEvidence) { e.Source.Replaced = true }, func(e *capacityEvidence) { e.Calls = nil }, func(e *capacityEvidence) { e.Calls[0].Role = "other" }, func(e *capacityEvidence) { e.Error = "missing" }} {
		e := capacityControl(t)
		change(&e)
		for _, o := range judgeCapacity(t.Context(), e, "unit") {
			if o.Verdict != core.Error {
				t.Fatal(o.Verdict)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeCapacity(ctx, e, "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}
func TestContextInjectionSameCallAndIndependentDeclarations(t *testing.T) {
	v := injectionControl()
	if judgeContextInjection(t.Context(), v, "unit")[0].Verdict != core.Pass {
		t.Fatal("control")
	}
	for _, change := range []func(*TypedProductionResult){func(v *TypedProductionResult) { v.BuildError = "missing" }, func(v *TypedProductionResult) { v.Entries = []TypedMember{{Name: "@context"}} }, func(v *TypedProductionResult) { v.Calls = nil }, func(v *TypedProductionResult) { v.Calls[0].Version = "1.0" }, func(v *TypedProductionResult) { v.Calls[0].Model = []byte(`{}`) }, func(v *TypedProductionResult) { v.Calls[0].Entries = []byte(`{"@context":"other"}`) }, func(v *TypedProductionResult) { v.Calls[0].Error = "refused" }, func(v *TypedProductionResult) { v.Calls[0].MediaType = "application/json" }} {
		v := injectionControl()
		change(&v)
		if judgeContextInjection(t.Context(), v, "unit")[0].Verdict != core.Error {
			t.Fatal("provenance")
		}
	}
	for _, tt := range []struct {
		data string
		want core.Verdict
	}{{injectionModel, core.Fail}, {`{`, core.Fail}, {`{"id":"did:sage:web:registry.example:agent-1","@context":"https://other.example/"}`, core.NotSupported}} {
		v := injectionControl()
		v.Calls[0].Output = []byte(tt.data)
		if got := judgeContextInjection(t.Context(), v, "unit")[0].Verdict; got != tt.want {
			t.Fatal(got, tt.want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeContextInjection(ctx, injectionControl(), "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}
func TestPlainJSONFragmentIndependentMediaBoundary(t *testing.T) {
	e := mediaControl(t)
	if judgeFragmentMedia(t.Context(), e, "unit")[0].Verdict != core.Pass {
		t.Fatal("actual selected source and literal control")
	}
	for _, change := range []func(*RoutingResult){func(v *RoutingResult) { v.Request.PlainJSONFragment = false }, func(v *RoutingResult) { v.CaptureError = "lost" }, func(v *RoutingResult) { v.DriverInputs = nil }, func(v *RoutingResult) { v.Options = []byte(`{}`) }, func(v *RoutingResult) { v.DriverResults[0] = []byte(`{}`) }, func(v *RoutingResult) { v.Consumption[0].Version = "1.1" }, func(v *RoutingResult) { v.Consumption[0].JSONLD = true }, func(v *RoutingResult) { v.DataModel = []byte(`{}`) }, func(v *RoutingResult) { v.ResolvedEntries = []byte(`{"@context":"other"}`) }, func(v *RoutingResult) { v.ResolvedMetadata = []byte(`{"contentType":"application/did"}`) }, func(v *RoutingResult) { v.Result.Raw = []byte(`{}`) }, func(v *RoutingResult) { v.Result.Metadata = []byte(`{"contentType":"application/ld+json"}`) }} {
		e := mediaControl(t)
		q := e.Runtime[0].Request
		change(&e.Runtime[0])
		if fragmentMediaVerdict(q, e.Runtime[0], true) != core.Error {
			t.Fatal("misattributed media/selection")
		}
	}
	e = mediaControl(t)
	e.Runtime[1].Result.HasContent = true
	if fragmentMediaVerdict(e.Runtime[1].Request, e.Runtime[1], false) != core.Error {
		t.Fatal("missing control")
	}
	for _, change := range []func(*IntegerSourceResult){func(v *IntegerSourceResult) { v.Replaced = true }, func(v *IntegerSourceResult) { v.Archive = nil }, func(v *IntegerSourceResult) { v.Files = nil }, func(v *IntegerSourceResult) { v.Files["dereferencer/fragment.go"] = []byte("changed") }} {
		s := mediaControl(t).Source
		change(&s)
		if _, ready := fragmentMediaSourceReady(t.Context(), s); ready {
			t.Fatal("source provenance")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if judgeFragmentMedia(ctx, mediaControl(t), "unit")[0].Verdict != core.Error {
		t.Fatal("cancel")
	}
}

type internalEvidenceMock struct {
	noOperation
	capacity               capacityEvidence
	media                  fragmentMediaEvidence
	injection              TypedProductionResult
	sourceError, callError bool
}

func (s internalEvidenceMock) InspectIntegerSource(_ context.Context, q IntegerSourceRequest) (IntegerSourceResult, error) {
	v := s.capacity.Source
	if reflect.DeepEqual(q, fragmentSourceRequest()) {
		v = s.media.Source
	}
	if s.sourceError {
		return v, errors.New("lost source")
	}
	return v, nil
}
func (s internalEvidenceMock) InspectCapacity(_ context.Context, q CapacityRequest) (CapacityResult, error) {
	for _, v := range s.capacity.Calls {
		if reflect.DeepEqual(q, v.Request) {
			if s.callError {
				return v, errors.New("lost call")
			}
			return v, nil
		}
	}
	return CapacityResult{}, errors.New("unknown")
}
func (s internalEvidenceMock) InspectRouting(_ context.Context, q RoutingRequest) (RoutingResult, error) {
	for _, v := range s.media.Runtime {
		if reflect.DeepEqual(q, v.Request) {
			if s.callError {
				return v, errors.New("lost call")
			}
			return v, nil
		}
	}
	return RoutingResult{}, errors.New("unknown")
}
func (s internalEvidenceMock) InspectTypedProduction(context.Context, TypedProductionRequest) (TypedProductionResult, error) {
	if s.callError {
		return s.injection, errors.New("lost call")
	}
	return s.injection, nil
}
func TestInternalEvidenceCaseBoundaries(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendCapacityCase(&p)
	appendContextInjectionCase(&p)
	appendFragmentMediaCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("scope")
	}
	p.Name = "did-1.1"
	appendCapacityCase(&p)
	appendContextInjectionCase(&p)
	appendFragmentMediaCase(&p)
	good := internalEvidenceMock{capacity: capacityControl(t), media: mediaControl(t), injection: injectionControl()}
	sourceError := good
	sourceError.sourceError = true
	callError := good
	callError.callError = true
	for _, c := range p.Cases {
		for _, tt := range []struct {
			s    core.Subject
			want core.Verdict
		}{{noOperation{}, core.NotSupported}, {good, core.Pass}, {callError, core.Error}, {sourceError, core.Error}} {
			want := tt.want
			if c.ID == contextInjectionCase && tt.s == nil {
				continue
			}
			if c.ID == contextInjectionCase && tt.want == core.Error && reflect.DeepEqual(tt.s, sourceError) {
				want = core.Pass
			}
			for _, o := range c.Run(t.Context(), tt.s) {
				if o.Verdict != want {
					t.Fatal(c.ID, o.Verdict, want)
				}
			}
		}
	}
}

func TestKnownInvalidInjectedContextIsFail(t *testing.T) {
	for _, raw := range []string{`false`, `true`, `4`, `null`, `""`, `{}`, `[]`, `[false]`, `[""]`} {
		v := injectionControl()
		v.Calls[0].Output = []byte(`{"id":"did:sage:web:registry.example:agent-1","@context":` + raw + `}`)
		if judgeContextInjection(t.Context(), v, "unit")[0].Verdict != core.Fail {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{`"https://context.example/"`, `{"term":"https://term.example/"}`, `["https://context.example/",{}]`} {
		v, _ := core.ParseJSON([]byte(raw))
		if injectionContextVerdict(v) != core.NotSupported {
			t.Fatal(raw)
		}
	}
}

func TestFragmentMediaRejectsInvalidProofDescriptors(t *testing.T) {
	source := mediaControl(t).Source
	originalRelationship := relationshipWitnessBytes
	originalMedia := fragmentMediaWitness
	defer func() { relationshipWitnessBytes = originalRelationship; fragmentMediaWitness = originalMedia }()
	relationshipWitnessBytes = []byte(`{`)
	if _, ready := fragmentMediaSourceReady(t.Context(), source); ready {
		t.Fatal("invalid relationship proof accepted")
	}
	relationshipWitnessBytes = originalRelationship
	fragmentMediaWitness = []byte(`{`)
	if _, ready := fragmentMediaSourceReady(t.Context(), source); ready {
		t.Fatal("invalid media proof accepted")
	}
	fragmentMediaWitness = originalMedia
	if _, ready := fragmentMediaSourceReady(t.Context(), source); !ready {
		t.Fatal("descriptor restoration")
	}
}
