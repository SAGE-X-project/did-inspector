package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func cachedContextControl() BaseContextResult {
	return BaseContextResult{Operation: "github.com/sage-x-project/did-go/jsonld.BaseContext", Version: "1.1", URL: did11Context, Data: append([]byte{}, independentDIDContext...)}
}
func undefinedConsumerControl() ConsumptionCapture {
	q := unknownConsumerFixture()
	return ConsumptionCapture{Operation: pipelineConsumer, Input: q.Data, MediaType: q.MediaType, Require: "unknown", Expected: "unknown", Version: "1.1", JSONLD: true, DroppedTerms: []string{unusedTerm}, Model: []byte(`{"id":"did:sage:web:registry.example:agent-1"}`), Entries: []byte(`{"@context":"` + did11Context + `"}`)}
}
func undefinedProducerControl() producerContextPair {
	good, bad := unknownProducerFixtures()
	makeCall := func(q TypedProductionRequest) TypedProductionResult {
		model, _ := typedExpected(q, false, false)
		data, _ := model.MarshalJSON()
		output, _ := typedExpected(q, true, true)
		wire, _ := output.MarshalJSON()
		return TypedProductionResult{ID: q.ID, Controllers: q.Controllers, ControllerShape: "set", Fields: q.Fields, Entries: q.Entries, Calls: []ProductionCapture{{Operation: pipelineProducer, Model: data, Entries: []byte(`{}`), Version: "1.1", JSONLD: true, Output: wire, MediaType: "application/did"}}}
	}
	return producerContextPair{makeCall(good), makeCall(bad)}
}
func TestIndependentContextAndCache(t *testing.T) {
	if !contextOracleReady() || judgeBaseContext(cachedContextControl(), "input").Verdict != core.Pass {
		t.Fatal("context oracle")
	}
	for _, change := range []func(*BaseContextResult){func(r *BaseContextResult) { r.Operation = "other" }, func(r *BaseContextResult) { r.Version = "1.0" }, func(r *BaseContextResult) { r.URL = "other" }, func(r *BaseContextResult) { r.Error = "missing" }, func(r *BaseContextResult) { r.Data = append(r.Data, ' ') }} {
		r := cachedContextControl()
		change(&r)
		if judgeBaseContext(r, "input").Verdict == core.Pass {
			t.Fatal("bad cache PASS")
		}
	}
	original := independentDIDContext
	independentDIDContext = []byte("{}")
	if contextOracleReady() {
		t.Fatal("unpinned oracle")
	}
	independentDIDContext = original
}
func TestUnknownTermConsumer(t *testing.T) {
	q := unknownConsumerFixture()
	if judgeUnknownConsumer(q, undefinedConsumerControl(), "input").Verdict != core.Pass {
		t.Fatal("consumer")
	}
	for _, change := range []func(*ConsumptionCapture){func(r *ConsumptionCapture) { r.Operation = "other" }, func(r *ConsumptionCapture) { r.Input = []byte(`{}`) }, func(r *ConsumptionCapture) { r.Error = "refused" }, func(r *ConsumptionCapture) { r.CaptureError = "lost" }, func(r *ConsumptionCapture) { r.Version = "1.0" }, func(r *ConsumptionCapture) { r.JSONLD = false }, func(r *ConsumptionCapture) { r.DroppedTerms = nil }, func(r *ConsumptionCapture) {
		r.Model = []byte(`{"id":"did:sage:web:registry.example:agent-1","inspectionNote":"retained"}`)
	}, func(r *ConsumptionCapture) { r.Entries = []byte(`{}`) }} {
		r := undefinedConsumerControl()
		change(&r)
		if judgeUnknownConsumer(q, r, "input").Verdict == core.Pass {
			t.Fatal("undefined term retained")
		}
	}
}
func TestUnknownTermDefaultProducerFindingAndAlternatives(t *testing.T) {
	pair := undefinedProducerControl()
	if judgeUnknownProducer(pair, "input").Verdict != core.Fail {
		t.Fatal("recommendation hidden")
	}
	pair.Negative.Calls[0].Error = "refusal"
	pair.Negative.Calls[0].Output = nil
	if judgeUnknownProducer(pair, "input").Verdict != core.Pass {
		t.Fatal("refusal")
	}
	pair = undefinedProducerControl()
	pair.Negative.Calls[0].Output = pair.Positive.Calls[0].Output
	if judgeUnknownProducer(pair, "input").Verdict != core.Pass {
		t.Fatal("removal")
	}
	for _, tt := range []struct {
		change func(*producerContextPair)
		want   core.Verdict
	}{
		{func(r *producerContextPair) { r.Positive.Calls = nil }, core.Error}, {func(r *producerContextPair) { r.Negative.Calls = nil }, core.Error}, {func(r *producerContextPair) { r.Positive.Calls[0].Error = "reject all" }, core.Error},
		{func(r *producerContextPair) { r.Negative.Calls[0].Error = "partial" }, core.Error}, {func(r *producerContextPair) { r.Negative.Calls[0].MediaType = "text/html" }, core.Error},
		{func(r *producerContextPair) { r.Negative.Calls[0].Output = []byte(`{`) }, core.Fail}, {func(r *producerContextPair) {
			r.Negative.Calls[0].Output = []byte(`{"id":"did:sage:web:registry.example:agent-1"}`)
		}, core.Fail},
		{func(r *producerContextPair) {
			r.Negative.Calls[0].Output = []byte(`{"@context":["` + did11Context + `",{"inspectionNote":"https://agent.example/term"}],"id":"did:sage:web:registry.example:agent-1","inspectionNote":"public test term"}`)
		}, core.NotSupported},
		{func(r *producerContextPair) {
			r.Negative.Calls[0].Output = []byte(`{"@context":"` + did11Context + `","id":"did:sage:web:registry.example:agent-1","otherTerm":"unreviewed"}`)
		}, core.NotSupported},
	} {
		pair = undefinedProducerControl()
		tt.change(&pair)
		if v := judgeUnknownProducer(pair, "input").Verdict; v != tt.want {
			t.Fatal(v, tt.want)
		}
	}
}

type libraryContextMock struct {
	noOperation
	failAt int
	calls  int
}

func (s *libraryContextMock) failed() bool { s.calls++; return s.calls == s.failAt }
func (s *libraryContextMock) InspectBaseContext(context.Context) (BaseContextResult, error) {
	if s.failed() {
		return BaseContextResult{}, errors.New("adapter failed")
	}
	return cachedContextControl(), nil
}
func (s *libraryContextMock) InspectConsumption(_ context.Context, _ ConsumptionRequest) (ConsumptionCapture, error) {
	if s.failed() {
		return ConsumptionCapture{}, errors.New("adapter failed")
	}
	return undefinedConsumerControl(), nil
}
func (s *libraryContextMock) InspectTypedProduction(_ context.Context, q TypedProductionRequest) (TypedProductionResult, error) {
	if s.failed() {
		return TypedProductionResult{}, errors.New("adapter failed")
	}
	pair := undefinedProducerControl()
	if len(q.Fields) == 0 {
		return pair.Positive, nil
	}
	return pair.Negative, nil
}
func TestContextProfileDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendLibraryContextCases(&p)
		want := 3
		if name == "did-core-1.0" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{&libraryContextMock{}, core.Pass}, {&libraryContextMock{failAt: 1}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					want := tt.v
					if o.Statement == "did11-cr20260305#json-ld-processors.6" && want == core.Pass {
						want = core.Fail
					}
					if o.Verdict != want || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
			if c.Statements[0] == "did11-cr20260305#json-ld-processors.6" {
				out := c.Run(t.Context(), &libraryContextMock{failAt: 2})[0]
				var pair producerContextPair
				_ = json.Unmarshal([]byte(out.Observed), &pair)
				if out.Verdict != core.Error || len(pair.Positive.Calls) != 1 {
					t.Fatal("partial producer evidence lost")
				}
			}
		}
	}
}
