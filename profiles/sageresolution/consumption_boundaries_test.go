package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

func TestActualRootPlacementControls(t *testing.T) {
	r := pipelineFixture()
	o := judgeProductionRoot(r, "unit")
	if o.Verdict != core.Pass || o.Input != "unit" || o.Observed == "" {
		t.Fatal(o)
	}
	for _, tc := range []struct {
		mutate func(*PipelineResult)
		want   core.Verdict
	}{
		{func(r *PipelineResult) { r.Producer[0].Model = []byte(`{"missing":null}`) }, core.Fail},
		{func(r *PipelineResult) {
			r.Producer[0].Entries = []byte(`{"@context":"https://www.w3.org/ns/did/v1.1"}`)
		}, core.Pass},
		{func(r *PipelineResult) {
			r.Producer[0].Output = []byte(`{"wrapper":{"id":"did:sage:web:x:a","ext":[]}}`)
		}, core.Fail},
		{func(r *PipelineResult) { r.Producer[0].Output = []byte(`[]`) }, core.Fail},
		{func(r *PipelineResult) { r.Producer[0].Output = []byte(`{"id":"one","id":"two"}`) }, core.Fail},
		{func(r *PipelineResult) { r.Producer[0].Output = []byte(`{`) }, core.Fail},
		{func(r *PipelineResult) { r.Producer = nil }, core.Error},
		{func(r *PipelineResult) { r.Producer[0].Operation = "generic" }, core.Error},
		{func(r *PipelineResult) { r.Producer[0].Error = "actual error" }, core.Error},
		{func(r *PipelineResult) { r.Producer[0].Model = []byte(`[]`) }, core.Error},
		{func(r *PipelineResult) { r.Producer[0].Entries = []byte(`null`) }, core.Error},
		{func(r *PipelineResult) { r.Producer[0].Entries = []byte(`{"id":"overlap"}`) }, core.Error},
		{func(r *PipelineResult) { r.Result.Snapshot = json.RawMessage(`{`) }, core.Error},
	} {
		r := pipelineFixture()
		tc.mutate(&r)
		o := judgeProductionRoot(r, "unit")
		if o.Verdict != tc.want || o.Input != "unit" || o.Observed == "" {
			t.Fatal(o)
		}
	}
}
func consumerFixture(q ConsumptionRequest, version string) ConsumptionCapture {
	return ConsumptionCapture{Operation: pipelineConsumer, Input: q.Data, MediaType: q.MediaType, Require: "unknown", Expected: "unknown", Version: version, Model: q.Data, Entries: []byte(`{}`)}
}
func TestConsumerMediaBoundaryControls(t *testing.T) {
	q := ConsumptionRequest{[]byte(`{"id":"did:sage:web:x:a"}`), "application/did"}
	base := consumerFixture(q, "1.1")
	o := judgeConsumption(base, q, consumerMediaStatement, "1.1", "unit")
	if o.Verdict != core.Pass || o.Observed == "" || o.Input != "unit" {
		t.Fatal(o)
	}
	for _, tc := range []struct {
		mutate func(*ConsumptionCapture)
		want   core.Verdict
	}{
		{func(r *ConsumptionCapture) { r.Version = "1.0" }, core.Fail},
		{func(r *ConsumptionCapture) { r.Error = "consumer error" }, core.Fail},
		{func(r *ConsumptionCapture) { r.CaptureError = "capture error" }, core.Error},
		{func(r *ConsumptionCapture) { r.JSONLD = true }, core.Fail},
		{func(r *ConsumptionCapture) { r.DroppedTerms = []string{"id"} }, core.Fail},
		{func(r *ConsumptionCapture) { r.Model = []byte(`{}`) }, core.Fail},
		{func(r *ConsumptionCapture) { r.Model = []byte(`null`) }, core.Fail},
		{func(r *ConsumptionCapture) { r.Entries = []byte(`null`) }, core.Fail},
		{func(r *ConsumptionCapture) { r.Entries = []byte(`{"@context":"wrong"}`) }, core.Fail},
		{func(r *ConsumptionCapture) { r.Input = []byte(`{}`) }, core.Error},
		{func(r *ConsumptionCapture) { r.MediaType = "application/did+json" }, core.Error},
		{func(r *ConsumptionCapture) { r.Operation = "generic" }, core.Error},
		{func(r *ConsumptionCapture) { r.Require = "1.1" }, core.Error},
		{func(r *ConsumptionCapture) { r.Expected = "1.0" }, core.Error},
		{func(r *ConsumptionCapture) { r.Strict = true }, core.Error},
	} {
		r := consumerFixture(q, "1.1")
		tc.mutate(&r)
		o := judgeConsumption(r, q, consumerMediaStatement, "1.1", "unit")
		if o.Verdict != tc.want || o.Observed == "" {
			t.Fatal(o)
		}
	}
	for _, bad := range []ConsumptionRequest{{[]byte(`{`), "application/did"}, {[]byte(`[]`), "application/did"}, {q.Data, "application/json"}} {
		r := consumerFixture(bad, "1.1")
		if o := judgeConsumption(r, bad, consumerMediaStatement, "1.1", "unit"); o.Verdict != core.Error {
			t.Fatal(o)
		}
	}
	if o := judgeConsumption(base, q, "other", "1.1", "unit"); o.Verdict != core.Error {
		t.Fatal(o)
	}
}
func TestConsumerNonObjectRootControls(t *testing.T) {
	for _, literal := range []string{`[]`, `"text"`, `42`, `true`, `null`} {
		q := ConsumptionRequest{[]byte(literal), "application/did"}
		r := consumerFixture(q, "unknown")
		r.Model = nil
		r.Entries = nil
		r.Error = "actual consumer error"
		r.CaptureError = "no document"
		if o := judgeConsumption(r, q, consumerRootStatement, "", "unit"); o.Verdict != core.Pass || o.Observed == "" {
			t.Fatal(o)
		}
		r.Error = ""
		if o := judgeConsumption(r, q, consumerRootStatement, "", "unit"); o.Verdict != core.Fail {
			t.Fatal(o)
		}
		r.Error = "error"
		r.Model = []byte(`{}`)
		if o := judgeConsumption(r, q, consumerRootStatement, "", "unit"); o.Verdict != core.Fail {
			t.Fatal(o)
		}
	}
	q0 := ConsumptionRequest{[]byte(`[]`), "application/did+json"}
	r0 := consumerFixture(q0, "1.0")
	r0.Model = nil
	r0.Entries = nil
	r0.Error = "error"
	if o := judgeConsumption(r0, q0, consumerRootStatement, "", "unit"); o.Verdict != core.Error {
		t.Fatal("legacy root result misattributed", o)
	}
	q := ConsumptionRequest{[]byte(`{}`), "application/did"}
	r := consumerFixture(q, "unknown")
	if o := judgeConsumption(r, q, consumerRootStatement, "", "unit"); o.Verdict != core.Error {
		t.Fatal(o)
	}
}

type consumptionOnly struct{ fail bool }

func (consumptionOnly) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit-consumption"} }
func (consumptionOnly) Supports(string, core.Capability) bool { return false }
func (s consumptionOnly) InspectPipeline(context.Context, sageprojection.Record, Request) (PipelineResult, error) {
	if s.fail {
		return PipelineResult{}, errors.New("execution error")
	}
	return pipelineFixture(), nil
}
func (s consumptionOnly) InspectConsumption(_ context.Context, q ConsumptionRequest) (ConsumptionCapture, error) {
	if s.fail {
		return ConsumptionCapture{}, errors.New("execution error")
	}
	value, _ := core.ParseJSON(q.Data)
	version := "1.1"
	if q.MediaType == "application/did+json" {
		version = "1.0"
	}
	r := consumerFixture(q, version)
	if value.Kind != core.KindObject {
		r.Model = nil
		r.Entries = nil
		r.Error = "actual library error"
	}
	return r, nil
}
func TestConsumptionBoundaryCasesKeepScopeAndInput(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	p := core.Profile{Name: "did-1.1"}
	appendConsumptionBoundaryCases(&p, rows)
	if len(p.Cases) != 12 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, tc := range []struct {
			s    core.Subject
			want core.Verdict
		}{{consumptionOnly{}, core.Pass}, {consumptionOnly{true}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tc.s) {
				if o.Verdict != tc.want || o.Input == "" {
					t.Fatal(c.ID, o)
				}
			}
		}
	}
	p = core.Profile{Name: "did-core-1.0"}
	appendConsumptionBoundaryCases(&p, rows)
	if len(p.Cases) != 0 {
		t.Fatal("legacy scope expanded")
	}
}
