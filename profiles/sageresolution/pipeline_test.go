package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

func pipelineFixture() PipelineResult {
	model := []byte(`{"id":"did:sage:web:x:a","ext":["text",42,true,null,{"nested":false}]}`)
	entries := []byte(`{"@context":"https://www.w3.org/ns/did/v1.1"}`)
	wire := []byte(`{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:sage:web:x:a","ext":["text",42,true,null,{"nested":false}]}`)
	return PipelineResult{Producer: []ProductionCapture{{Operation: pipelineProducer, Model: model, Entries: []byte(`{}`), Version: "1.1", JSONLD: true, Output: wire, MediaType: "application/did"}}, Consumer: []ConsumptionCapture{{Operation: pipelineConsumer, Input: wire, MediaType: "application/did", Version: "1.1", JSONLD: true, Require: "unknown", Expected: "unknown", Model: model, Entries: entries}}, Result: Result{Metadata: json.RawMessage(`{"contentType":"application/did"}`), HasContent: true, ContentKind: "document", Raw: wire}}
}
func TestPipelineActualBoundaryControls(t *testing.T) {
	baseline := pipelineFixture()
	for _, o := range judgePipeline(baseline, "unit-input") {
		if o.Verdict != core.Pass || o.Input != "unit-input" || o.Observed == "" {
			t.Fatal(o)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*PipelineResult)
		want   []core.Verdict
	}{
		{"producer drops entry", func(r *PipelineResult) { r.Producer[0].Model = []byte(`{"id":"did:sage:web:x:a","missing":true}`) }, []core.Verdict{core.Fail, core.Pass, core.Pass, core.Pass, core.Pass}},
		{"consumer drops entry", func(r *PipelineResult) { r.Consumer[0].Model = []byte(`{"id":"did:sage:web:x:a"}`) }, []core.Verdict{core.Pass, core.Pass, core.Pass, core.Fail, core.Fail}},
		{"consumer context missing", func(r *PipelineResult) { r.Consumer[0].Entries = []byte(`{}`) }, []core.Verdict{core.Pass, core.Pass, core.Fail, core.Pass, core.Fail}},
		{"context in data model", func(r *PipelineResult) {
			r.Consumer[0].Model = r.Consumer[0].Input
			r.Consumer[0].Entries = []byte(`{}`)
		}, []core.Verdict{core.Pass, core.Pass, core.Fail, core.Fail, core.Pass}},
		{"bad media", func(r *PipelineResult) { r.Producer[0].MediaType = "application/did;broken" }, []core.Verdict{core.Pass, core.Fail, core.Pass, core.Pass, core.Pass}},
		{"bad consumer media", func(r *PipelineResult) { r.Consumer[0].MediaType = "application/did+json" }, []core.Verdict{core.Pass, core.Pass, core.NotSupported, core.NotSupported, core.NotSupported}},
		{"bad metadata media", func(r *PipelineResult) { r.Result.Metadata = json.RawMessage(`{}`) }, []core.Verdict{core.Pass, core.Pass, core.Pass, core.Pass, core.Pass}},
		{"unobserved term processing", func(r *PipelineResult) { r.Consumer[0].DroppedTerms = []string{"extra"} }, []core.Verdict{core.Pass, core.Pass, core.Pass, core.NotSupported, core.NotSupported}},
		{"outside selected types", func(r *PipelineResult) { r.Producer[0].Model = []byte(`{"extra":1.5}`) }, []core.Verdict{core.NotSupported, core.Pass, core.Pass, core.Pass, core.Pass}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := pipelineFixture()
			tc.mutate(&r)
			for i, o := range judgePipeline(r, "unit-input") {
				if o.Verdict != tc.want[i] || o.Input != "unit-input" || o.Observed == "" {
					t.Fatal(o, tc.want[i])
				}
			}
		})
	}
	// A post-consumption snapshot never substitutes for actual pre-producer maps.
	baseline.Result.Snapshot = json.RawMessage(`{"wrong":true}`)
	baseline.Producer[0].Entries = baseline.Consumer[0].Entries
	baseline.Producer[0].MediaType = "Application/DID; charset=utf-8"
	for _, o := range judgePipeline(baseline, "unit") {
		if o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
}
func TestPipelineUnavailableAndAttribution(t *testing.T) {
	for _, mutate := range []func(*PipelineResult){
		func(r *PipelineResult) { r.Producer = nil }, func(r *PipelineResult) { r.Consumer = nil }, func(r *PipelineResult) { r.Consumer = append(r.Consumer, r.Consumer[0]) },
		func(r *PipelineResult) { r.Producer[0].Operation = "generic" }, func(r *PipelineResult) { r.Consumer[0].Operation = "generic" },
		func(r *PipelineResult) { r.Producer[0].Version = "1.0" }, func(r *PipelineResult) { r.Producer[0].IncludeSecret = true }, func(r *PipelineResult) { r.Producer[0].JSONLD = false }, func(r *PipelineResult) { r.Consumer[0].Version = "1.0" }, func(r *PipelineResult) { r.Consumer[0].JSONLD = false },
		func(r *PipelineResult) { r.Consumer[0].Require = "1.1" }, func(r *PipelineResult) { r.Consumer[0].Expected = "1.0" }, func(r *PipelineResult) { r.Consumer[0].Strict = true },
		func(r *PipelineResult) { r.Producer[0].Error = "delegate error" }, func(r *PipelineResult) { r.Consumer[0].CaptureError = "accessor error" },
		func(r *PipelineResult) { r.Result.Metadata = json.RawMessage(`null`) },
		func(r *PipelineResult) { r.Result.Metadata = json.RawMessage(`{`) }, func(r *PipelineResult) { r.Result.Snapshot = json.RawMessage(`{`) }, func(r *PipelineResult) { r.Result.Metadata = json.RawMessage(`{"error":null}`) },
		func(r *PipelineResult) { r.Result.HasContent = false }, func(r *PipelineResult) { r.Result.ContentKind = "method" }, func(r *PipelineResult) { r.Result.Exchange = &core.HTTPExchange{} }, func(r *PipelineResult) { r.Result.Native = &NativeObservation{} }, func(r *PipelineResult) { r.Result.Raw = []byte(`{}`) }, func(r *PipelineResult) { r.Consumer[0].Input = []byte(`{}`) },
		func(r *PipelineResult) { r.Producer[0].Model = []byte(`[]`) }, func(r *PipelineResult) { r.Producer[0].Model = []byte(`{"x":1,"x":2}`) }, func(r *PipelineResult) { r.Consumer[0].Entries = []byte{0xff} },
		func(r *PipelineResult) { r.Producer[0].Entries = []byte(`{"id":"overlap"}`) }, func(r *PipelineResult) { r.Consumer[0].Entries = []byte(`{"id":"overlap"}`) },
		func(r *PipelineResult) {
			b := []byte(`{"id":"did:sage:web:x:a"}`)
			r.Producer[0].Output = b
			r.Consumer[0].Input = b
			r.Result.Raw = b
		},
	} {
		r := pipelineFixture()
		mutate(&r)
		for _, o := range judgePipeline(r, "unit-input") {
			if o.Verdict != core.Error || o.Input != "unit-input" || o.Observed == "" {
				t.Fatal(o)
			}
		}
	}
}

type pipelineOnly struct{ fail bool }

func (pipelineOnly) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit-pipeline"} }
func (pipelineOnly) Supports(string, core.Capability) bool { return false }
func (s pipelineOnly) InspectPipeline(context.Context, sageprojection.Record, Request) (PipelineResult, error) {
	if s.fail {
		return PipelineResult{}, errors.New("fixture execution error")
	}
	return pipelineFixture(), nil
}
func TestPipelineCasesKeepFreshScope(t *testing.T) {
	rows, _ := sageprojection.Fixtures()
	p := core.Profile{Name: "did-1.1"}
	appendPipelineCases(&p, rows)
	if len(p.Cases) != 5 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, tc := range []struct {
			s core.Subject
			v core.Verdict
		}{{pipelineOnly{}, core.Pass}, {pipelineOnly{true}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tc.s) {
				if o.Verdict != tc.v || o.Input == "" {
					t.Fatal(c.ID, o)
				}
			}
		}
	}
	p = core.Profile{Name: "did-core-1.0"}
	appendPipelineCases(&p, rows)
	if len(p.Cases) != 0 {
		t.Fatal("legacy pipeline attribution")
	}
}
