package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func minimalControl() (RoutingResult, TypedProductionResult) {
	model := []byte(`{"id":"did:example:123"}`)
	r := RoutingResult{Request: minimalRequest(), Role: "root resolver/dereferencer library with literal example driver; not SAGE Source", Operation: "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve", DataModel: model, Entries: []byte(`{}`), Result: Result{Metadata: []byte(`{"contentType":"application/did"}`), HasContent: true, ReturnedID: "did:example:123", ContentKind: "document"}}
	p := TypedProductionResult{ID: "did:example:123", Calls: []ProductionCapture{{Operation: "github.com/sage-x-project/did-go/producer.Producer.Produce", Model: model, Entries: []byte(`{}`), Output: model, Version: "1.0", MediaType: "application/did+json"}}}
	return r, p
}
func TestMinimalRepresentationControls(t *testing.T) {
	r, p := minimalControl()
	if judgeMinimal(r, p, "input")[0].Verdict != core.Pass {
		t.Fatal("minimal control")
	}
	for _, change := range []func(*RoutingResult, *TypedProductionResult){func(r *RoutingResult, p *TypedProductionResult) { r.Request.Request.Input = "other" }, func(r *RoutingResult, p *TypedProductionResult) { r.Role = "other" }, func(r *RoutingResult, p *TypedProductionResult) { r.Operation = "other" }, func(r *RoutingResult, p *TypedProductionResult) { r.CaptureError = "lost" }, func(r *RoutingResult, p *TypedProductionResult) { r.Result.HasContent = false }, func(r *RoutingResult, p *TypedProductionResult) { r.Result.ReturnedID = "other" }, func(r *RoutingResult, p *TypedProductionResult) { r.Result.ContentKind = "other" }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls = nil }, func(r *RoutingResult, p *TypedProductionResult) { p.BuildError = "lost" }, func(r *RoutingResult, p *TypedProductionResult) { p.CaptureError = "lost" }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].Operation = "other" }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].Version = "1.1" }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].JSONLD = true }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].Error = "refused" }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].CaptureError = "lost" }, func(r *RoutingResult, p *TypedProductionResult) { r.DataModel = []byte(`{`) }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].Model = []byte(`{`) }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].Entries = []byte(`{`) }, func(r *RoutingResult, p *TypedProductionResult) { p.Calls[0].Output = []byte(`{`) }} {
		r, p := minimalControl()
		change(&r, &p)
		if judgeMinimal(r, p, "input")[0].Verdict != core.Error {
			t.Fatal("false minimal attribution")
		}
	}
	r, p = minimalControl()
	p.Calls[0].MediaType = "other"
	if judgeMinimal(r, p, "input")[0].Verdict != core.Fail {
		t.Fatal("wrong representation")
	}
}

type minimalMock struct {
	noOperation
	fail string
}

func (s minimalMock) InspectRouting(context.Context, RoutingRequest) (RoutingResult, error) {
	r, _ := minimalControl()
	if s.fail == "resolve" {
		return r, errors.New("lost resolver")
	}
	return r, nil
}
func (s minimalMock) InspectTypedProduction(context.Context, TypedProductionRequest) (TypedProductionResult, error) {
	_, p := minimalControl()
	if s.fail == "produce" {
		return p, errors.New("lost producer")
	}
	return p, nil
}
func TestMinimalDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendMinimalCase(&p)
		if name != "did-1.1" && len(p.Cases) > 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{minimalMock{}, core.Pass}, {minimalMock{fail: "resolve"}, core.Error}, {minimalMock{fail: "produce"}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}

func TestMinimalRequiresSuccessfulResolutionAndMinimalEntries(t *testing.T) {
	for _, change := range []func(*RoutingResult){func(r *RoutingResult) { r.Result.Metadata = []byte(`{"error":{}}`) }, func(r *RoutingResult) { r.Result.Metadata = []byte(`{`) }, func(r *RoutingResult) { r.Entries = []byte(`{"extra":true}`) }, func(r *RoutingResult) { r.Entries = []byte(`{`) }} {
		r, p := minimalControl()
		change(&r)
		if judgeMinimal(r, p, "input")[0].Verdict != core.Error {
			t.Fatal("false successful minimum")
		}
	}
}
