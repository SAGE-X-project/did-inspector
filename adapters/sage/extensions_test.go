package sage

import (
	"context"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"runtime/debug"
	"testing"
)

func TestExtensionActualOriginalCalls(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	found := 0
	for _, c := range p.Cases {
		if c.ID == "did-1.1/sage-resolution/extension-codecs" || c.ID == "did-1.1/sage-resolution/extension-application-handler" {
			found++
			for _, o := range c.Run(t.Context(), s) {
				want := core.Pass
				if o.Statement == "cid10#multibase-0.1" || o.Statement == "cid10#multihash.1" {
					want = core.NotSupported
				}
				if o.Verdict != want {
					t.Fatal(o.Statement, o.Verdict, o.Observed)
				}
			}
		}
	}
	if found != 2 {
		t.Fatal(found)
	}
}
func TestExtensionAdapterBoundaries(t *testing.T) {
	s, _ := sourceTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := s.InspectMultibaseExtension(ctx, sageresolution.CapacityRequest{}); e == nil {
		t.Fatal("cancel")
	}
	for _, q := range []sageresolution.CapacityRequest{{Operation: "other"}, {Operation: "encode", Header: 'x'}, {Operation: "decode"}, {Operation: "encode", Header: 'f', Data: make([]byte, 65)}, {Operation: "decode", Encoded: string(make([]byte, 257))}} {
		if _, e := s.InspectMultibaseExtension(t.Context(), q); e == nil {
			t.Fatal(q)
		}
	}
	base, _ := s.sourceObserver.build()
	base.GoVersion = "other"
	s.sourceObserver.build = func() (*debug.BuildInfo, bool) { return base, true }
	if _, e := s.InspectMultibaseExtension(t.Context(), sageresolution.CapacityRequest{Operation: "encode", Header: 'f', Data: []byte{1}}); e == nil {
		t.Fatal("identity")
	}
}
func TestApplicationAdapterConfigurationAndCapture(t *testing.T) {
	out := sageresolution.RoutingResult{}
	q := sageresolution.RoutingRequest{ApplicationHandler: "handled", Document: sageresolution.ConsumptionRequest{Data: []byte(`{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:resources"}`), MediaType: "application/did"}, Request: sageresolution.Request{Function: "dereference", Input: "did:example:resources/public-resource"}}
	for _, change := range []func(*sageresolution.RoutingRequest){func(q *sageresolution.RoutingRequest) { q.ApplicationHandler = "other" }, func(q *sageresolution.RoutingRequest) { q.Request.Function = "resolve" }, func(q *sageresolution.RoutingRequest) { q.PlainJSONFragment = true }, func(q *sageresolution.RoutingRequest) { q.ObserveProduction = true }, func(q *sageresolution.RoutingRequest) { q.ObserveResourceHandler = true }} {
		bad := q
		change(&bad)
		if _, e := applicationHandlerOptions(bad, &out); e == nil {
			t.Fatal("unselected mode")
		}
	}
	s, _ := identify(pinned)
	bad := q
	bad.Request.Function = "resolve"
	if _, e := s.InspectRouting(t.Context(), bad); e == nil {
		t.Fatal("must reject mode before resolve branch")
	}
	opts, e := applicationHandlerOptions(q, &out)
	if e != nil || len(opts) != 1 {
		t.Fatal(e)
	}

	// Deliberately unarchivable unit data checks capture-error propagation only.
	// The callback is not an original-dispatch success oracle in this unit test.
	u, e := did.ParseURL("did:example:resources/public-resource")
	if e != nil {
		t.Fatal(e)
	}
	badOptions := resolution.DereferenceOptions{Extra: map[string]any{"not-json": func() {}}}
	badResult := resolution.Result{ResolutionMetadata: resolution.ResolutionMetadata{Extra: map[string]any{"not-json": func() {}}}}
	out = sageresolution.RoutingResult{}
	result, handled := applicationResourceHandler("handled", &out)(t.Context(), u, badResult, badOptions)
	if !handled || result.ContentStream == nil || out.CaptureError == "" || len(out.ApplicationHandler) != 1 || out.ApplicationHandler[0].Input.CaptureError == "" {
		t.Fatal("capture error lost")
	}
}
