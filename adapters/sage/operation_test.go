package sage

import (
	"context"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"sync"
	"testing"
)

func TestActualRemainingOperationsAndBinding(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/remaining-operation-") && !strings.Contains(c.ID, "/remaining-binding-") && !strings.Contains(c.ID, "/remaining-expansion-") && !strings.Contains(c.ID, "/remaining-proxy-") && !strings.Contains(c.ID, "/remaining-preference-") && !strings.Contains(c.ID, "/remaining-cid-http-") && !strings.Contains(c.ID, "/remaining-minimal-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			allowed := o.Verdict == core.Pass || (o.Statement == "res10-crd20261001#resolver-architectures-proxied.2" && o.Verdict == core.Fail)
			if !allowed {
				t.Fatal(c.ID, o.Statement, o.Verdict, o.Observed)
			}
		}
	}
	if count != 12 {
		t.Fatal(count)
	}
}
func TestOperationAdapterInputFailures(t *testing.T) {
	s, _ := identify(pinned)
	for _, q := range []sageresolution.LibraryOperationRequest{{Kind: "bad"}, {Kind: "cache", Input: "bad"}} {
		if _, e := s.InspectLibraryOperation(t.Context(), q); e == nil {
			t.Fatal(q)
		}
	}
	for _, verb := range []string{"GET", "invalid"} {
		if _, e := s.InspectRoutingBinding(t.Context(), sageresolution.RoutingRequest{}, verb); e == nil {
			t.Fatal("invalid fixture")
		}
	}
}

func TestOwnedBindingRefusesCanceledAndInvalidRequests(t *testing.T) {
	s, _ := identify(pinned)
	q := sageresolution.RoutingRequest{Document: sageresolution.ConsumptionRequest{Data: []byte(`{"id":"did:example:123"}`), MediaType: "application/did"}, Request: sageresolution.Request{Function: "dereference", Input: "did:example:123?service=one", Accept: "text/uri-list"}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := s.InspectRoutingBinding(ctx, q, "GET"); e == nil {
		t.Fatal("canceled operation accepted")
	}
	if _, e := s.InspectRoutingBinding(t.Context(), q, "invalid method"); e == nil {
		t.Fatal("invalid method accepted")
	}
	q.Request.Input = "bad"
	if out, e := s.InspectRoutingBinding(t.Context(), q, "GET"); e != nil || out.Exchange.Status != 400 || len(out.Native) != 0 {
		t.Fatal("invalid identifier did not retain actual handler refusal", e)
	}
}

type invalidBindingDelegate struct{}

func (invalidBindingDelegate) Dereference(context.Context, did.DIDURL, resolution.DereferenceOptions) resolution.DereferenceResult {
	return resolution.DereferenceResult{ContentStream: func() {}}
}
func TestBindingCaptureRetainsDelegateFailure(t *testing.T) {
	out := sageresolution.RoutingBindingResult{}
	var mu sync.Mutex
	r := bindingDereferencer{invalidBindingDelegate{}, &out, &mu}
	u, _ := did.ParseURL("did:example:123")
	res := r.Dereference(t.Context(), u, resolution.DereferenceOptions{})
	if res.ContentStream == nil || len(out.Native) != 1 || out.Native[0].CaptureError == "" {
		t.Fatal("delegate capture loss")
	}
}

func TestTypedProductionRejectsUnknownVersion(t *testing.T) {
	s, _ := identify(pinned)
	out, e := s.InspectTypedProduction(t.Context(), sageresolution.TypedProductionRequest{ID: "did:example:123", Version: "unknown"})
	if e != nil || out.BuildError == "" || len(out.Calls) != 0 {
		t.Fatal("unknown version accepted", e)
	}
}

func TestTypedProductionRejectsContradictoryControllerShape(t *testing.T) {
	s, _ := identify(pinned)
	for _, q := range []sageresolution.TypedProductionRequest{{ID: "did:example:123", ControllerShape: "other"}, {ID: "did:example:123", ControllerShape: "absent", Controllers: []string{"did:example:controller"}}} {
		out, e := s.InspectTypedProduction(t.Context(), q)
		if e != nil || out.BuildError == "" || len(out.Calls) != 0 {
			t.Fatal("contradictory shape accepted")
		}
	}
}
