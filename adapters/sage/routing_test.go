package sage

import (
	"context"
	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
	"time"
)

func TestActualLibraryRouting(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/remaining-routing-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			want := core.Pass
			if strings.HasSuffix(c.ID, "forward-uri-options") {
				want = core.Fail
			}
			if o.Verdict != want {
				t.Fatal(c.ID, o.Statement, o.Verdict)
			}
		}
	}
	if count != 12 {
		t.Fatal(count)
	}
}

func TestRoutingAdapterAndFixtureBoundaries(t *testing.T) {
	s, _ := identify(pinned)
	q := sageresolution.RoutingRequest{Document: sageresolution.ConsumptionRequest{Data: []byte(`{"id":"did:example:123"}`), MediaType: "application/did"}, Request: sageresolution.Request{Function: "dereference", Input: "did:example:123"}}
	for _, change := range []func(*sageresolution.RoutingRequest){func(q *sageresolution.RoutingRequest) { q.Document.MediaType = "text/plain" }, func(q *sageresolution.RoutingRequest) { q.Request.Function = "unknown" }, func(q *sageresolution.RoutingRequest) { q.Request.Input = "bad" }} {
		x := q
		change(&x)
		if _, e := s.InspectRouting(t.Context(), x); e == nil {
			t.Fatal(x)
		}
	}
	q.Request.Function = "resolve"
	q.Request.Input = "bad"
	if _, e := s.InspectRouting(t.Context(), q); e == nil {
		t.Fatal("bad DID")
	}
	q.Request.Input = "did:example:123"
	r, e := s.InspectRouting(t.Context(), q)
	if e != nil || !r.Result.HasContent || r.Operation != "github.com/sage-x-project/did-go/resolver.DefaultResolver.Resolve" {
		t.Fatal(e, r)
	}
	for _, function := range []string{"resolve", "dereference"} {
		q.Request.Function = function
		q.Request.Options = map[string]any{"unserializable": func() {}}
		if _, e := s.InspectRouting(t.Context(), q); e == nil {
			t.Fatal("capture failure lost")
		}
	}
	calls := [][]byte{}
	m := literalRoutingMethod{body: []byte(`{}`), calls: &calls}
	if _, e := m.Create(context.Background(), nil, method.CreateOptions{}); e != method.ErrNotSupported {
		t.Fatal(e)
	}
	if _, e := m.Update(context.Background(), did.DID{}, nil, method.UpdateOptions{}); e != method.ErrNotSupported {
		t.Fatal(e)
	}
	if _, e := m.Deactivate(context.Background(), did.DID{}, method.DeactivateOptions{}); e != method.ErrNotSupported {
		t.Fatal(e)
	}
	tooLarge := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, e := m.Read(t.Context(), did.DID{}, method.ReadOptions{VersionTime: &tooLarge}); e == nil {
		t.Fatal("invalid option capture")
	}
	out := sageresolution.RoutingResult{}
	spy := routingResolver{routingConstant{}, &out}
	result := spy.Resolve(t.Context(), did.DID{}, resolution.ResolutionOptions{Extra: map[string]any{"unserializable": func() {}}})
	if out.CaptureError == "" || result.Raw == nil {
		t.Fatal("passive wrapper modified delegate result")
	}
}

type routingConstant struct{}

func (routingConstant) Resolve(context.Context, did.DID, resolution.ResolutionOptions) resolution.Result {
	return resolution.Result{Raw: []byte(`{}`)}
}
