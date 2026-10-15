package sage

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

func TestActualInternalEvidenceBoundaries(t *testing.T) {
	s, _ := sourceTest(t)
	p, err := sageresolution.Profile("did-1.1")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range p.Cases {
		if strings.HasSuffix(c.ID, "/capacity-u64-component") || strings.HasSuffix(c.ID, "/context-injection-no-context") || strings.HasSuffix(c.ID, "/fragment-plain-json-media") {
			count++
			obs := c.Run(t.Context(), s)
			for _, o := range obs {
				if o.Verdict != core.Pass {
					t.Fatalf("%s %s", o.Statement, o.Verdict)
				}
			}
			if dir := os.Getenv("SAGE_CAPTURE_INTERNAL_EVIDENCE"); dir != "" {
				b, _ := json.Marshal(obs)
				name := c.ID[strings.LastIndex(c.ID, "/")+1:]
				if err := os.WriteFile(dir+"/"+name+".json", b, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if count != 3 {
		t.Fatal(count)
	}
}
func TestCapacityObserverLimits(t *testing.T) {
	s, _ := sourceTest(t)
	q := sageresolution.CapacityRequest{Operation: "encode", Header: 'u', Data: []byte{0, 1, 2}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.InspectCapacity(ctx, q); err == nil {
		t.Fatal("cancel")
	}
	for _, change := range []func(*sageresolution.CapacityRequest){func(q *sageresolution.CapacityRequest) { q.Operation = "other" }, func(q *sageresolution.CapacityRequest) { q.Header = 'z' }, func(q *sageresolution.CapacityRequest) { q.Data = make([]byte, 4097) }, func(q *sageresolution.CapacityRequest) { q.Encoded = strings.Repeat("A", 4097) }} {
		v := q
		change(&v)
		if _, err := s.InspectCapacity(t.Context(), v); err == nil {
			t.Fatal("scope")
		}
	}
	s.sourceObserver.build = func() (*debug.BuildInfo, bool) { return nil, false }
	if _, err := s.InspectCapacity(t.Context(), q); err == nil {
		t.Fatal("identity")
	}
	s, _ = sourceTest(t)
	q.Operation = "decode"
	q.Encoded = "u="
	if v, err := s.InspectCapacity(t.Context(), q); err != nil || v.Error == "" {
		t.Fatal("ordinary invalid alphabet", err)
	}
}
func TestPlainJSONRoutingOptIn(t *testing.T) {
	s, _ := sourceTest(t)
	q := sageresolution.RoutingRequest{PlainJSONFragment: true, Document: sageresolution.ConsumptionRequest{Data: []byte(`{"id":"did:example:resources"}`), MediaType: "application/did+json"}, Request: sageresolution.Request{Function: "dereference", Input: "did:example:resources#none", Accept: "application/did+json"}}
	v, err := s.InspectRouting(t.Context(), q)
	if err != nil || len(v.Consumption) != 1 || v.Consumption[0].Version != "1.0" {
		t.Fatal(err, v)
	}
	for _, change := range []func(*sageresolution.RoutingRequest){func(q *sageresolution.RoutingRequest) { q.PlainJSONFragment = false }, func(q *sageresolution.RoutingRequest) { q.Document.MediaType = "application/did" }, func(q *sageresolution.RoutingRequest) { q.Request.Function = "resolve" }, func(q *sageresolution.RoutingRequest) { q.ObserveProduction = true }, func(q *sageresolution.RoutingRequest) { q.ObserveResourceHandler = true }} {
		v := q
		change(&v)
		if _, err := s.InspectRouting(t.Context(), v); err == nil {
			t.Fatal("opt-in")
		}
	}
	m := literalRoutingMethod{media: "application/did+json"}
	if m.Produces()[0] != "application/did+json" {
		t.Fatal("declared driver media")
	}
	if (literalRoutingMethod{}).Produces()[0] != "application/did" {
		t.Fatal("old driver")
	}
}
