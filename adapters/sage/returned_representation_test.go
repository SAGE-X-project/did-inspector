package sage

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualReturnedRepresentation(t *testing.T) {
	s, _ := sourceTest(t)
	p, err := sageresolution.Profile("did-1.1")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.HasSuffix(c.ID, "/returned-minimal-representation") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				t.Fatal(o.Statement, o.Verdict)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
	q := sageresolution.RoutingRequest{ObserveProduction: true, Document: sageresolution.ConsumptionRequest{Data: []byte(`{"id":"did:example:123"}`), MediaType: "application/did"}, Request: sageresolution.Request{Function: "dereference", Input: "did:example:123"}}
	if _, err := s.InspectRouting(t.Context(), q); err == nil {
		t.Fatal("producer observer must have a Resolve caller")
	}
	q.Request.Function = "resolve"
	q.Request.Accept = "application/did+json"
	v, err := s.InspectRouting(t.Context(), q)
	if err != nil || len(v.Production) != 1 || v.Production[0].Version != "1.0" || len(v.Consumption) != 1 || v.Consumption[0].Version != "1.1" {
		t.Fatal(err, v)
	}
}
