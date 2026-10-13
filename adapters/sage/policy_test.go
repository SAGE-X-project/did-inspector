package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualLiteralKeyPolicy(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/key-policy-") {
			continue
		}
		count++
		want := core.Pass
		if strings.Contains(c.ID, "format-") {
			want = core.Fail
		}
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != want {
				t.Fatal(c.ID, o.Statement, o.Verdict)
			}
			var values []sageresolution.PolicyResult
			if json.Unmarshal([]byte(o.Observed), &values) != nil || len(values) == 0 {
				t.Fatal("lost actual captures")
			}
		}
	}
	if count != 18 {
		t.Fatal(count)
	}
}
func TestPolicyAdapterRefusesUnobservedInputs(t *testing.T) {
	s, _ := identify(pinned)
	q := sageresolution.PolicyRequest{Mode: "retrieve", Document: sageresolution.ConsumptionRequest{MediaType: "application/did", Data: []byte(`{"id":"did:sage:web:registry.example:agent-1"}`)}, Reference: "did:sage:web:registry.example:agent-1#sign", Purpose: "authentication", Now: "2029-01-01T00:00:00Z"}
	for _, change := range []func(*sageresolution.PolicyRequest){func(x *sageresolution.PolicyRequest) { x.Document.MediaType = "text/plain" }, func(x *sageresolution.PolicyRequest) { x.Mode = "other" }, func(x *sageresolution.PolicyRequest) { x.Reference = "invalid" }, func(x *sageresolution.PolicyRequest) { x.Purpose = "invalid" }, func(x *sageresolution.PolicyRequest) { x.Now = "invalid" }, func(x *sageresolution.PolicyRequest) { x.Options = map[string]any{"accept": true} }} {
		x := q
		change(&x)
		if _, e := s.InspectPolicy(t.Context(), x); e == nil {
			t.Fatal(x)
		}
	}
	x := q
	x.Document.Data = []byte(`{`)
	out, e := s.InspectPolicy(t.Context(), x)
	if e != nil || out.Consumer.Error == "" || out.Retrieval.Operation != "" || len(out.Retrieval.Calls) > 0 {
		t.Fatal("consumer refusal mislabelled as RP refusal", e)
	}
}
