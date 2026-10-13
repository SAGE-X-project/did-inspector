package sage

import (
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestActualProducerContextBoundary(t *testing.T) {
	s, _ := identify(pinned)
	base := sageresolution.TypedValue{Kind: "string", Text: "https://www.w3.org/ns/did/v1.1"}
	values := []sageresolution.TypedValue{base, {Kind: "boolean"}, {Kind: "integer", Text: "42"}, {Kind: "list", Items: []sageresolution.TypedValue{base, {Kind: "boolean"}}}}
	for i, v := range values {
		q := sageresolution.TypedProductionRequest{ID: "did:sage:web:registry.example:agent-1", Controllers: []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}, Entries: []sageresolution.TypedMember{{Name: "@context", Value: v}}, JSONLD: true}
		out, e := s.InspectTypedProduction(t.Context(), q)
		if e != nil || out.BuildError != "" || out.CaptureError != "" || len(out.Calls) != 1 || len(out.Entries) != 1 || out.Entries[0].Value.Kind != v.Kind || out.Calls[0].Operation != producerOperation || out.Calls[0].CaptureError != "" {
			t.Fatal(i, out, e)
		}
		call := out.Calls[0]
		if i == 0 {
			if call.Error != "" || call.MediaType != "application/did" || len(call.Output) == 0 {
				t.Fatal(out)
			}
		} else if call.Error == "" || len(call.Output) != 0 {
			t.Fatal("actual producer did not refuse context", i, out)
		}
	}
}
