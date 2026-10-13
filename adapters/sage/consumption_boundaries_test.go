package sage

import (
	"bytes"
	"testing"

	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func TestSelectedConsumerDeclaredMediaChangesDetectedVersion(t *testing.T) {
	s, _ := identify(pinned)
	data := []byte(`{"id":"did:sage:web:registry.example:agent-1"}`)
	for media, want := range map[string]string{"application/did": "1.1", "application/did+json": "1.0"} {
		got, err := s.InspectConsumption(t.Context(), sageresolution.ConsumptionRequest{Data: data, MediaType: media})
		if err != nil || got.Error != "" || got.CaptureError != "" || got.Version != want || got.JSONLD || !bytes.Equal(got.Input, data) || !bytes.Equal(got.Model, data) || string(got.Entries) != "{}" || got.Require != "unknown" || got.Expected != "unknown" || got.Strict {
			t.Fatal(got, err)
		}
	}
}
func TestSelectedConsumerRejectsLiteralNonObjectRoots(t *testing.T) {
	s, _ := identify(pinned)
	for _, literal := range []string{`[]`, `"text"`, `42`, `true`, `null`} {
		got, err := s.InspectConsumption(t.Context(), sageresolution.ConsumptionRequest{Data: []byte(literal), MediaType: "application/did"})
		if err != nil || got.Error == "" || got.Operation != consumerOperation || !bytes.Equal(got.Input, []byte(literal)) || len(got.Model) > 0 || len(got.Entries) > 0 {
			t.Fatal(got, err)
		}
	}
	if _, err := s.InspectConsumption(t.Context(), sageresolution.ConsumptionRequest{MediaType: "application/json"}); err == nil {
		t.Fatal("accepted unsupported observer media")
	}
}
