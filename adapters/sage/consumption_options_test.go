package sage

import (
	"bytes"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestActualAdditionalConsumptionOptions(t *testing.T) {
	for _, strict := range []bool{false, true} {
		q := sageresolution.ConsumptionOptionsRequest{Document: sageresolution.ConsumptionRequest{Data: []byte(`{"@context":"https://www.w3.org/ns/did/v1.1","id":"did:example:options"}`), MediaType: "application/did"}, Require: "1.1", Strict: strict}
		v, e := (&Subject{}).InspectConsumptionOptions(t.Context(), q)
		if e != nil || v.Error != "" || v.CaptureError != "" || !bytes.Equal(v.Input, q.Document.Data) || v.Require != "1.1" || v.Strict != strict || v.Version != "1.1" || !v.JSONLD {
			t.Fatal(v, e)
		}
		q.Document.Data = []byte(`{`)
		v, e = (&Subject{}).InspectConsumptionOptions(t.Context(), q)
		if e != nil || v.Error == "" {
			t.Fatal("refusal lost", v, e)
		}
	}
	for _, q := range []sageresolution.ConsumptionOptionsRequest{{}, {Require: "1.1"}, {Document: sageresolution.ConsumptionRequest{MediaType: "application/did"}, Require: "1.0"}} {
		if _, e := (&Subject{}).InspectConsumptionOptions(t.Context(), q); e == nil {
			t.Fatal("unknown options")
		}
	}
}
