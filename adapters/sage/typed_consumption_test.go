package sage

import (
	"bytes"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"testing"
)

func TestActualTypedConsumerWitness(t *testing.T) {
	s, _ := identify(pinned)
	const literal = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"],"verificationMethod":[{"id":"did:sage:web:registry.example:agent-1#sign","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},"expires":"2020-12-21T04:17:47.123456789+09:00","revoked":"2020-12-20T23:59:59.987654321-05:00"}],"integer":9007199254740991,"double":2.0,"clock":"2020-12-21T04:17:47.123456789+09:00","list":[false,null,"한글\n"],"map":{"value":1.5,"empty":{}}}`
	q := sageresolution.ConsumptionRequest{Data: []byte(literal), MediaType: "application/did"}
	out, e := s.InspectTypedConsumption(t.Context(), q)
	if e != nil || out.Call.Error != "" || out.Call.CaptureError != "" || out.CaptureError != "" || !bytes.Equal(out.Call.Input, q.Data) || out.Call.Operation != consumerOperation || out.Call.Version != "1.1" || out.Call.JSONLD || out.Call.Strict || out.Call.Require != "unknown" || out.Call.Expected != "unknown" {
		t.Fatal(out, e)
	}
	if out.ID != "did:sage:web:registry.example:agent-1" || out.ControllerShape != "set" || len(out.Controllers) != 2 || out.Controllers[0] != "did:sage:web:registry.example:controller-a" || len(out.Entries) != 0 || string(out.Call.Entries) != "{}" {
		t.Fatal(out)
	}
	fields := map[string]sageresolution.TypedValue{}
	for _, f := range out.Fields {
		fields[f.Name] = f.Value
	}
	if fields["integer"].Kind != "integer" || fields["integer"].Text != "9007199254740991" || fields["double"].Kind != "double" || fields["double"].Text != "2" || fields["clock"].Kind != "string" || fields["clock"].Text != "2020-12-21T04:17:47.123456789+09:00" {
		t.Fatal(fields)
	}
	l := fields["list"]
	if l.Kind != "list" || len(l.Items) != 3 || l.Items[0].Kind != "boolean" || l.Items[0].Flag || l.Items[1].Kind != "null" || l.Items[2].Text != "한글\n" {
		t.Fatal(l)
	}
	m := fields["map"]
	if m.Kind != "map" || len(m.Members) != 2 || m.Members[0].Value.Kind != "double" || m.Members[0].Value.Text != "1.5" || m.Members[1].Value.Kind != "map" {
		t.Fatal(m)
	}
	if len(out.Methods) != 1 || out.Methods[0].Expires.Kind != "datetime" || out.Methods[0].Expires.Text != "2020-12-21T04:17:47.123456789+09:00" || out.Methods[0].Revoked.Text != "2020-12-20T23:59:59.987654321-05:00" {
		t.Fatal(out.Methods)
	}
}
func TestActualTypedConsumerRejectionAndAbsentDate(t *testing.T) {
	s, _ := identify(pinned)
	for _, data := range []string{`null`, `{`, `{"id":42}`} {
		r, e := s.InspectTypedConsumption(t.Context(), sageresolution.ConsumptionRequest{Data: []byte(data), MediaType: "application/did"})
		if e != nil || r.Call.Error == "" || r.ID != "" || len(r.Methods) > 0 {
			t.Fatal(r, e)
		}
	}
	if _, e := s.InspectTypedConsumption(t.Context(), sageresolution.ConsumptionRequest{MediaType: "application/did+json"}); e == nil {
		t.Fatal("legacy media accepted")
	}
	q := sageresolution.ConsumptionRequest{Data: []byte(`{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[{"id":"#key","type":"Example","controller":"did:sage:web:registry.example:agent-1"}]}`), MediaType: "application/did"}
	r, e := s.InspectTypedConsumption(t.Context(), q)
	if e != nil || r.Call.Error != "" || len(r.Methods) != 1 || r.Methods[0].Expires != nil || r.Methods[0].Revoked != nil {
		t.Fatal(r, e)
	}
}
