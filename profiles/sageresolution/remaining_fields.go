package sageresolution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
)

// This is RFC8032 section7.1 test1's published seed, never an operational key.
// It is consumed only as public test data; no signing or key custody occurs.
func publicTestSeed() []byte {
	b, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	return b
}
func remainingFieldFixtures() []optionalFixture {
	out := []optionalFixture{}
	for _, name := range []string{"public-jwk", "secret-jwk", "secret-multibase", "service-extension", "custom-relationship", "no-context"} {
		absent, present := optionalDocument(), optionalDocument()
		id := ""
		a := absent["verificationMethod"].([]any)[0].(map[string]any)
		b := present["verificationMethod"].([]any)[0].(map[string]any)
		switch name {
		case "public-jwk":
			id = "cid10#JsonWebKey.2"
			delete(a, "publicKeyJwk")
		case "secret-jwk":
			id = "cid10#JsonWebKey.10"
			secret := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "d": "nWGxne_9WmC6hEr0kuzCxERJxWl7MmkZcDusAxyuf2A"}
			b["secretKeyJwk"] = secret
		case "secret-multibase":
			id = "cid10#Multikey.4"
			a["type"] = "Multikey"
			delete(a, "publicKeyJwk")
			b["type"] = "Multikey"
			delete(b, "publicKeyJwk")
			b["secretKeyMultibase"] = btcEncode(append([]byte{0x80, 0x26}, publicTestSeed()...))
		case "service-extension":
			id = "cid10#services.4"
			service := map[string]any{"id": policyDID + "#service", "type": "ExampleService", "serviceEndpoint": "https://agent.example/service"}
			absent["service"] = []any{service}
			present["service"] = []any{map[string]any{"id": policyDID + "#service", "type": "ExampleService", "serviceEndpoint": "https://agent.example/service", "publicNote": map[string]any{"sequence": []any{true, nil, "ordered"}}}}
		case "custom-relationship":
			id = "cid10#verification-relationships.1"
			present["exampleApproval"] = []any{policyDID + "#sign"}
		case "no-context":
			id = "cid10#context-injection.2"
			present = map[string]any{"id": policyDID}
		}
		out = append(out, optionalFixture{Name: name, Statements: []string{id}, Control: optionalRequest(optionalDocument()), Variants: []ConsumptionRequest{optionalRequest(absent), optionalRequest(present)}})
	}
	return out
}
func remainingMaterialFixtures() []libraryDocumentFixture {
	out := []libraryDocumentFixture{}
	for _, f := range remainingFieldFixtures() {
		if f.Name != "secret-jwk" && f.Name != "secret-multibase" {
			continue
		}
		good := f.Variants[1]
		var bad map[string]any
		_ = json.Unmarshal(good.Data, &bad)
		method := bad["verificationMethod"].([]any)[0].(map[string]any)
		field, id := "secretKeyJwk", "cid10#JsonWebKey.11"
		if f.Name == "secret-jwk" {
			method[field] = map[string]any{"kty": 42}
		} else {
			field = "secretKeyMultibase"
			id = "cid10#Multikey.5"
			method[field] = "z0"
		}
		b, _ := json.Marshal(bad)
		out = append(out, libraryDocumentFixture{Name: f.Name + "-shape", Statement: id, Positive: good, Negative: ConsumptionRequest{Data: b, MediaType: "application/did"}})
	}
	return out
}
func appendRemainingFieldCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range remainingFieldFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-fields-" + f.Name, Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			out := optionalCapture{Variants: []ConsumptionCapture{}}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no direct consumer", string(input), out)
			}
			c, e := s.InspectConsumption(ctx, f.Control)
			out.Control = c
			if e != nil {
				return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
			}
			for _, q := range f.Variants {
				c, e := s.InspectConsumption(ctx, q)
				out.Variants = append(out.Variants, c)
				if e != nil {
					return libraryUnavailable(f.Statements, core.Error, e.Error(), string(input), out)
				}
			}
			obs := judgeOptional(f, out, string(input))
			for i := range obs {
				obs[i].Detail += " Additional selected public test fixtures only; secret parameters are the published RFC8032 test vector, not operational secrets. No signer is constructed, and custom relationship/service properties establish acceptance, not authorization or complete extension rules."
			}
			return obs
		}})
	}
	for _, f := range remainingMaterialFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-fields-" + f.Name, Profile: p.Name, Statements: []string{f.Statement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			out := consumerPair{}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return libraryUnavailable([]string{f.Statement}, core.NotSupported, "no direct consumer", string(input), out)
			}
			c, e := s.InspectConsumption(ctx, f.Positive)
			out.Positive = c
			if e != nil {
				return libraryUnavailable([]string{f.Statement}, core.Error, e.Error(), string(input), out)
			}
			c, e = s.InspectConsumption(ctx, f.Negative)
			out.Negative = c
			if e != nil {
				return libraryUnavailable([]string{f.Statement}, core.Error, e.Error(), string(input), out)
			}
			return []core.Observation{judgeLibraryDocument(f, out, string(input))}
		}})
	}
	id := "did11-cr20260305#production.3"
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-fields-substructures", Profile: p.Name, Statements: []string{id}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := typedProductionFixtures()[0]
		input, _ := json.Marshal(q)
		s, ok := target.(TypedProductionSubject)
		if !ok {
			return libraryUnavailable([]string{id}, core.NotSupported, "no typed producer", string(input), nil)
		}
		out, e := s.InspectTypedProduction(ctx, q)
		if e != nil {
			return libraryUnavailable([]string{id}, core.Error, e.Error(), string(input), out)
		}
		o := judgeTypedProduction(out, q, string(input))
		o.Statement = id
		if o.Verdict == core.Fail {
			o.Verdict = core.NotSupported
		}
		o.Detail += " Additional nested substructures permission exercised using a fresh plain JSON producer call; no producer feature obligation or full JSON-LD processing claim."
		return []core.Observation{o}
	}})
}
