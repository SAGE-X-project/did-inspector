package sageresolution

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
)

// These are local consumer model inputs, not published DID documents. The
// secret parameter is the already published RFC8032 vector; no signer is used.
func choiceOptionalFixtures() []optionalFixture {
	var ed codecFixture
	for _, f := range codecFixtures() {
		if f.Name == "Ed25519" && !f.Secret {
			ed = f
		}
	}
	public, local := optionalDocument(), optionalDocument()
	a := public["verificationMethod"].([]any)[0].(map[string]any)
	b := local["verificationMethod"].([]any)[0].(map[string]any)
	for _, m := range []map[string]any{a, b} {
		m["type"] = "Multikey"
		delete(m, "publicKeyJwk")
	}
	a["publicKeyMultibase"] = codecRequests(ed)[0].Encoded
	b["secretKeyMultibase"] = btcEncode(append([]byte{0x80, 0x26}, publicTestSeed()...))
	control := optionalRequest(public)
	return []optionalFixture{{Name: "public-multibase-local-model", Statements: []string{"cid10#Multikey.2"}, Control: control, Variants: []ConsumptionRequest{control, optionalRequest(local)}}}
}
func appendChoiceOptionalCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range choiceOptionalFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/choice-optional-" + f.Name, Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			out := optionalCapture{Variants: []ConsumptionCapture{}}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no local consumer observer", string(input), out)
			}
			c, err := s.InspectConsumption(ctx, f.Control)
			out.Control = c
			if err != nil {
				return libraryUnavailable(f.Statements, core.Error, err.Error(), string(input), out)
			}
			for _, q := range f.Variants {
				c, err := s.InspectConsumption(ctx, q)
				out.Variants = append(out.Variants, c)
				if err != nil {
					return libraryUnavailable(f.Statements, core.Error, err.Error(), string(input), out)
				}
			}
			obs := judgeOptional(f, out, string(input))
			for i := range obs {
				obs[i].Detail += " Public Multikey and public RFC8032 secret-only local model controls exercise the OPTIONAL public field. This does not publish secret material, authorize verification, claim that every material-free method is valid, or treat a consumer choice as a standards erratum."
			}
			return obs
		}})
	}
}
