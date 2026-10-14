package sageresolution

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"strings"
)

var nativeKeyRemainingIDs = []string{"cid10#JsonWebKey.5", "cid10#JsonWebKey.6", "cid10#JsonWebKey.9", "cid10#data-model.1", "did11-cr20260305#verification-methods.1"}

func completeSelectedPublicJWK(m core.Value) core.Verdict {
	if m.Kind != core.KindObject {
		return core.Fail
	}
	allowed := map[string]bool{"id": true, "type": true, "controller": true, "publicKeyJwk": true}
	for _, member := range m.Object {
		if !allowed[member.Name] {
			return core.NotSupported
		}
	}
	id, _ := m.Get("id")
	typ, _ := m.Get("type")
	controller, _ := m.Get("controller")
	jwk, has := m.Get("publicKeyJwk")
	if id.Kind != core.KindString || !checks.IsDIDURL(id.Str) || controller.Kind != core.KindString || !checks.IsDID(controller.Str) || typ.Kind != core.KindString {
		return core.Fail
	}
	if typ.Str != "JsonWebKey" || !has {
		return core.NotSupported
	}
	if jwk.Kind != core.KindObject {
		return core.Fail
	}
	for _, member := range jwk.Object {
		switch member.Name {
		case "kty", "crv", "x", "kid", "alg":
		default:
			if contains([]string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "r", "t"}, member.Name) {
				return core.Fail
			}
			return core.NotSupported
		}
	}
	kty, _ := jwk.Get("kty")
	crv, _ := jwk.Get("crv")
	x, _ := jwk.Get("x")
	if kty.Kind != core.KindString || kty.Str != "OKP" || crv.Kind != core.KindString || x.Kind != core.KindString {
		return core.Fail
	}
	if crv.Str != "Ed25519" && crv.Str != "X25519" {
		return core.NotSupported
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(x.Str)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != x.Str {
		return core.Fail
	}
	for _, field := range []string{"kid", "alg"} {
		v, present := jwk.Get(field)
		if present && v.Kind != core.KindString {
			return core.Fail
		}
	}
	// All material alternatives are absent and exactly one public JWK exists;
	// date/secret/extension branches are deliberately outside this selected case.
	return core.Pass
}
func judgeRemainingNativeKeys(out Result, input string) []core.Observation {
	obs := libraryUnavailable(nativeKeyRemainingIDs, core.Error, "Fresh actual SAGE producer output for the public Ed25519/X25519 record, not author-supplied kid literals. Recommendation choices, absent-kid applicability, explicit purpose references and every applicable mandatory member of the selected public OKP JsonWebKey branch are independently checked. Unknown method classes/extensions/dates remain unsupported; no controller authority, private key custody, proof validity, complete datatype/JSON-LD handling or every verification class is established. Existing mandatory date findings and full standard limits remain.", input, out)
	md, e := parse(out.Metadata)
	raw, ee := parse(out.Raw)
	if e != nil || ee != nil || !out.HasContent || out.ContentKind != "document" || out.ReturnedID != policyDID || out.Native != nil || out.Exchange != nil {
		return obs
	}
	if _, failed := md.Get("error"); failed {
		return obs
	}
	methods, has := raw.Get("verificationMethod")
	if !has || methods.Kind != core.KindArray || len(methods.Array) != 2 {
		return obs
	}
	// Independent exact public material controls establish this actor/input scope.
	expected := map[string]string{"sign": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "agree": "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	kidVerdict := core.Pass
	composite := core.Pass
	relationships := core.Pass
	noKid := true
	seen := map[string]bool{}
	for _, m := range methods.Array {
		class := completeSelectedPublicJWK(m)
		id, _ := m.Get("id")
		fragment := strings.TrimPrefix(id.Str, policyDID+"#")
		xWant, known := expected[fragment]
		jwk, _ := m.Get("publicKeyJwk")
		x, _ := jwk.Get("x")
		if class == core.Pass && (!known || x.Str != xWant) {
			class = core.NotSupported // Unknown public points are not validated by a length check.
		}
		if known {
			if seen[fragment] {
				return obs
			}
			seen[fragment] = true
		}
		if class == core.Fail {
			composite = core.Fail
		} else if class == core.NotSupported && composite != core.Fail {
			composite = class
		}
		kid, present := jwk.Get("kid")
		if present {
			noKid = false
		}
		if !present || kid.Kind != core.KindString || kid.Str != fragment {
			kidVerdict = core.Fail
		}
		purpose := "authentication"
		if fragment == "agree" {
			purpose = "keyAgreement"
		}
		refs, ok := raw.Get(purpose)
		bound := false
		if ok && refs.Kind == core.KindArray {
			for _, ref := range refs.Array {
				if ref.Kind == core.KindString && ref.Str == id.Str {
					bound = true
				}
			}
		}
		if !bound {
			relationships = core.Fail
		}
	}
	for i := range obs {
		switch obs[i].Statement {
		case "cid10#JsonWebKey.5":
			obs[i].Verdict = kidVerdict
		case "cid10#JsonWebKey.6", "cid10#JsonWebKey.9":
			obs[i].Verdict = core.NotSupported
			if noKid {
				obs[i].Verdict = core.NotApplicable
				obs[i].Detail += " No actual kid value is present in these two freshly produced JWKs; no thumbprint or hint-id comparison applies. Absence is not evidence of a missing API."
			}
		case "cid10#data-model.1":
			obs[i].Verdict = relationships
		case "did11-cr20260305#verification-methods.1":
			obs[i].Verdict = composite
		}
		obs[i].Expected = "Actual producer kid choice and applicability, purpose binding, and complete selected public OKP method members"
	}
	return obs
}
func appendRemainingNativeKeyCases(p *core.Profile, records []sageprojection.Record) {
	if p.Name != "did-1.1" {
		return
	}
	r := records[0]
	p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/remaining-native-keys", Profile: p.Name, Statements: nativeKeyRemainingIDs, Run: func(ctx context.Context, target core.Subject) []core.Observation {
		q := Request{Function: "resolve", Input: r.DID, Accept: "application/did"}
		input, _ := json.Marshal(struct {
			Record  sageprojection.Record `json:"record"`
			Request Request               `json:"request"`
		}{r, q})
		s, ok := target.(Subject)
		if !ok {
			return libraryUnavailable(nativeKeyRemainingIDs, core.NotSupported, "no SAGE native operation", string(input), nil)
		}
		out, e := s.InspectResolution(ctx, r, q)
		if e != nil {
			return libraryUnavailable(nativeKeyRemainingIDs, core.Error, e.Error(), string(input), out)
		}
		return judgeRemainingNativeKeys(out, string(input))
	}})
}
