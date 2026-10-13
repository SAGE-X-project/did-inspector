package sageprojection

import (
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/did11"
)

type rule struct {
	id, expected string
	check        func(core.DocumentJSON, string) (bool, bool)
}

func rulesFor(name string) []rule {
	prefix := "core10"
	versionKey := "core10"
	if name == did11.Name {
		prefix = "cid10"
		versionKey = "did11-cr20260305"
	}
	add := func(id, want string, fn func(core.DocumentJSON, string) (bool, bool)) rule {
		return rule{prefix + "#" + id, want, fn}
	}
	subjectID := "did-subject.1"
	vmID := "verification-methods.6"
	vmType := "verification-methods.7"
	vmController := "verification-methods.9"
	svcUnique := "services.6"
	svcType := "services.8"
	svcEndpoint := "services.10"
	if name == did11.Name {
		subjectID = "subjects.2"
		vmID = "verification-methods.5"
		vmType = "verification-methods.6"
		vmController = "verification-methods.7"
		svcUnique = "services.7"
		svcType = "services.9"
		svcEndpoint = "services.12"
	}
	out := []rule{
		{versionKey + "#production.2", "a JSON document root object", func(d core.DocumentJSON, _ string) (bool, bool) { _, ok := d.Get("id"); return true, ok }},
		{versionKey + "#production.4", "the selected projection media type", func(_ core.DocumentJSON, mt string) (bool, bool) {
			want := "application/did+json"
			if name == did11.Name {
				want = "application/did"
			}
			return true, mt == want
		}},
		add(subjectID, "a string id in the root map", func(d core.DocumentJSON, _ string) (bool, bool) {
			v, ok := d.Get("id")
			if name == did11.Name {
				return true, ok && v.Kind == core.KindString && checks.IsAbsoluteURI(v.Str)
			}
			return true, ok && v.Kind == core.KindString && checks.IsDID(v.Str)
		}),
		add("verification-methods.2", "verificationMethod is a set of maps", func(d core.DocumentJSON, _ string) (bool, bool) {
			v, ok := d.Get("verificationMethod")
			return ok, maps(v)
		}),
		add("verification-methods.3", "methods include id, type, controller and publicKeyJwk", methodRule(func(v core.Value) bool {
			return stringMember(v, "id") && stringMember(v, "type") && stringMember(v, "controller") && objectMember(v, "publicKeyJwk")
		})),
		add(vmID, "method ids are absolute DID URLs", methodRule(func(v core.Value) bool {
			id, _ := v.Get("id")
			return id.Kind == core.KindString && checks.IsDIDURL(id.Str)
		})),
		add(vmType, "method type is a string", methodRule(func(v core.Value) bool { return stringMember(v, "type") })),
		add(vmController, "method controller is a DID string", methodRule(func(v core.Value) bool {
			x, _ := v.Get("controller")
			return x.Kind == core.KindString && checks.IsDID(x.Str)
		})),
		add("authentication.2", "a present authentication relationship is nonempty", relationshipRule("authentication")),
		add("assertion.2", "a present assertionMethod relationship is nonempty", relationshipRule("assertionMethod")),
		add("key-agreement.2", "a present keyAgreement relationship is nonempty", relationshipRule("keyAgreement")),
		add("services.2", "service is a set of maps", func(d core.DocumentJSON, _ string) (bool, bool) { v, ok := d.Get("service"); return ok, maps(v) }),
		add("services.3", "each service includes id, type and serviceEndpoint", serviceRule(func(v core.Value) bool {
			_, a := v.Get("id")
			_, b := v.Get("type")
			_, c := v.Get("serviceEndpoint")
			return a && b && c
		})),
		add(svcUnique, "no duplicate service identifiers", func(d core.DocumentJSON, _ string) (bool, bool) {
			v, ok := d.Get("service")
			if !ok {
				return false, true
			}
			if !maps(v) {
				return true, false
			}
			seen := map[string]bool{}
			for _, item := range v.Array {
				id, _ := item.Get("id")
				if id.Kind != core.KindString || seen[id.Str] {
					return true, false
				}
				seen[id.Str] = true
			}
			return true, true
		}),
		add(svcType, "service type is a string or a set of strings", serviceRule(func(v core.Value) bool { x, _ := v.Get("type"); return stringsValue(x) })),
		add(svcEndpoint, "serviceEndpoint is a string, map or nonempty set of those", serviceRule(func(v core.Value) bool { x, _ := v.Get("serviceEndpoint"); return endpoint(x) })),
	}
	if name == did11.Name {
		out = append(out,
			rule{versionKey + "#json-ld-processors.4", "the pinned DID 1.1 base context string or first array entry", func(d core.DocumentJSON, _ string) (bool, bool) {
				v, ok := d.Get("@context")
				return true, ok && validContext(v)
			}},
			add("JsonWebKey.1", "verification method type JsonWebKey", methodRule(func(v core.Value) bool {
				x, _ := v.Get("type")
				return x.Kind == core.KindString && x.Str == "JsonWebKey"
			})),
			add("JsonWebKey.4", "public JWK contains no private or secret members", methodRule(func(v core.Value) bool {
				j, ok := v.Get("publicKeyJwk")
				if !ok || j.Kind != core.KindObject {
					return false
				}
				for _, m := range j.Object {
					switch m.Name {
					case "d", "p", "q", "dp", "dq", "qi", "oth", "k":
						return false
					}
				}
				return true
			})),
			add("JsonWebKey.7", "JWK alg is included (recommendation)", methodRule(func(v core.Value) bool { j, _ := v.Get("publicKeyJwk"); return stringMember(j, "alg") })),
			add("JsonWebKey.8", "the represented elliptic curve has a crv string", methodRule(func(v core.Value) bool { j, _ := v.Get("publicKeyJwk"); return stringMember(j, "crv") })),
		)
	}
	return out
}
func maps(v core.Value) bool {
	if v.Kind != core.KindArray || !unique(v.Array) {
		return false
	}
	for _, x := range v.Array {
		if x.Kind != core.KindObject {
			return false
		}
	}
	return true
}
func stringMember(v core.Value, key string) bool {
	x, ok := v.Get(key)
	return ok && x.Kind == core.KindString
}
func objectMember(v core.Value, key string) bool {
	x, ok := v.Get(key)
	return ok && x.Kind == core.KindObject
}
func methodRule(fn func(core.Value) bool) func(core.DocumentJSON, string) (bool, bool) {
	return setRule("verificationMethod", fn)
}
func serviceRule(fn func(core.Value) bool) func(core.DocumentJSON, string) (bool, bool) {
	return setRule("service", fn)
}
func setRule(key string, fn func(core.Value) bool) func(core.DocumentJSON, string) (bool, bool) {
	return func(d core.DocumentJSON, _ string) (bool, bool) {
		v, ok := d.Get(key)
		if !ok {
			return false, true
		}
		if !maps(v) {
			return true, false
		}
		if len(v.Array) == 0 {
			return false, true
		}
		for _, x := range v.Array {
			if !fn(x) {
				return true, false
			}
		}
		return true, true
	}
}
func relationshipRule(key string) func(core.DocumentJSON, string) (bool, bool) {
	return func(d core.DocumentJSON, _ string) (bool, bool) {
		v, ok := d.Get(key)
		if !ok {
			return false, true
		}
		if v.Kind != core.KindArray || len(v.Array) == 0 || !unique(v.Array) {
			return true, false
		}
		for _, x := range v.Array {
			if x.Kind != core.KindObject && (x.Kind != core.KindString || !checks.IsDIDURL(x.Str)) {
				return true, false
			}
		}
		return true, true
	}
}
func stringsValue(v core.Value) bool {
	if v.Kind == core.KindString {
		return true
	}
	if v.Kind != core.KindArray || !unique(v.Array) {
		return false
	}
	for _, x := range v.Array {
		if x.Kind != core.KindString {
			return false
		}
	}
	return true
}
func endpoint(v core.Value) bool {
	if v.Kind == core.KindString || v.Kind == core.KindObject {
		return true
	}
	if v.Kind != core.KindArray || len(v.Array) == 0 || !unique(v.Array) {
		return false
	}
	for _, x := range v.Array {
		if x.Kind != core.KindString && x.Kind != core.KindObject {
			return false
		}
	}
	return true
}
func judge(out Result, name string, rules []rule, input string) []core.Observation {
	d, err := core.ParseDocumentJSON(out.Raw)
	if err != nil {
		return observations(ruleIDs(rules), core.Error, "produced bytes are not a document: "+err.Error())
	}
	dup := checks.DuplicateMembers(d.Value())
	if len(dup) > 0 {
		return observations(ruleIDs(rules), core.Error, fmt.Sprintf("duplicate JSON members: %v", dup))
	}
	obs := make([]core.Observation, 0, len(rules))
	for _, r := range rules {
		applies, ok := r.check(d, out.MediaType)
		v := core.Pass
		if !applies {
			v = core.NotApplicable
		} else if !ok {
			v = core.Fail
		}
		detail := "Produced fixture document only; arbitrary document inputs, network authority and full publication conformance are untested."
		if name == did11.Name && r.id == "cid10#JsonWebKey.7" {
			detail = "SAGE intentionally omits alg; its authoritative record selects the algorithm. This remains a recommendation-level FAIL."
		}
		obs = append(obs, core.Observation{Statement: r.id, Verdict: v, Input: input, Expected: r.expected, Observed: "mediaType=" + out.MediaType + "; document=" + string(out.Raw), Detail: detail})
	}
	return obs
}
func ruleIDs(rules []rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.id
	}
	return out
}

func unique(values []core.Value) bool {
	for i, v := range values {
		for _, old := range values[:i] {
			if eq, _ := checks.EqualJSON(v, old); eq {
				return false
			}
		}
	}
	return true
}
func validContext(v core.Value) bool {
	const base = "https://www.w3.org/ns/did/v1.1"
	if v.Kind == core.KindString {
		return v.Str == base
	}
	return v.Kind == core.KindArray && len(v.Array) > 0 && v.Array[0].Kind == core.KindString && v.Array[0].Str == base
}
