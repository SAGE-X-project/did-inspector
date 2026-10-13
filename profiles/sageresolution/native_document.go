package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
)

type nativeRule struct {
	id, expected string
	check        func(core.DocumentJSON) (bool, bool)
	supported    func(core.DocumentJSON) bool
}

// Native rules judge newly observed accessor values. They do not reuse a
// projection verdict or subject validator. Representation production clauses
// and cryptographic material validation are not part of this rule suite.
func nativeDocumentRules(name string) []nativeRule {
	prefix, subject, methodID, methodType, controller := "core10#", "did-subject.1", "verification-methods.6", "verification-methods.7", "verification-methods.9"
	serviceType, endpoint := "services.8", "services.10"
	legacy := name == "did-core-1.0"
	if !legacy {
		prefix, subject, methodID, methodType, controller = "cid10#", "subjects.2", "verification-methods.5", "verification-methods.6", "verification-methods.7"
		serviceType, endpoint = "services.9", "services.12"
	}
	rule := func(id, want string, fn func(core.DocumentJSON) (bool, bool)) nativeRule {
		return nativeRule{id: prefix + id, expected: want, check: fn}
	}
	identifier := func(value core.Value, method bool) bool {
		if value.Kind != core.KindString {
			return false
		}
		if method {
			return checks.IsDIDURL(value.Str)
		}
		return checks.IsDID(value.Str)
	}
	fields := []nativeRule{
		rule(subject, "id exists in the root map; Core 1.0 also requires DID syntax", func(d core.DocumentJSON) (bool, bool) {
			v, ok := d.Get("id")
			if !legacy {
				return true, ok
			}
			return true, ok && identifier(v, false)
		}),
		rule("verification-methods.2", "verificationMethod is a set of maps", nativeMapSet("verificationMethod")),
		rule("verification-methods.3", "selected JWK method includes id, type, controller and publicKeyJwk map (field shape only)", nativeEach("verificationMethod", func(v core.Value) bool {
			return nativeString(v, "id") && nativeString(v, "type") && nativeString(v, "controller") && (!knownNativeJWK(v) || nativeObject(v, "publicKeyJwk"))
		})),
		rule(methodID, "method id is an absolute identifier; selected ASCII URI syntax only for CID", nativeEach("verificationMethod", func(v core.Value) bool { x, _ := v.Get("id"); return identifier(x, true) })),
		rule(methodType, "method type is one nonempty string", nativeEach("verificationMethod", func(v core.Value) bool { x, _ := v.Get("type"); return x.Kind == core.KindString && x.Str != "" })),
		rule(controller, "controller is a DID (Core 1.0) or selected ASCII URI (CID)", nativeEach("verificationMethod", func(v core.Value) bool { x, _ := v.Get("controller"); return identifier(x, false) })),
		rule("authentication.2", "present authentication is a nonempty verification relationship set", nativeRelationship("authentication")),
		rule("assertion.2", "present assertionMethod is a nonempty verification relationship set", nativeRelationship("assertionMethod")),
		rule("key-agreement.2", "present keyAgreement is a nonempty verification relationship set", nativeRelationship("keyAgreement")),
		rule("services.2", "service is a set of maps", nativeMapSet("service")),
		rule(serviceType, "service type is a string or a set of strings", nativeEach("service", func(v core.Value) bool { x, ok := v.Get("type"); return ok && nativeStrings(x) })),
		rule(endpoint, "serviceEndpoint is a string, map or nonempty set of strings/maps", nativeEach("service", func(v core.Value) bool { x, ok := v.Get("serviceEndpoint"); return ok && nativeEndpoint(x) })),
	}
	if legacy {
		fields = append(fields, rule("services.3", "each service contains id, type and serviceEndpoint", nativeEach("service", func(v core.Value) bool {
			_, a := v.Get("id")
			_, b := v.Get("type")
			_, c := v.Get("serviceEndpoint")
			return a && b && c
		})))
	} else {
		fields = append(fields,
			rule("services.8", "service type property is present", nativeEach("service", func(v core.Value) bool { _, ok := v.Get("type"); return ok })),
			rule("services.11", "serviceEndpoint property is present", nativeEach("service", func(v core.Value) bool { _, ok := v.Get("serviceEndpoint"); return ok })),
			rule("services.7", "services with present id properties have no duplicate ids", func(d core.DocumentJSON) (bool, bool) {
				v, ok := d.Get("service")
				if !ok {
					return false, true
				}
				if !nativeMaps(v) {
					return true, false
				}
				seen := []core.Value{}
				for _, s := range v.Array {
					if id, present := s.Get("id"); present {
						for _, previous := range seen {
							if same, _ := checks.EqualJSON(id, previous); same {
								return true, false
							}
						}
						seen = append(seen, id)
					}
				}
				return true, true
			}),
		)
	}
	kept := fields[:0]
	for _, field := range fields {
		// General URI syntax does not establish the URL Standard clauses.
		if !legacy && (field.id == "cid10#verification-methods.5" || field.id == "cid10#verification-methods.7") {
			continue
		}
		if strings.HasSuffix(field.id, "#verification-methods.3") || field.id == prefix+methodType {
			field.supported = nativeKnownMethods
		}
		for _, key := range []string{"authentication", "assertionMethod", "keyAgreement"} {
			suffix := map[string]string{"authentication": "authentication.2", "assertionMethod": "assertion.2", "keyAgreement": "key-agreement.2"}[key]
			if field.id == prefix+suffix {
				field.supported = func(d core.DocumentJSON) bool { return nativeKnownRelationship(d, key) }
			}
		}
		kept = append(kept, field)
	}
	return kept
}
func nativeString(v core.Value, key string) bool {
	x, ok := v.Get(key)
	return ok && x.Kind == core.KindString
}
func nativeObject(v core.Value, key string) bool {
	x, ok := v.Get(key)
	return ok && x.Kind == core.KindObject
}
func nativeUnique(a []core.Value) bool {
	for i, v := range a {
		for _, old := range a[:i] {
			if same, _ := checks.EqualJSON(v, old); same {
				return false
			}
		}
	}
	return true
}
func nativeMaps(v core.Value) bool {
	if v.Kind != core.KindArray || !nativeUnique(v.Array) {
		return false
	}
	for _, item := range v.Array {
		if item.Kind != core.KindObject {
			return false
		}
	}
	return true
}
func nativeMapSet(key string) func(core.DocumentJSON) (bool, bool) {
	return func(d core.DocumentJSON) (bool, bool) { v, ok := d.Get(key); return ok, !ok || nativeMaps(v) }
}
func nativeEach(key string, fn func(core.Value) bool) func(core.DocumentJSON) (bool, bool) {
	return func(d core.DocumentJSON) (bool, bool) {
		v, ok := d.Get(key)
		if !ok {
			return false, true
		}
		if !nativeMaps(v) {
			return true, false
		}
		if len(v.Array) == 0 {
			return false, true
		}
		for _, item := range v.Array {
			if !fn(item) {
				return true, false
			}
		}
		return true, true
	}
}
func nativeRelationship(key string) func(core.DocumentJSON) (bool, bool) {
	return func(d core.DocumentJSON) (bool, bool) {
		v, ok := d.Get(key)
		if !ok {
			return false, true
		}
		if v.Kind != core.KindArray || len(v.Array) == 0 || !nativeUnique(v.Array) {
			return true, false
		}
		for _, item := range v.Array {
			if item.Kind == core.KindObject {
				if !nativeString(item, "id") || !nativeString(item, "type") || !nativeString(item, "controller") || (knownNativeJWK(item) && !nativeObject(item, "publicKeyJwk")) {
					return true, false
				}
			} else if item.Kind != core.KindString || (strings.HasPrefix(item.Str, "did:") && !checks.IsDIDURL(item.Str)) {
				return true, false
			}
		}
		return true, true
	}
}
func nativeStrings(v core.Value) bool {
	if v.Kind == core.KindString {
		return true
	}
	if v.Kind != core.KindArray || !nativeUnique(v.Array) {
		return false
	}
	for _, item := range v.Array {
		if item.Kind != core.KindString {
			return false
		}
	}
	return true
}
func nativeEndpoint(v core.Value) bool {
	if v.Kind == core.KindString || v.Kind == core.KindObject {
		return true
	}
	if v.Kind != core.KindArray || len(v.Array) == 0 || !nativeUnique(v.Array) {
		return false
	}
	for _, item := range v.Array {
		if item.Kind != core.KindString && item.Kind != core.KindObject {
			return false
		}
	}
	return true
}

func judgeNativeDocument(o Result, name string, input string) []core.Observation {
	rules := nativeDocumentRules(name)
	ids := make([]string, len(rules))
	for i, rule := range rules {
		ids[i] = rule.id
	}
	fail := func(detail string) []core.Observation {
		obs := unavailable(ids, core.Error, detail)
		for i := range obs {
			obs[i].Input = input
		}
		return obs
	}
	md, err := parse(o.Metadata)
	if err != nil {
		return fail(err.Error())
	}
	if !o.HasContent || o.ContentKind != "document" {
		return fail("no returned native document to inspect")
	}
	if _, failed := md.Get("error"); failed {
		return fail("native resolver returned an error")
	}
	if name == "did-1.1" {
		mt, _ := md.Get("contentType")
		if mt.Kind != core.KindString || checks.MediaTypeEssence(mt.Str) != "application/did" {
			return fail("DID 1.1 inspection requires actual application/did resolution")
		}
	}
	d, err := parse(o.Snapshot)
	if err != nil {
		return fail(err.Error())
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return fail(err.Error())
	}
	out := make([]core.Observation, 0, len(rules))
	for _, rule := range rules {
		applies, pass := rule.check(d)
		verdict := core.Pass
		if !applies {
			verdict = core.NotApplicable
		} else if rule.supported != nil && !rule.supported(d) {
			verdict = core.NotSupported
		} else if !pass {
			verdict = core.Fail
		}
		out = append(out, core.Observation{Statement: rule.id, Verdict: verdict, Input: input, Expected: rule.expected, Observed: string(raw), Detail: "Actual native accessor snapshot only. Selected JWK field/set syntax and DID references only; unknown material types or reference forms are not judged. Full verification material semantics, general URL Standard parsing, external references, service operation and authority are untested. No projection verdict is reused."})
	}
	return out
}
func appendNativeDocumentCases(p *core.Profile, rows []sageprojection.Record) {
	name := p.Name
	for i, record := range rows {
		if record.State == "deactivated" {
			continue
		}
		q := Request{Function: "resolve10", Input: record.DID}
		if name == "did-1.1" {
			q.Function = "resolve"
			q.Accept = "application/did"
		}
		rules := nativeDocumentRules(name)
		ids := make([]string, len(rules))
		for j, rule := range rules {
			ids[j] = rule.id
		}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-document-record-%d", name, i), Profile: name, Statements: ids, Run: func(ctx context.Context, s core.Subject) []core.Observation {
			input, _ := json.Marshal(struct {
				Record  sageprojection.Record `json:"record"`
				Request Request               `json:"request"`
			}{record, q})
			target, ok := s.(Subject)
			if !ok {
				obs := unavailable(ids, core.NotSupported, "no native resolution operation")
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			result, err := target.InspectResolution(ctx, record, q)
			if err != nil {
				obs := unavailable(ids, core.Error, err.Error())
				for i := range obs {
					obs[i].Input = string(input)
				}
				return obs
			}
			return judgeNativeDocument(result, name, string(input))
		}})
	}
}

func knownNativeJWK(v core.Value) bool {
	typ, _ := v.Get("type")
	return typ.Kind == core.KindString && (typ.Str == "JsonWebKey" || typ.Str == "JsonWebKey2020")
}
func nativeKnownMethods(d core.DocumentJSON) bool {
	methods, present := d.Get("verificationMethod")
	if !present || !nativeMaps(methods) {
		return true
	}
	for _, method := range methods.Array {
		typ, _ := method.Get("type")
		if typ.Kind == core.KindString && typ.Str != "" && !knownNativeJWK(method) {
			return false
		}
	}
	return true
}
func nativeKnownRelationship(d core.DocumentJSON, key string) bool {
	items, present := d.Get(key)
	if !present || items.Kind != core.KindArray {
		return true
	}
	for _, item := range items.Array {
		if item.Kind == core.KindString && !strings.HasPrefix(item.Str, "did:") {
			return false
		}
		if item.Kind == core.KindObject {
			typ, _ := item.Get("type")
			if typ.Kind == core.KindString && typ.Str != "" && !knownNativeJWK(item) {
				return false
			}
		}
	}
	return true
}
