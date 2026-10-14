package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/sage-x-project/did-inspector/core"
)

type optionalFixture struct {
	Name       string               `json:"name"`
	Statements []string             `json:"statements"`
	Control    ConsumptionRequest   `json:"control"`
	Variants   []ConsumptionRequest `json:"variants"`
}
type optionalCapture struct {
	Control  ConsumptionCapture   `json:"control"`
	Variants []ConsumptionCapture `json:"variants"`
}

func optionalDocument() map[string]any {
	var d map[string]any
	_ = json.Unmarshal([]byte(policyBase), &d)
	return d
}
func optionalRequest(d map[string]any) ConsumptionRequest {
	b, _ := json.Marshal(d)
	return ConsumptionRequest{Data: b, MediaType: "application/did"}
}

// Permissions are exercised through explicit valid inputs. These are library
// consumer observations, not assertions that SAGE registry records carry them.
func optionalFixtures() []optionalFixture {
	out := []optionalFixture{}
	for _, row := range []struct{ field, section string }{
		{"authentication", "authentication"}, {"assertionMethod", "assertion"}, {"keyAgreement", "key-agreement"},
		{"capabilityInvocation", "capability-invocation"}, {"capabilityDelegation", "capability-delegation"}} {
		absent := optionalDocument()
		delete(absent, "authentication")
		reference := optionalDocument()
		delete(reference, "authentication")
		reference[row.field] = []any{policyDID + "#sign"}
		embedded := optionalDocument()
		delete(embedded, "authentication")
		method := embedded["verificationMethod"].([]any)[0]
		delete(embedded, "verificationMethod")
		embedded[row.field] = []any{method}
		mixed := optionalDocument()
		delete(mixed, "authentication")
		other := optionalDocument()["verificationMethod"].([]any)[0].(map[string]any)
		other["id"] = policyDID + "#embedded"
		mixed[row.field] = []any{policyDID + "#sign", other}
		out = append(out, optionalFixture{row.field, []string{"cid10#" + row.section + ".1", "cid10#" + row.section + ".3"}, optionalRequest(optionalDocument()), []ConsumptionRequest{optionalRequest(absent), optionalRequest(reference), optionalRequest(embedded), optionalRequest(mixed)}})
	}
	for _, row := range []struct {
		name, id string
		value    any
		method   bool
	}{
		{"controller", "cid10#controllers.1", []any{policyDID}, false},
		{"alsoKnownAs", "cid10#also-known-as.1", []any{"https://agent.example/profile"}, false},
		{"service", "cid10#services.1", []any{map[string]any{"id": policyDID + "#service", "type": "ExampleService", "serviceEndpoint": "https://agent.example/service"}}, false},
		{"verificationMethod", "cid10#verification-methods.1", nil, false},
		{"expires", "cid10#verification-methods.8", "2030-01-01T00:00:00Z", true},
		{"revoked", "cid10#verification-methods.10", "2030-01-01T00:00:00Z", true},
		{"exampleExtra", "cid10#verification-methods.4", map[string]any{"label": "public fixture", "sequence": []any{true, nil, "ordered", 2}}, true}} {
		absent, present := optionalDocument(), optionalDocument()
		if row.method {
			present["verificationMethod"].([]any)[0].(map[string]any)[row.name] = row.value
		} else if row.name == "verificationMethod" {
			delete(absent, "verificationMethod")
			delete(absent, "authentication")
			delete(present, "authentication")
		} else {
			present[row.name] = row.value
		}
		out = append(out, optionalFixture{row.name, []string{row.id}, optionalRequest(optionalDocument()), []ConsumptionRequest{optionalRequest(absent), optionalRequest(present)}})
	}
	return out
}
func optionalPremise(f optionalFixture) bool {
	for _, expected := range append(optionalFixtures(), remainingFieldFixtures()...) {
		if f.Name == expected.Name {
			return reflect.DeepEqual(f, expected)
		}
	}
	return false
}

// A complete, attributable refusal of a permitted literal is a capability finding, not a mandatory-rule violation.
// Missing capture or contradictory partial results remain observer errors.
func optionalAcceptance(q ConsumptionRequest, c ConsumptionCapture) core.Verdict {
	if !sameConsumerCall(c, q) {
		return core.Error
	}
	if c.Error != "" {
		if len(c.Model) > 0 || len(c.Entries) > 0 {
			return core.Error
		}
		return core.NotSupported
	}
	if c.CaptureError != "" || c.Version != "1.1" || c.JSONLD || len(c.DroppedTerms) > 0 {
		return core.Error
	}
	expected, e := parse(q.Data)
	actual, ee := parse(c.Model)
	entries, eee := parse(c.Entries)
	if e != nil || ee != nil || eee != nil {
		return core.Error
	}
	if entries.Len() != 0 || !equalOptionalDocument(expected.Value(), actual.Value()) {
		return core.NotSupported
	}
	return core.Pass
}
func judgeOptional(f optionalFixture, c optionalCapture, input string) []core.Observation {
	raw, _ := json.Marshal(c)
	out := libraryUnavailable(f.Statements, core.Error, "Actual pinned consumer of explicit optional-field and embedded/reference literals. PASS means selected library acceptance and semantic value preservation only; it does not establish SAGE Source field support, authoritative controllers, permission to use a key, proof validation, all extensions or full document conformance. OPTIONAL and MAY do not require fields to be produced. Known DID sets ignore order; extension Lists retain order and value kinds.", input, json.RawMessage(raw))
	if !optionalPremise(f) || len(c.Variants) != len(f.Variants) || optionalAcceptance(f.Control, c.Control) != core.Pass {
		return out
	}
	for i := range out {
		indexes := []int{0, 1}
		if len(f.Statements) == 2 {
			indexes = []int{0}
			if i == 1 {
				indexes = []int{1, 2, 3}
			}
		}
		verdict := core.Pass
		for _, index := range indexes {
			v := optionalAcceptance(f.Variants[index], c.Variants[index])
			if v == core.Error {
				verdict = v
				break
			}
			if v == core.NotSupported {
				verdict = v
			}
		}
		out[i].Verdict = verdict
		out[i].Expected = "Acceptance and preservation of the explicitly permitted absent/present or reference/embedded/mixed literals"
	}
	return out
}
func appendOptionalCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range optionalFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/optional-%s", p.Name, f.Name), Profile: p.Name, Statements: f.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			out := optionalCapture{Variants: []ConsumptionCapture{}}
			s, ok := target.(ConsumptionSubject)
			if !ok {
				return libraryUnavailable(f.Statements, core.NotSupported, "no direct consumer", string(input), out)
			}
			control, e := s.InspectConsumption(ctx, f.Control)
			out.Control = control
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
			return judgeOptional(f, out, string(input))
		}})
	}
}

func equalOptionalDocument(expected, actual core.Value) bool {
	// Fixed date controls may be rendered with another offset for the same instant.
	left, lp := expected.Get("verificationMethod")
	right, rp := actual.Get("verificationMethod")
	if lp && rp && len(left.Array) == 1 && len(right.Array) == 1 {
		for _, field := range []string{"expires", "revoked"} {
			a, ap := left.Array[0].Get(field)
			b, bp := right.Array[0].Get(field)
			if !ap && !bp {
				continue
			}
			if !ap || !bp || a.Kind != core.KindString || b.Kind != core.KindString {
				return false
			}
			t, e := time.Parse(time.RFC3339Nano, a.Str)
			u, err := time.Parse(time.RFC3339Nano, b.Str)
			if e != nil || err != nil || !t.Equal(u) {
				return false
			}
			for i := range right.Array[0].Object {
				if right.Array[0].Object[i].Name == field {
					right.Array[0].Object[i].Value = a
				}
			}
		}
	}
	return equalObserved(expected, actual, "document")
}
