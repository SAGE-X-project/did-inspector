package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"time"
)

const typedConsumerStatement = "did11-cr20260305#consumption.1"
const typedConsumerLiteral = `{"id":"did:sage:web:registry.example:agent-1","controller":["did:sage:web:registry.example:controller-a","did:sage:web:registry.example:controller-b"],"verificationMethod":[{"id":"did:sage:web:registry.example:agent-1#sign","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},"expires":"2020-12-21T04:17:47.123456789+09:00","revoked":"2020-12-20T23:59:59.987654321-05:00"}],"text":"quote \" and slash \\ and newline \n","unicode":"한글","integer":9007199254740991,"double":1.5,"wholeDouble":2.0,"boolean":true,"null":null,"list":[-42,"ordered",false,null],"map":{"nested":["value",1.5],"empty":{}},"unknownClock":"2020-12-21T04:17:47.123456789+09:00"}`

func typedConsumptionFixtures() []ConsumptionRequest {
	q := ConsumptionRequest{Data: []byte(typedConsumerLiteral), MediaType: "application/did"}
	doc, _ := core.ParseJSON(q.Data)
	// JSON objects do not guarantee insertion order. A second actual input has
	// reversed root member order while list/set order and values stay unchanged.
	for i, j := 0, len(doc.Object)-1; i < j; i, j = i+1, j-1 {
		doc.Object[i], doc.Object[j] = doc.Object[j], doc.Object[i]
	}
	reversed, _ := doc.MarshalJSON()
	return []ConsumptionRequest{q, {Data: reversed, MediaType: q.MediaType}}
}
func expectedConsumedFields() []TypedMember {
	str := func(s string) TypedValue { return TypedValue{Kind: "string", Text: s} }
	return []TypedMember{
		{"text", str("quote \" and slash \\ and newline \n")}, {"unicode", str("한글")},
		{"integer", TypedValue{Kind: "integer", Text: "9007199254740991"}},
		{"double", TypedValue{Kind: "double", Text: "1.5"}}, {"wholeDouble", TypedValue{Kind: "double", Text: "2"}},
		{"boolean", TypedValue{Kind: "boolean", Flag: true}}, {"null", TypedValue{Kind: "null"}},
		{"list", TypedValue{Kind: "list", Items: []TypedValue{{Kind: "integer", Text: "-42"}, str("ordered"), {Kind: "boolean"}, {Kind: "null"}}}},
		{"map", TypedValue{Kind: "map", Members: []TypedMember{{"nested", TypedValue{Kind: "list", Items: []TypedValue{str("value"), {Kind: "double", Text: "1.5"}}}}, {"empty", TypedValue{Kind: "map"}}}}},
		{"unknownClock", str("2020-12-21T04:17:47.123456789+09:00")},
	}
}
func typedMembersEqual(got, want []TypedMember) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g.Name] {
			return false
		}
		seen[g.Name] = true
		found := false
		for _, w := range want {
			if g.Name == w.Name {
				found = typedValueEqual(g.Value, w.Value)
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func typedValueEqual(g, w TypedValue) bool {
	if g.Kind != w.Kind || g.Text != w.Text || g.Flag != w.Flag || len(g.Items) != len(w.Items) {
		return false
	}
	for i := range w.Items {
		if !typedValueEqual(g.Items[i], w.Items[i]) {
			return false
		}
	}
	return typedMembersEqual(g.Members, w.Members)
}
func sameDatetime(g *TypedValue, w string) bool {
	if g == nil || g.Kind != "datetime" || g.Flag || len(g.Items) > 0 || len(g.Members) > 0 {
		return false
	}
	a, e := time.Parse(time.RFC3339Nano, g.Text)
	b, f := time.Parse(time.RFC3339Nano, w)
	return e == nil && f == nil && a.Equal(b)
}
func knownTypedConsumption(q ConsumptionRequest) bool {
	for _, f := range typedConsumptionFixtures() {
		if reflect.DeepEqual(q, f) {
			return true
		}
	}
	return false
}
func judgeTypedConsumption(out TypedConsumptionResult, q ConsumptionRequest, input string) core.Observation {
	raw, _ := json.Marshal(out)
	obs := core.Observation{Statement: typedConsumerStatement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Selected JSON consumption table values become actual typed map/list/set/datetime/string/integer/double/boolean/null values", Detail: "Direct selected consumer library actor, literal public input, default options and actual returned typed accessors only. Map insertion order is not required; list/controller set order and datetime instants including fractions are checked. Unknown date-looking strings remain strings. Selected safe integers and doubles 1.5/2.0 only; forced double properties without a fraction, full numeric ranges, all property contexts, JSON-LD processing, authority and SAGE resolver/ingress remain unestablished. No subject validator or producer supplies the oracle."}
	if !knownTypedConsumption(q) || !sameConsumerCall(out.Call, q) {
		return obs
	}
	obs.Verdict = core.Fail
	c := out.Call
	if c.Error != "" {
		return obs
	}
	if out.CaptureError != "" || c.CaptureError != "" {
		obs.Verdict = core.Error
		return obs
	}
	if c.Version != "1.1" || c.JSONLD || len(c.DroppedTerms) > 0 {
		return obs
	}
	controllers := []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}
	if out.ID != "did:sage:web:registry.example:agent-1" || out.ControllerShape != "set" || !reflect.DeepEqual(out.Controllers, controllers) || !typedMembersEqual(out.Fields, expectedConsumedFields()) || len(out.Entries) != 0 || len(out.Methods) != 1 {
		return obs
	}
	m := out.Methods[0]
	if m.ID != "did:sage:web:registry.example:agent-1#sign" || !sameDatetime(m.Expires, "2020-12-21T04:17:47.123456789+09:00") || !sameDatetime(m.Revoked, "2020-12-20T23:59:59.987654321-05:00") {
		return obs
	}
	source, e := core.ParseJSON(q.Data)
	model, f := parse(c.Model)
	entries, h := parse(c.Entries)
	if e != nil || f != nil || h != nil || len(entries.Members) != 0 {
		return obs
	}
	// Known datetime entries may be normalized to another equivalent offset.
	// Compare their instant and full fraction, while unknownClock stays a string.
	actual := model.Value()
	if !normalizeConsumedDates(&source) || !normalizeConsumedDates(&actual) {
		return obs
	}
	same, _ := checks.EqualJSON(source, actual)
	if same {
		obs.Verdict = core.Pass
	}
	return obs
}

// normalizeConsumedDates normalizes only the reviewed known datetime paths.
func normalizeConsumedDates(root *core.Value) bool {
	for i := range root.Object {
		if root.Object[i].Name != "verificationMethod" {
			continue
		}
		methods := &root.Object[i].Value
		if methods.Kind != core.KindArray || len(methods.Array) != 1 || methods.Array[0].Kind != core.KindObject {
			return false
		}
		count := 0
		for j := range methods.Array[0].Object {
			m := &methods.Array[0].Object[j]
			if m.Name != "expires" && m.Name != "revoked" {
				continue
			}
			if m.Value.Kind != core.KindString {
				return false
			}
			t, e := time.Parse(time.RFC3339Nano, m.Value.Str)
			if e != nil {
				return false
			}
			m.Value = core.String(t.UTC().Format(time.RFC3339Nano))
			count++
		}
		return count == 2
	}
	return false
}
func appendTypedConsumptionCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for i, q := range typedConsumptionFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-typed-consumption-%d", p.Name, i), Profile: p.Name, Statements: []string{typedConsumerStatement}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(q)
			obs := core.Observation{Statement: typedConsumerStatement, Input: string(input), Verdict: core.NotSupported, Detail: "no actual returned typed consumer boundary"}
			s, ok := target.(TypedConsumptionSubject)
			if !ok {
				return []core.Observation{obs}
			}
			out, e := s.InspectTypedConsumption(ctx, q)
			if e != nil {
				obs.Verdict = core.Error
				obs.Detail = e.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeTypedConsumption(out, q, string(input))}
		}})
	}
}
