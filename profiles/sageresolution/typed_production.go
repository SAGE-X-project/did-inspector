package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

func typedProductionFixtures() []TypedProductionRequest {
	stringValue := func(s string) TypedValue { return TypedValue{Kind: "string", Text: s} }
	fields := []TypedMember{
		{"text", stringValue("quote \" and slash \\ and newline \n")}, {"unicode", stringValue("한글")},
		{"integer", TypedValue{Kind: "integer", Text: "9007199254740991"}},
		{"double", TypedValue{Kind: "double", Text: "1.5"}}, {"wholeDouble", TypedValue{Kind: "double", Text: "2"}},
		{"boolean", TypedValue{Kind: "boolean", Flag: true}}, {"null", TypedValue{Kind: "null"}},
		{"list", TypedValue{Kind: "list", Items: []TypedValue{{Kind: "integer", Text: "-42"}, stringValue("ordered"), {Kind: "boolean"}, {Kind: "null"}}}},
		{"map", TypedValue{Kind: "map", Members: []TypedMember{{"nested", TypedValue{Kind: "list", Items: []TypedValue{stringValue("value"), {Kind: "double", Text: "1.5"}}}}, {"empty", TypedValue{Kind: "map"}}}}},
		{"clock", TypedValue{Kind: "datetime", Text: "2020-12-21T04:17:47.123456789+09:00"}},
		{"otherClock", TypedValue{Kind: "datetime", Text: "2020-12-20T23:59:59.987654321-05:00"}},
	}
	entries := []TypedMember{{"representationNote", TypedValue{Kind: "map", Members: []TypedMember{{"note", stringValue("retained")}, {"flag", TypedValue{Kind: "boolean", Flag: true}}}}}}
	q := TypedProductionRequest{ID: "did:sage:web:registry.example:agent-1", Controllers: []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}, Fields: fields, Entries: entries}
	ld := q
	ld.JSONLD = true
	return []TypedProductionRequest{q, ld}
}
func typedJSON(v TypedValue, normalizeDate bool) (core.Value, error) {
	switch v.Kind {
	case "string":
		return core.String(v.Text), nil
	case "integer":
		n, e := strconv.ParseInt(v.Text, 10, 64)
		if e != nil || n < -9007199254740991 || n > 9007199254740991 {
			return core.Value{}, fmt.Errorf("unsupported integer fixture")
		}
		return core.Number(strconv.FormatInt(n, 10)), nil
	case "double":
		if v.Text != "1.5" && v.Text != "2" {
			return core.Value{}, fmt.Errorf("unsupported double fixture")
		}
		text := v.Text
		if text == "2" {
			text = "2.0"
		}
		return core.Number(text), nil
	case "boolean":
		return core.Bool(v.Flag), nil
	case "null":
		return core.Null(), nil
	case "datetime":
		t, e := time.Parse(time.RFC3339Nano, v.Text)
		if e != nil {
			return core.Value{}, e
		}
		if normalizeDate {
			return core.String(t.UTC().Format(time.RFC3339)), nil
		}
		return core.String(t.Format(time.RFC3339Nano)), nil
	case "list":
		items := []core.Value{}
		for _, item := range v.Items {
			x, e := typedJSON(item, normalizeDate)
			if e != nil {
				return core.Value{}, e
			}
			items = append(items, x)
		}
		return core.Array(items...), nil
	case "map":
		return typedMap(v.Members, normalizeDate)
	}
	return core.Value{}, fmt.Errorf("unsupported fixture type")
}
func typedMap(fields []TypedMember, normalizeDate bool) (core.Value, error) {
	members := []core.Member{}
	for _, m := range fields {
		value, e := typedJSON(m.Value, normalizeDate)
		if e != nil {
			return core.Value{}, e
		}
		members = append(members, core.M(m.Name, value))
	}
	value := core.Object(members...)
	if len(checks.DuplicateMembers(value)) > 0 {
		return value, fmt.Errorf("duplicate fixture map")
	}
	return value, nil
}
func typedExpected(q TypedProductionRequest, normalizeDate, wire bool) (core.Value, error) {
	model, e := typedMap(q.Fields, normalizeDate)
	if e != nil {
		return model, e
	}
	entries, e := typedMap(q.Entries, normalizeDate)
	if e != nil {
		return entries, e
	}
	controllers := []core.Value{}
	for _, c := range q.Controllers {
		controllers = append(controllers, core.String(c))
	}
	members := []core.Member{core.M("id", core.String(q.ID)), core.M("controller", core.Array(controllers...))}
	members = append(members, model.Object...)
	if wire {
		members = append(members, entries.Object...)
		if q.JSONLD {
			members = append(members, core.M("@context", core.String(did11Context)))
		}
	}
	value := core.Object(members...)
	if len(checks.DuplicateMembers(value)) > 0 {
		return value, fmt.Errorf("overlapping fixture entries")
	}
	return value, nil
}

// typedOutputEqual compares number lexical categories as well as JSON values.
// Thus an integer written as 42.0 or an integral double written as 2 fails.
func typedOutputEqual(got, want core.Value) bool {
	equal, _ := checks.EqualJSON(got, want)
	if !equal {
		return false
	}
	switch want.Kind {
	case core.KindNumber:
		expectedDouble := strings.Contains(want.Number, ".")
		return expectedDouble == strings.Contains(got.Number, ".")
	case core.KindObject:
		for _, m := range want.Object {
			v, _ := got.Get(m.Name)
			if !typedOutputEqual(v, m.Value) {
				return false
			}
		}
	case core.KindArray:
		for i, v := range want.Array {
			if !typedOutputEqual(got.Array[i], v) {
				return false
			}
		}
	}
	return true
}
func knownTypedFixture(q TypedProductionRequest) bool {
	for _, fixture := range typedProductionFixtures() {
		if reflect.DeepEqual(q, fixture) {
			return true
		}
	}
	return false
}
func judgeTypedProduction(out TypedProductionResult, q TypedProductionRequest, input string) core.Observation {
	id := "did11-cr20260305#production.1"
	if q.JSONLD {
		id = "did11-cr20260305#json-ld-processors.2"
	}
	raw, _ := json.Marshal(out)
	obs := core.Observation{Statement: id, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Selected actual typed map/list/set/datetime/string/integer/double/boolean/null values follow the pinned JSON production table", Detail: "Direct producer selected by SAGE integration. Actual pre-producer typed witnesses, separate maps, options and return bytes are archived. Selected Unicode/escape strings, safe integers, doubles 1.5/2, datetime offsets with fractions, nested lists/maps and an ordered controller set only. Full value ranges, every contextual property conversion, JSON-LD term semantics, remote contexts, authority and SAGE resolver/ingress remain unestablished. No consumer, subject validator or post-consumption snapshot supplies the expected document."}
	if !knownTypedFixture(q) || out.BuildError != "" || out.CaptureError != "" || len(out.Calls) != 1 {
		return obs
	}
	if out.ID != q.ID || out.ControllerShape != "set" || !reflect.DeepEqual(out.Controllers, q.Controllers) || !reflect.DeepEqual(out.Fields, q.Fields) || !reflect.DeepEqual(out.Entries, q.Entries) {
		return obs
	}
	p := out.Calls[0]
	if p.Operation != pipelineProducer || p.Version != "1.1" || p.JSONLD != q.JSONLD || p.IncludeSecret || p.CaptureError != "" {
		return obs
	}
	model, em := parse(p.Model)
	entries, ee := parse(p.Entries)
	wantModel, e1 := typedExpected(q, false, false)
	wantEntries, e2 := typedMap(q.Entries, false)
	if em != nil || ee != nil || e1 != nil || e2 != nil || !typedOutputEqual(model.Value(), wantModel) || !typedOutputEqual(entries.Value(), wantEntries) {
		return obs
	}
	want, e := typedExpected(q, true, true)
	if e != nil {
		return obs
	}
	obs.Verdict = core.Fail
	if p.Error != "" || !pipelineMedia(p.MediaType) {
		return obs
	}
	got, e := core.ParseJSON(p.Output)
	if e == nil && len(checks.DuplicateMembers(got)) == 0 && typedOutputEqual(got, want) {
		obs.Verdict = core.Pass
	}
	return obs
}
func appendTypedProductionCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for i, q := range typedProductionFixtures() {
		id := "did11-cr20260305#production.1"
		if q.JSONLD {
			id = "did11-cr20260305#json-ld-processors.2"
		}
		p.Cases = append(p.Cases, core.Case{ID: fmt.Sprintf("%s/sage-resolution/native-typed-production-%d", p.Name, i), Profile: p.Name, Statements: []string{id}, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(q)
			obs := core.Observation{Statement: id, Input: string(input), Verdict: core.NotSupported, Detail: "no actual typed producer input boundary"}
			s, ok := target.(TypedProductionSubject)
			if !ok {
				return []core.Observation{obs}
			}
			out, e := s.InspectTypedProduction(ctx, q)
			if e != nil {
				obs.Verdict = core.Error
				obs.Detail = e.Error()
				return []core.Observation{obs}
			}
			return []core.Observation{judgeTypedProduction(out, q, string(input))}
		}})
	}
}
