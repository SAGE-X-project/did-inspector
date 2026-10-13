package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
	"testing"
)

func consumerTypedGood(q ConsumptionRequest) TypedConsumptionResult {
	return TypedConsumptionResult{Call: ConsumptionCapture{Operation: pipelineConsumer, Input: q.Data, MediaType: q.MediaType, Require: "unknown", Expected: "unknown", Version: "1.1", Model: q.Data, Entries: []byte(`{}`)}, ID: "did:sage:web:registry.example:agent-1", ControllerShape: "set", Controllers: []string{"did:sage:web:registry.example:controller-a", "did:sage:web:registry.example:controller-b"}, Fields: expectedConsumedFields(), Entries: []TypedMember{}, Methods: []ConsumedMethod{{ID: "did:sage:web:registry.example:agent-1#sign", Expires: &TypedValue{Kind: "datetime", Text: "2020-12-21T04:17:47.123456789+09:00"}, Revoked: &TypedValue{Kind: "datetime", Text: "2020-12-20T23:59:59.987654321-05:00"}}}}
}
func TestTypedConsumptionRequiresActualKindsAndValues(t *testing.T) {
	for _, q := range typedConsumptionFixtures() {
		if o := judgeTypedConsumption(consumerTypedGood(q), q, "input"); o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
	changes := []struct {
		name    string
		verdict core.Verdict
		change  func(*TypedConsumptionResult)
	}{
		{"adapter-capture", core.Error, func(r *TypedConsumptionResult) { r.CaptureError = "unavailable" }},
		{"call-capture", core.Error, func(r *TypedConsumptionResult) { r.Call.CaptureError = "unavailable" }},
		{"operation", core.Error, func(r *TypedConsumptionResult) { r.Call.Operation = "fake" }},
		{"input", core.Error, func(r *TypedConsumptionResult) { r.Call.Input = []byte(`{}`) }},
		{"media", core.Error, func(r *TypedConsumptionResult) { r.Call.MediaType = "application/did+json" }},
		{"require", core.Error, func(r *TypedConsumptionResult) { r.Call.Require = "1.1" }},
		{"expected", core.Error, func(r *TypedConsumptionResult) { r.Call.Expected = "1.1" }},
		{"strict", core.Error, func(r *TypedConsumptionResult) { r.Call.Strict = true }},
		{"consumer-error", core.Fail, func(r *TypedConsumptionResult) { r.Call.Error = "rejected" }},
		{"version", core.Fail, func(r *TypedConsumptionResult) { r.Call.Version = "1.0" }},
		{"jsonld", core.Fail, func(r *TypedConsumptionResult) { r.Call.JSONLD = true }},
		{"dropped", core.Fail, func(r *TypedConsumptionResult) { r.Call.DroppedTerms = []string{"text"} }},
		{"id", core.Fail, func(r *TypedConsumptionResult) { r.ID = "other" }},
		{"set-shape", core.Fail, func(r *TypedConsumptionResult) { r.ControllerShape = "list" }},
		{"set-order", core.Fail, func(r *TypedConsumptionResult) {
			r.Controllers[0], r.Controllers[1] = r.Controllers[1], r.Controllers[0]
		}},
		{"string", core.Fail, func(r *TypedConsumptionResult) { r.Fields[0].Value.Text = "changed" }},
		{"unicode", core.Fail, func(r *TypedConsumptionResult) { r.Fields[1].Value.Text = "changed" }},
		{"integer-kind", core.Fail, func(r *TypedConsumptionResult) { r.Fields[2].Value.Kind = "double" }},
		{"double-kind", core.Fail, func(r *TypedConsumptionResult) { r.Fields[4].Value.Kind = "integer" }},
		{"double-value", core.Fail, func(r *TypedConsumptionResult) { r.Fields[3].Value.Text = "2" }},
		{"boolean", core.Fail, func(r *TypedConsumptionResult) { r.Fields[5].Value.Flag = false }},
		{"null", core.Fail, func(r *TypedConsumptionResult) { r.Fields[6].Value.Kind = "string" }},
		{"list-order", core.Fail, func(r *TypedConsumptionResult) {
			r.Fields[7].Value.Items[0], r.Fields[7].Value.Items[1] = r.Fields[7].Value.Items[1], r.Fields[7].Value.Items[0]
		}},
		{"nested-map", core.Fail, func(r *TypedConsumptionResult) { r.Fields[8].Value.Members[0].Value.Items[0].Text = "changed" }},
		{"unknown-date-kind", core.Fail, func(r *TypedConsumptionResult) { r.Fields[9].Value.Kind = "datetime" }},
		{"extra-field", core.Fail, func(r *TypedConsumptionResult) { r.Fields = append(r.Fields, TypedMember{Name: "extra"}) }},
		{"duplicate-field", core.Fail, func(r *TypedConsumptionResult) { r.Fields[1] = r.Fields[0] }},
		{"representation-leak", core.Fail, func(r *TypedConsumptionResult) { r.Entries = []TypedMember{r.Fields[0]} }},
		{"method-count", core.Fail, func(r *TypedConsumptionResult) { r.Methods = nil }},
		{"method-id", core.Fail, func(r *TypedConsumptionResult) { r.Methods[0].ID = "other" }},
		{"date-kind", core.Fail, func(r *TypedConsumptionResult) { r.Methods[0].Expires.Kind = "string" }},
		{"date-fraction-loss", core.Fail, func(r *TypedConsumptionResult) { r.Methods[0].Expires.Text = "2020-12-21T04:17:47+09:00" }},
		{"date-offset-loss", core.Fail, func(r *TypedConsumptionResult) { r.Methods[0].Revoked.Text = "2020-12-20T23:59:59.987654321Z" }},
		{"nil-date", core.Fail, func(r *TypedConsumptionResult) { r.Methods[0].Expires = nil }},
		{"bad-model", core.Fail, func(r *TypedConsumptionResult) { r.Call.Model = []byte(`{`) }},
		{"missing-model", core.Fail, func(r *TypedConsumptionResult) { r.Call.Model = []byte(`{}`) }},
		{"bad-entries", core.Fail, func(r *TypedConsumptionResult) { r.Call.Entries = []byte(`{`) }},
		{"wrong-entries", core.Fail, func(r *TypedConsumptionResult) { r.Call.Entries = []byte(`{"extra":true}`) }},
	}
	q := typedConsumptionFixtures()[0]
	for _, tt := range changes {
		t.Run(tt.name, func(t *testing.T) {
			r := consumerTypedGood(q)
			tt.change(&r)
			if o := judgeTypedConsumption(r, q, "input"); o.Verdict != tt.verdict {
				t.Fatal(o)
			}
		})
	}
	q.Data = []byte(`{"id":"did:sage:web:registry.example:agent-1"}`)
	if o := judgeTypedConsumption(consumerTypedGood(q), q, "input"); o.Verdict != core.Error {
		t.Fatal("incomplete fixture promoted", o)
	}
}
func TestTypedConsumerMapOrderAndDatetimeInstant(t *testing.T) {
	q := typedConsumptionFixtures()[0]
	r := consumerTypedGood(q)
	r.Fields[0], r.Fields[1] = r.Fields[1], r.Fields[0]
	r.Fields[8].Value.Members[0], r.Fields[8].Value.Members[1] = r.Fields[8].Value.Members[1], r.Fields[8].Value.Members[0]
	r.Methods[0].Expires.Text = "2020-12-20T19:17:47.123456789Z"
	r.Call.Model = []byte(strings.ReplaceAll(string(q.Data), "2020-12-21T04:17:47.123456789+09:00", "2020-12-20T19:17:47.123456789Z"))
	// Only the known method date may change lexical offset; unknownClock must not.
	r.Call.Model = []byte(strings.Replace(string(r.Call.Model), `"unknownClock":"2020-12-20T19:17:47.123456789Z"`, `"unknownClock":"2020-12-21T04:17:47.123456789+09:00"`, 1))
	if o := judgeTypedConsumption(r, q, "input"); o.Verdict != core.Pass {
		t.Fatal(o)
	}
	for _, v := range []*TypedValue{nil, {Kind: "string"}, {Kind: "datetime", Text: "bad"}, {Kind: "datetime", Text: "2020-12-20T19:17:47Z", Flag: true}, {Kind: "datetime", Text: "2020-12-20T19:17:47Z", Items: []TypedValue{{Kind: "null"}}}} {
		if sameDatetime(v, "2020-12-20T19:17:47Z") {
			t.Fatal(v)
		}
	}
	if sameDatetime(&TypedValue{Kind: "datetime", Text: "2020-12-20T19:17:47Z"}, "bad") {
		t.Fatal("bad expected date")
	}
	if typedValueEqual(TypedValue{Kind: "list", Items: []TypedValue{{Kind: "null"}}}, TypedValue{Kind: "list"}) {
		t.Fatal("list size")
	}
}

type typedConsumerOnly struct{ err bool }

func (typedConsumerOnly) Describe() core.SubjectInfo            { return core.SubjectInfo{Name: "unit"} }
func (typedConsumerOnly) Supports(string, core.Capability) bool { return false }
func (s typedConsumerOnly) InspectTypedConsumption(_ context.Context, q ConsumptionRequest) (TypedConsumptionResult, error) {
	if s.err {
		return TypedConsumptionResult{}, errors.New("unavailable")
	}
	return consumerTypedGood(q), nil
}
func TestTypedConsumerOptionalOperationAndScope(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendTypedConsumptionCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("legacy promoted")
	}
	p.Name = "did-1.1"
	appendTypedConsumptionCases(&p)
	if len(p.Cases) != 2 {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, s := range []core.Subject{noOperation{}, typedConsumerOnly{err: true}, typedConsumerOnly{}} {
			o := c.Run(t.Context(), s)[0]
			want := core.Pass
			if _, ok := s.(noOperation); ok {
				want = core.NotSupported
			}
			if v, ok := s.(typedConsumerOnly); ok && v.err {
				want = core.Error
			}
			if o.Verdict != want || o.Input == "" {
				t.Fatal(o)
			}
			if o.Verdict == core.Pass {
				var out TypedConsumptionResult
				if json.Unmarshal([]byte(o.Observed), &out) != nil || out.Call.Operation != pipelineConsumer {
					t.Fatal(o)
				}
			}
		}
	}
}

func TestTypedConsumerKnownDateNormalizationGuards(t *testing.T) {
	for _, literal := range []string{`{}`, `{"verificationMethod":{}}`, `{"verificationMethod":[]}`, `{"verificationMethod":[null]}`, `{"verificationMethod":[{"expires":42,"revoked":"2020-12-20T19:17:47Z"}]}`, `{"verificationMethod":[{"expires":"bad","revoked":"2020-12-20T19:17:47Z"}]}`, `{"verificationMethod":[{"expires":"2020-12-20T19:17:47Z"}]}`} {
		v, _ := core.ParseJSON([]byte(literal))
		if normalizeConsumedDates(&v) {
			t.Fatal(literal)
		}
	}
	q := typedConsumptionFixtures()[0]
	r := consumerTypedGood(q)
	r.Call.Error = "actual rejection"
	r.Call.CaptureError = "no returned model"
	if o := judgeTypedConsumption(r, q, "input"); o.Verdict != core.Fail {
		t.Fatal(o)
	}
	r = consumerTypedGood(q)
	r.Call.Model = []byte(strings.Replace(string(q.Data), `"expires":"2020-12-21T04:17:47.123456789+09:00"`, `"expires":42`, 1))
	if o := judgeTypedConsumption(r, q, "input"); o.Verdict != core.Fail {
		t.Fatal(o)
	}
}
