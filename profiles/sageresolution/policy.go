package sageresolution

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"time"
)

const policyDID = "did:sage:web:registry.example:agent-1"
const policyNow = "2029-01-01T00:00:00Z"
const policyRole = "literal library fixture; not SAGE registry Source"
const policyBase = `{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[{"id":"did:sage:web:registry.example:agent-1#sign","type":"JsonWebKey","controller":"did:sage:web:registry.example:agent-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}}],"authentication":["did:sage:web:registry.example:agent-1#sign"]}`

type dateVector struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
	Valid bool   `json:"valid"`
}

// The flags are literal independent XSD 1.1 controls, not results of the
// subject's RFC3339 reader. In particular comma and offsets beyond14:00 fail.
func dateVectors() []dateVector {
	return []dateVector{
		{"utc", "2030-01-01T00:00:00Z", true}, {"fraction-offset", "2030-01-01T09:00:00.500000001+09:00", true}, {"negative-offset", "2029-12-31T19:00:00.5-05:00", true}, {"positive-limit", "2030-01-01T14:00:00+14:00", true}, {"negative-limit", "2029-12-31T10:00:00-14:00", true}, {"zero-offset", "2030-01-01T00:00:00+00:00", true},
		{"boolean", false, false}, {"number", 42, false}, {"null", nil, false}, {"missing-zone", "2030-01-01T00:00:00", false}, {"date-only", "2030-01-01", false}, {"bad-calendar", "2030-02-30T00:00:00Z", false}, {"comma", "2030-01-01T00:00:00,5Z", false}, {"positive-outside", "2030-01-01T00:00:00+14:01", false}, {"negative-outside", "2030-01-01T00:00:00-14:01", false},
	}
}
func literalPolicy(field string, value any) ConsumptionRequest {
	var doc map[string]any
	_ = json.Unmarshal([]byte(policyBase), &doc)
	if field != "" {
		doc["verificationMethod"].([]any)[0].(map[string]any)[field] = value
	}
	b, _ := json.Marshal(doc)
	return ConsumptionRequest{b, "application/did"}
}
func policyRequest(doc ConsumptionRequest) PolicyRequest {
	return PolicyRequest{Document: doc, Mode: "retrieve", Reference: policyDID + "#sign", Purpose: "authentication", Now: policyNow}
}

type dateFixture struct {
	Field     string          `json:"field"`
	Statement string          `json:"statement"`
	Vectors   []dateVector    `json:"vectors"`
	Requests  []PolicyRequest `json:"requests"`
}

func dateFixtures() []dateFixture {
	var out []dateFixture
	for _, field := range []string{"expires", "revoked"} {
		id := "cid10#verification-methods.9"
		if field == "revoked" {
			id = "cid10#verification-methods.11"
		}
		f := dateFixture{Field: field, Statement: id, Vectors: dateVectors()}
		for _, v := range f.Vectors {
			q := policyRequest(literalPolicy(field, v.Value))
			q.Mode = "consume"
			f.Requests = append(f.Requests, q)
		}
		out = append(out, f)
	}
	return out
}

type policyFixture struct {
	Name      string          `json:"name"`
	Field     string          `json:"field,omitempty"`
	Statement string          `json:"statement"`
	Requests  []PolicyRequest `json:"requests"`
	Refuse    bool            `json:"refuse"`
}

func keyPolicyFixtures() []policyFixture {
	var out []policyFixture
	for _, field := range []string{"expires", "revoked"} {
		id := "cid10#verification-methods.9"
		if field == "revoked" {
			id = "cid10#verification-methods.11"
		}
		for _, wire := range []struct{ name, value string }{{"utc", "2030-01-01T00:00:00.5Z"}, {"offset", "2030-01-01T09:00:00.5+09:00"}} {
			for i, now := range []string{"2030-01-01T00:00:00.499999999Z", "2030-01-01T00:00:00.5Z", "2030-01-01T00:00:00.500000001Z"} {
				q := policyRequest(literalPolicy(field, wire.value))
				q.Now = now
				out = append(out, policyFixture{Name: fmt.Sprintf("%s-%s-%d", field, wire.name, i), Field: field, Statement: id, Requests: []PolicyRequest{q}, Refuse: i > 0})
			}
		}
	}
	return out
}
func retrievalPolicyFixtures() []policyFixture {
	var out []policyFixture
	for _, name := range []string{"non-document", "document-id", "method-id", "controller"} {
		good := policyRequest(literalPolicy("", nil))
		bad := good
		var doc map[string]any
		_ = json.Unmarshal(bad.Document.Data, &doc)
		id := "cid10#retrieve-verification-method.5"
		switch name {
		case "non-document":
			bad.NonDocument = true
		case "document-id":
			id = "cid10#retrieve-verification-method.6"
			doc["id"] = "did:sage:web:registry.example:other-agent"
		case "method-id":
			id = "cid10#retrieve-verification-method.9"
			doc["verificationMethod"].([]any)[0].(map[string]any)["id"] = "did:sage:web:registry.example:other-agent#sign"
			doc["authentication"] = []string{"did:sage:web:registry.example:other-agent#sign"}
		case "controller":
			id = "cid10#retrieve-verification-method.10"
			doc["verificationMethod"].([]any)[0].(map[string]any)["controller"] = "did:sage:web:registry.example:other-agent"
		}
		bad.Document.Data, _ = json.Marshal(doc)
		out = append(out, policyFixture{Name: name, Statement: id, Requests: []PolicyRequest{good, bad}, Refuse: true})
	}
	return out
}
func policyCapture(q PolicyRequest, o PolicyResult) core.Verdict {
	if o.Role != policyRole || o.CaptureError != "" || !sameConsumerCall(o.Consumer, q.Document) {
		return core.Error
	}
	if o.Consumer.Error != "" {
		if len(o.Consumer.Model) > 0 || len(o.Consumer.Entries) > 0 || len(o.Methods) > 0 || len(o.Retrieval.Calls) > 0 || o.Retrieval.Operation != "" || len(o.Retrieval.Method) > 0 || len(o.ClockValues) > 0 {
			return core.Error
		}
		return core.Pass
	}
	if o.Consumer.CaptureError != "" || o.Consumer.Version != "1.1" || o.Consumer.JSONLD || len(o.Consumer.DroppedTerms) > 0 {
		return core.Error
	}
	source, e := parse(q.Document.Data)
	model, ee := parse(o.Consumer.Model)
	entries, eee := parse(o.Consumer.Entries)
	if e != nil || ee != nil || eee != nil || entries.Len() != 0 {
		return core.Error
	}
	// Known date fields are compared as instants; other entries retain their
	// original independent literal values. No malformed date is made valid here.
	sourceMethods, ok := source.Get("verificationMethod")
	if !ok || len(sourceMethods.Array) != 1 || len(o.Methods) != 1 {
		return core.Error
	}
	modelMethods, ok := model.Get("verificationMethod")
	if !ok || len(modelMethods.Array) != 1 {
		return core.Error
	}
	for _, field := range []string{"expires", "revoked"} {
		value, present := sourceMethods.Array[0].Get(field)
		actual, has := modelMethods.Array[0].Get(field)
		w := o.Methods[0].Expires
		if field == "revoked" {
			w = o.Methods[0].Revoked
		}
		if !present {
			if has || w != nil {
				return core.Error
			}
			continue
		}
		if !has || value.Kind != core.KindString || actual.Kind != core.KindString || w == nil || w.Kind != "datetime" {
			return core.Error
		}
		t, e := time.Parse(time.RFC3339Nano, value.Str)
		u, ee := time.Parse(time.RFC3339Nano, actual.Str)
		v, eee := time.Parse(time.RFC3339Nano, w.Text)
		if e != nil || ee != nil || eee != nil || !t.Equal(u) || !t.Equal(v) {
			return core.Error
		}
		for i := range modelMethods.Array[0].Object {
			if modelMethods.Array[0].Object[i].Name == field {
				modelMethods.Array[0].Object[i].Value = value
			}
		}
	}
	id, _ := sourceMethods.Array[0].Get("id")
	if !equalObserved(source.Value(), model.Value(), "document") || o.Methods[0].ID != id.Str {
		return core.Error
	}

	if q.Mode == "consume" {
		if o.Retrieval.Operation != "" || len(o.Retrieval.Calls) > 0 || len(o.ClockValues) > 0 {
			return core.Error
		}
		return core.Pass
	}
	r := o.Retrieval
	if r.Operation != "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod" || r.Reference != q.Reference || r.Purpose != q.Purpose || r.CaptureError != "" || r.Clock != 0 || len(r.Calls) != 1 {
		return core.Error
	}
	options := q.Options
	if options == nil {
		options = map[string]any{}
	}
	var actualOpts map[string]any
	if json.Unmarshal(r.Calls[0].Options, &actualOpts) != nil || !reflect.DeepEqual(options, actualOpts) || r.Calls[0].Input != policyDID {
		return core.Error
	}
	result := r.Calls[0].Result
	if result.Native != nil || result.Exchange != nil {
		return core.Error
	}
	if q.NonDocument {
		if result.ContentKind != "" || !result.HasContent || result.ReturnedID != "" || string(result.Raw) != `"literal non-document fixture"` {
			return core.Error
		}
	} else {
		snapshot, e := parse(result.Snapshot)
		id, _ := source.Get("id")
		if e != nil || !result.HasContent || result.ContentKind != "document" || result.ReturnedID != id.Str || !equalObserved(snapshot.Value(), model.Value(), "document") {
			return core.Error
		}
	}
	for _, now := range o.ClockValues {
		a, e := time.Parse(time.RFC3339Nano, now)
		b, ee := time.Parse(time.RFC3339Nano, q.Now)
		if e != nil || ee != nil || !a.Equal(b) {
			return core.Error
		}
	}
	return core.Pass
}
func policyRefusal(o PolicyResult) bool {
	return o.Retrieval.Error != "" && len(o.Retrieval.Method) == 0
}
func policyMethod(q PolicyRequest, o PolicyResult) bool {
	if o.Retrieval.Error != "" || len(o.Retrieval.Problem) > 0 || o.Retrieval.ProblemSerializer != "" {
		return false
	}
	m, e := parse(o.Retrieval.Method)
	model, ee := parse(o.Consumer.Model)
	methods, _ := model.Get("verificationMethod")
	return e == nil && ee == nil && len(methods.Array) == 1 && equalObserved(m.Value(), methods.Array[0], "method")
}
func judgeDate(f dateFixture, values []PolicyResult, input string) core.Observation {
	raw, _ := json.Marshal(values)
	o := core.Observation{Statement: f.Statement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual preserved typed dateTimeStamp controls and rejection of independently malformed one-field inputs", Detail: "Actual selected library consumer. Literal XML Schema 1.1 dateTimeStamp controls require a time zone, allow offsets/subseconds and forbid comma separators and offsets beyond14:00. This checks selected mandatory syntax only; relying-party non-use is observed in separate cases. Original date bytes and typed instants are preserved. Consumer rejection is never substituted for relying-party rejection. No SAGE record feature, operational authority or complete XML Schema datatype implementation is claimed."}
	if (f.Field != "expires" && f.Field != "revoked") || !reflect.DeepEqual(f.Vectors, dateVectors()) || len(values) != len(f.Vectors) || len(f.Requests) != len(f.Vectors) {
		return o
	}
	ownID := "cid10#verification-methods.9"
	if f.Field == "revoked" {
		ownID = "cid10#verification-methods.11"
	}
	if f.Statement != ownID {
		return o
	}
	v := core.Pass
	for i, vector := range f.Vectors {
		q := f.Requests[i]
		if q.Mode != "consume" || !reflect.DeepEqual(q.Document, literalPolicy(f.Field, vector.Value)) {
			return o
		}
		out := values[i]
		if out.Role != policyRole || out.CaptureError != "" || !sameConsumerCall(out.Consumer, q.Document) || len(out.Retrieval.Calls) > 0 || out.Retrieval.Operation != "" || len(out.ClockValues) > 0 {
			return o
		}
		if vector.Valid && policyCapture(q, out) != core.Pass {
			return o
		}
		if out.Consumer.Error != "" && policyCapture(q, out) != core.Pass {
			return o
		}
		if vector.Valid {
			if out.Consumer.Error != "" {
				o.Verdict = core.Error
				return o
			}
		} else if out.Consumer.Error == "" {
			v = core.Fail
		}
	}
	o.Verdict = v
	return o
}
func policyPremise(f policyFixture) bool {
	for _, known := range append(keyPolicyFixtures(), retrievalPolicyFixtures()...) {
		if reflect.DeepEqual(f, known) {
			return true
		}
	}
	return false
}
func judgePolicy(f policyFixture, values []PolicyResult, input string) core.Observation {
	raw, _ := json.Marshal(values)
	o := core.Observation{Statement: f.Statement, Verdict: core.Error, Input: input, Observed: string(raw), Expected: "Actual method admission with explicit clock and original accepted literal document, or mandatory relying-party refusal", Detail: "Selected pinned relying party over an explicit literal fixture dereferencer, not a SAGE registry/Source. Actual consumer success, document and typed method dates, pre-dereference input/options, returned method/error and actual clock reads are preserved. MUST-raise cases judge refusal independently of the SHOULD canonical error type. Revocation requires no method at/after the specified instant; expiry refusal is advisory and cannot create a requirement FAIL. This is method admission only, not cryptographic use/non-use in all callers, source authority, irreversible revocation or complete schema conformance."}
	if !policyPremise(f) || len(values) != len(f.Requests) || len(values) == 0 {
		return o
	}
	o.Verdict = core.Pass
	for i, q := range f.Requests {
		out := values[i]
		if policyCapture(q, out) != core.Pass || out.Consumer.Error != "" {
			o.Verdict = core.Error
			return o
		}
		refuse := f.Refuse
		if len(f.Requests) == 2 && i == 0 {
			refuse = false
		}
		if f.Field != "" {
			if len(out.ClockValues) != 1 {
				o.Verdict = core.Error
				return o
			}
			if f.Field == "expires" && refuse {
				o.Detail += fmt.Sprintf(" Advisory expiry refusal observed: %t.", policyRefusal(out))
				if !policyRefusal(out) && !policyMethod(q, out) {
					o.Verdict = core.Error
				}
				continue
			}
		} else if len(out.ClockValues) != (map[bool]int{true: 0, false: 1}[refuse]) {
			o.Verdict = core.Error
			return o
		}
		if refuse {
			if !policyRefusal(out) {
				o.Verdict = core.Fail
			}
		} else if f.Field != "" {
			o.Detail += fmt.Sprintf(" Before-time admission observed: %t; refusal observed: %t. Neither admission nor refusal before the boundary is mandated by this clause.", policyMethod(q, out), policyRefusal(out))
			if !policyMethod(q, out) && !policyRefusal(out) {
				o.Verdict = core.Error
			}
		} else if !policyMethod(q, out) {
			o.Verdict = core.Error
		}
	}
	return o
}
func appendPolicyCases(p *core.Profile) {
	if p.Name != "did-1.1" {
		return
	}
	for _, f := range dateFixtures() {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/key-policy-format-" + f.Field, Profile: p.Name, Statements: []string{f.Statement, "cid10#conformance.2", "did11-cr20260305#production-and-consumption.18"}, Run: func(ctx context.Context, s core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			values, e := observePolicy(ctx, s, f.Requests)
			if e != nil {
				return libraryUnavailable([]string{f.Statement, "cid10#conformance.2", "did11-cr20260305#production-and-consumption.18"}, e.verdict, e.detail, string(input), values)
			}
			observation := judgeDate(f, values, string(input))
			out := []core.Observation{observation}
			for _, id := range []string{"cid10#conformance.2", "did11-cr20260305#production-and-consumption.18"} {
				copy := observation
				copy.Statement = id
				out = append(out, copy)
			}
			return out
		}})
	}
	for _, f := range append(keyPolicyFixtures(), retrievalPolicyFixtures()...) {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/key-policy-" + f.Name, Profile: p.Name, Statements: []string{f.Statement}, Run: func(ctx context.Context, s core.Subject) []core.Observation {
			input, _ := json.Marshal(f)
			values, e := observePolicy(ctx, s, f.Requests)
			if e != nil {
				return libraryUnavailable([]string{f.Statement}, e.verdict, e.detail, string(input), values)
			}
			return []core.Observation{judgePolicy(f, values, string(input))}
		}})
	}
}

type policyUnavailable struct {
	verdict core.Verdict
	detail  string
}

func observePolicy(ctx context.Context, s core.Subject, requests []PolicyRequest) ([]PolicyResult, *policyUnavailable) {
	values := []PolicyResult{}
	target, ok := s.(PolicySubject)
	if !ok {
		return values, &policyUnavailable{core.NotSupported, "no explicit literal library policy observer"}
	}
	for _, q := range requests {
		out, e := target.InspectPolicy(ctx, q)
		values = append(values, out)
		if e != nil {
			return values, &policyUnavailable{core.Error, e.Error()}
		}
	}
	return values, nil
}
