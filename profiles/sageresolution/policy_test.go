package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
	"testing"
	"time"
)

func policyControl(q PolicyRequest, refuse bool) PolicyResult {
	c := consumerFixture(q.Document, "1.1")
	var doc map[string]any
	_ = json.Unmarshal(q.Document.Data, &doc)
	methods := doc["verificationMethod"].([]any)
	m := methods[0].(map[string]any)
	w := ConsumedMethod{ID: m["id"].(string)}
	for _, field := range []string{"expires", "revoked"} {
		if v, ok := m[field].(string); ok {
			instant, _ := time.Parse(time.RFC3339Nano, v)
			typed := &TypedValue{Kind: "datetime", Text: instant.Format(time.RFC3339Nano)}
			if field == "expires" {
				w.Expires = typed
			} else {
				w.Revoked = typed
			}
			m[field] = instant.Format(time.RFC3339Nano)
		}
	}
	c.Model, _ = json.Marshal(doc)
	o := PolicyResult{Role: policyRole, Consumer: c, Methods: []ConsumedMethod{w}, Retrieval: RetrievalResult{Calls: []RetrievalCall{}}, ClockValues: []string{}}
	if q.Mode == "consume" {
		return o
	}
	r := &o.Retrieval
	r.Operation = "github.com/sage-x-project/did-go/relyingparty.RelyingParty.VerificationMethod"
	r.Reference = q.Reference
	r.Purpose = q.Purpose
	options := q.Options
	if options == nil {
		options = map[string]any{}
	}
	b, _ := json.Marshal(options)
	result := Result{Metadata: []byte(`{"contentType":"application/did"}`), ContentMetadata: []byte(`{}`), HasContent: true, ReturnedID: doc["id"].(string), ContentKind: "document", Snapshot: c.Model, Raw: c.Model}
	if q.NonDocument {
		result = Result{Metadata: []byte(`{"contentType":"text/plain"}`), ContentMetadata: []byte(`{}`), HasContent: true, Raw: []byte(`"literal non-document fixture"`)}
	}
	r.Calls = []RetrievalCall{{Input: policyDID, Options: b, Result: result}}
	if !refuse || w.Expires != nil || w.Revoked != nil {
		o.ClockValues = []string{q.Now}
	}
	if refuse {
		r.Error = "actual opaque refusal"
	} else {
		r.Method, _ = json.Marshal(m)
	}
	return o
}
func dateControl(f dateFixture, acceptBad bool) []PolicyResult {
	var out []PolicyResult
	for i, v := range f.Vectors {
		q := f.Requests[i]
		accepted := v.Valid || acceptBad && (v.Name == "comma" || strings.HasSuffix(v.Name, "outside"))
		if !accepted {
			c := consumerFixture(q.Document, "unknown")
			c.Error = "actual input refusal"
			c.Model = nil
			c.Entries = nil
			c.CaptureError = "no document"
			out = append(out, PolicyResult{Role: policyRole, Consumer: c, Retrieval: RetrievalResult{Calls: []RetrievalCall{}}, ClockValues: []string{}})
		} else {
			out = append(out, policyControl(q, false))
		}
	}
	return out
}
func fixturePolicyControl(f policyFixture) []PolicyResult {
	var out []PolicyResult
	for i, q := range f.Requests {
		refuse := f.Refuse
		if len(f.Requests) == 2 && i == 0 {
			refuse = false
		}
		out = append(out, policyControl(q, refuse))
	}
	return out
}
func TestDateSyntaxAndActualPolicyAreDifferent(t *testing.T) {
	for _, f := range dateFixtures() {
		if judgeDate(f, dateControl(f, false), "input").Verdict != core.Pass || judgeDate(f, dateControl(f, true), "input").Verdict != core.Fail {
			t.Fatal(f.Field)
		}
		for _, change := range []func(*dateFixture){func(x *dateFixture) { x.Vectors = append([]dateVector{}, x.Vectors...); x.Vectors[0].Valid = false }, func(x *dateFixture) { x.Field = "unknown" }, func(x *dateFixture) {
			x.Requests = append([]PolicyRequest{}, x.Requests...)
			x.Requests[0].Document.Data = []byte(`{}`)
		}} {
			x := f
			change(&x)
			if judgeDate(x, dateControl(f, false), "input").Verdict != core.Error {
				t.Fatal("bad syntax premise")
			}
		}
		if judgeDate(f, nil, "input").Verdict != core.Error {
			t.Fatal("missing captures")
		}
		values := dateControl(f, false)
		values[0].Role = "source"
		if judgeDate(f, values, "input").Verdict != core.Error {
			t.Fatal("false role")
		}
		values = dateControl(f, false)
		values[0].Consumer.Error = "always reject"
		values[0].Consumer.Model = nil
		values[0].Consumer.Entries = nil
		values[0].Methods = nil
		if judgeDate(f, values, "input").Verdict != core.Error {
			t.Fatal("valid input refusal")
		}
	}
	for _, f := range keyPolicyFixtures() {
		o := fixturePolicyControl(f)
		if judgePolicy(f, o, "input").Verdict != core.Pass {
			t.Fatal(f.Name)
		}
		q := f.Requests[0]
		if !f.Refuse {
			refused := policyControl(q, true)
			if judgePolicy(f, []PolicyResult{refused}, "input").Verdict != core.Pass {
				t.Fatal("before-time refusal is not forbidden")
			}
		}
		if f.Field == "expires" && f.Refuse {
			allowed := policyControl(q, false)
			obs := judgePolicy(f, []PolicyResult{allowed}, "input")
			if obs.Verdict != core.Pass || !strings.Contains(obs.Detail, "false") {
				t.Fatal("expiry SHOULD became MUST", obs)
			}
		}
		if f.Field == "revoked" && f.Refuse {
			allowed := policyControl(q, false)
			if judgePolicy(f, []PolicyResult{allowed}, "input").Verdict != core.Fail {
				t.Fatal("revocation MUST ignored")
			}
		}
		empty := policyControl(q, false)
		empty.Retrieval.Method = nil
		if judgePolicy(f, []PolicyResult{empty}, "input").Verdict == core.Pass {
			t.Fatal("silent absence")
		}
		for _, change := range []func(*PolicyResult){func(x *PolicyResult) { x.ClockValues = nil }, func(x *PolicyResult) { x.ClockValues = []string{policyNow} }, func(x *PolicyResult) { x.ClockValues = []string{"bad"} }, func(x *PolicyResult) { x.Methods[0].Expires = nil; x.Methods[0].Revoked = nil }} {
			x := policyControl(q, f.Refuse)
			change(&x)
			if judgePolicy(f, []PolicyResult{x}, "input").Verdict != core.Error {
				t.Fatal("time witness lost")
			}
		}
	}
}
func TestPolicyCaptureAndRefusalMutationControls(t *testing.T) {
	fixtures := append(keyPolicyFixtures(), retrievalPolicyFixtures()...)
	for _, f := range fixtures {
		if !policyPremise(f) || judgePolicy(f, fixturePolicyControl(f), "input").Verdict != core.Pass {
			t.Fatal(f.Name)
		}
		if judgePolicy(f, nil, "input").Verdict != core.Error {
			t.Fatal("capture count")
		}
		bad := f
		bad.Statement = "other"
		if judgePolicy(bad, fixturePolicyControl(f), "input").Verdict != core.Error {
			t.Fatal("clause attribution")
		}
		for i, q := range f.Requests {
			changes := []func(*PolicyResult){func(x *PolicyResult) { x.Role = "actual Source" }, func(x *PolicyResult) { x.CaptureError = "lost" }, func(x *PolicyResult) { x.Consumer.Input = []byte(`{}`) }, func(x *PolicyResult) { x.Consumer.CaptureError = "lost" }, func(x *PolicyResult) { x.Consumer.Version = "1.0" }, func(x *PolicyResult) { x.Consumer.JSONLD = true }, func(x *PolicyResult) { x.Consumer.DroppedTerms = []string{"id"} }, func(x *PolicyResult) { x.Consumer.Model = []byte(`{`) }, func(x *PolicyResult) { x.Consumer.Entries = []byte(`{"x":true}`) }, func(x *PolicyResult) { x.Methods = nil }, func(x *PolicyResult) { x.Retrieval.Operation = "other" }, func(x *PolicyResult) { x.Retrieval.Reference = "other" }, func(x *PolicyResult) { x.Retrieval.Purpose = "assertionMethod" }, func(x *PolicyResult) { x.Retrieval.Clock = 1 }, func(x *PolicyResult) { x.Retrieval.CaptureError = "lost" }, func(x *PolicyResult) { x.Retrieval.Calls = nil }, func(x *PolicyResult) { x.Retrieval.Calls[0].Input += "#sign" }, func(x *PolicyResult) { x.Retrieval.Calls[0].Options = []byte(`{`) }, func(x *PolicyResult) { x.Retrieval.Calls[0].Options = []byte(`{"extra":true}`) }, func(x *PolicyResult) { x.Retrieval.Calls[0].Result.Native = &NativeObservation{} }, func(x *PolicyResult) { x.Retrieval.Calls[0].Result.Exchange = &core.HTTPExchange{} }, func(x *PolicyResult) { x.Retrieval.Calls[0].Result.HasContent = false }}
			for _, change := range changes {
				values := fixturePolicyControl(f)
				change(&values[i])
				if judgePolicy(f, values, "input").Verdict != core.Error {
					t.Fatal("bad capture accepted", f.Name, i)
				}
			}
			if q.NonDocument {
				values := fixturePolicyControl(f)
				values[i].Retrieval.Calls[0].Result.Raw = []byte(`"other"`)
				if judgePolicy(f, values, "input").Verdict != core.Error {
					t.Fatal("changed ordinary fixture")
				}
			} else {
				values := fixturePolicyControl(f)
				values[i].Retrieval.Calls[0].Result.Snapshot = []byte(`{"id":"other"}`)
				if judgePolicy(f, values, "input").Verdict != core.Error {
					t.Fatal("changed doc")
				}
			}
		}
		if f.Field == "" {
			values := fixturePolicyControl(f)
			values[1] = policyControl(f.Requests[1], false)
			if judgePolicy(f, values, "input").Verdict != core.Error {
				t.Fatal("early branch clock attribution")
			}
			values = fixturePolicyControl(f)
			values[1].Retrieval.Error = ""
			values[1].Retrieval.Method = []byte(`{}`)
			if judgePolicy(f, values, "input").Verdict != core.Fail {
				t.Fatal("MUST raise ignored")
			}
			values = fixturePolicyControl(f)
			values[1].Retrieval.Problem = []byte(`{"type":"https://www.w3.org/ns/did#INTERNAL_ERROR"}`)
			values[1].Retrieval.ProblemSerializer = "opaque native diagnostic"
			if judgePolicy(f, values, "input").Verdict != core.Pass {
				t.Fatal("SHOULD type became MUST")
			}
			values = fixturePolicyControl(f)
			values[0].Retrieval.Error = "denied"
			values[0].Retrieval.Method = nil
			if judgePolicy(f, values, "input").Verdict != core.Error {
				t.Fatal("lost positive control")
			}
		}
	}
}
func TestPolicyTypedDateAndDocumentWitnesses(t *testing.T) {
	q := keyPolicyFixtures()[0].Requests[0]
	for _, change := range []func(*PolicyResult){func(x *PolicyResult) { x.Methods[0].ID = "other" }, func(x *PolicyResult) { x.Methods[0].Expires.Kind = "string" }, func(x *PolicyResult) { x.Methods[0].Expires.Text = "bad" }, func(x *PolicyResult) { x.Methods[0].Revoked = &TypedValue{} }, func(x *PolicyResult) { x.Consumer.Model = []byte(`{"id":"x"}`) }, func(x *PolicyResult) { x.Consumer.Model = []byte(`{"id":"x","verificationMethod":[]}`) }, func(x *PolicyResult) { x.Retrieval.Calls[0].Result.Snapshot = []byte(`{`) }} {
		x := policyControl(q, false)
		change(&x)
		if policyCapture(q, x) == core.Pass {
			t.Fatal("date/model witness lost")
		}
	}
	consumed := q
	consumed.Mode = "consume"
	x := policyControl(consumed, false)
	x.Retrieval.Operation = "other"
	if policyCapture(consumed, x) == core.Pass {
		t.Fatal("retrieval substituted for syntax")
	}
	x = policyControl(q, false)
	x.Retrieval.Method = []byte(`{"id":"other"}`)
	if policyMethod(q, x) {
		t.Fatal("wrong admitted method")
	}
	x = policyControl(q, false)
	x.Retrieval.Problem = []byte(`{}`)
	if policyMethod(q, x) {
		t.Fatal("unexpected problem")
	}
}

type policyMock struct {
	noOperation
	failAt int
	calls  int
}

func (s *policyMock) InspectPolicy(_ context.Context, q PolicyRequest) (PolicyResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return PolicyResult{Role: "partial"}, errors.New("observer failed")
	}
	if q.Mode == "consume" {
		for _, f := range dateFixtures() {
			for i, request := range f.Requests {
				a, _ := json.Marshal(q)
				b, _ := json.Marshal(request)
				if string(a) == string(b) {
					return dateControl(f, false)[i], nil
				}
			}
		}
	}
	for _, f := range append(keyPolicyFixtures(), retrievalPolicyFixtures()...) {
		for i, request := range f.Requests {
			a, _ := json.Marshal(q)
			b, _ := json.Marshal(request)
			if string(a) == string(b) {
				return fixturePolicyControl(f)[i], nil
			}
		}
	}
	return PolicyResult{}, errors.New("unknown input")
}
func TestPolicyDispatchAndPartialCapture(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendPolicyCases(&p)
		want := 18
		if name == "did-core-1.0" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{&policyMock{}, core.Pass}, {&policyMock{failAt: 1}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o)
					}
				}
			}
			if strings.Contains(c.ID, "format-") {
				values, e := observePolicy(t.Context(), &policyMock{failAt: 2}, dateFixtures()[0].Requests)
				if e == nil || len(values) != 2 || values[0].Role != policyRole || values[1].Role != "partial" {
					t.Fatal("partial capture lost")
				}
			}
		}
	}
}

func TestPolicyAmbiguousOutcomeIsNotExpiryRequirementFailure(t *testing.T) {
	for _, f := range keyPolicyFixtures() {
		if f.Field != "expires" || !f.Refuse {
			continue
		}
		out := policyControl(f.Requests[0], false)
		out.Retrieval.Error = "method plus error"
		if judgePolicy(f, []PolicyResult{out}, "input").Verdict != core.Error {
			t.Fatal("ambiguous expiry outcome became requirement failure")
		}
	}
	f := dateFixtures()[0]
	f.Statement = "other"
	if judgeDate(f, dateControl(dateFixtures()[0], false), "input").Verdict != core.Error {
		t.Fatal("incorrect date clause")
	}
}
