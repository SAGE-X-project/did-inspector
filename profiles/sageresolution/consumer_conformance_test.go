package sageresolution

import (
	"context"
	"errors"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

func conformancePairFixture(f conformanceFixture) consumerPair {
	p := consumerFixture(f.Positive, "1.1")
	n := consumerFixture(f.Negative, "unknown")
	n.Model = nil
	n.Entries = nil
	n.Error = "actual selected consumer error"
	n.CaptureError = "no document accessor maps"
	return consumerPair{p, n}
}
func TestConformancePairsRequireAcceptedControlAndActualRejection(t *testing.T) {
	rows, err := conformanceFixtures()
	if err != nil || len(rows) != 9 {
		t.Fatal(err, len(rows))
	}
	for _, f := range rows {
		for _, o := range judgeConsumerConformance(conformancePairFixture(f), f, "unit-input") {
			if o.Verdict != core.Pass || o.Input != "unit-input" || o.Observed == "" {
				t.Fatal(f.Name, o)
			}
		}
		pair := conformancePairFixture(f)
		pair.Negative.Error = ""
		for _, o := range judgeConsumerConformance(pair, f, "unit") {
			if o.Verdict != core.Fail {
				t.Fatal(o)
			}
		}
		pair = conformancePairFixture(f)
		pair.Negative.Model = []byte(`{}`)
		for _, o := range judgeConsumerConformance(pair, f, "unit") {
			if o.Verdict != core.Fail {
				t.Fatal(o)
			}
		}
		pair = conformancePairFixture(f)
		pair.Positive.Error = "always reject"
		for _, o := range judgeConsumerConformance(pair, f, "unit") {
			if o.Verdict != core.Error {
				t.Fatal("unconditional rejection passed", o)
			}
		}
	}
}
func TestConformanceEvidenceAndFixtureGuards(t *testing.T) {
	rows, _ := conformanceFixtures()
	f := rows[0]
	for _, mutate := range []func(*consumerPair){
		func(p *consumerPair) { p.Positive.Operation = "generic" }, func(p *consumerPair) { p.Negative.Operation = "generic" },
		func(p *consumerPair) { p.Positive.Input = []byte(`{}`) }, func(p *consumerPair) { p.Negative.MediaType = "application/did+json" },
		func(p *consumerPair) { p.Positive.Require = "1.1" }, func(p *consumerPair) { p.Negative.Expected = "1.0" }, func(p *consumerPair) { p.Positive.Strict = true },
		func(p *consumerPair) { p.Positive.Version = "1.0" }, func(p *consumerPair) { p.Positive.JSONLD = true }, func(p *consumerPair) { p.Positive.DroppedTerms = []string{"id"} },
		func(p *consumerPair) { p.Positive.CaptureError = "capture failed" }, func(p *consumerPair) { p.Positive.Model = []byte(`null`) }, func(p *consumerPair) { p.Positive.Model = []byte(`{}`) }, func(p *consumerPair) { p.Positive.Entries = []byte(`null`) }, func(p *consumerPair) { p.Positive.Entries = []byte(`{"extra":true}`) },
	} {
		pair := conformancePairFixture(f)
		mutate(&pair)
		for _, o := range judgeConsumerConformance(pair, f, "unit-input") {
			if o.Verdict != core.Error || o.Input != "unit-input" || o.Observed == "" {
				t.Fatal(o)
			}
		}
	}
	for _, mutate := range []func(*conformanceFixture){
		func(f *conformanceFixture) { f.Positive.Data = []byte(`{`) }, func(f *conformanceFixture) { f.Negative.Data = []byte(`[]`) },
		func(f *conformanceFixture) { f.Positive.Data = []byte(`{"id":"did:sage:web:x:a"}`) },
		func(f *conformanceFixture) { f.Negative.Data = f.Positive.Data }, func(f *conformanceFixture) { f.Negative.Data = []byte(`{"extra":true}`) },
		func(f *conformanceFixture) { f.Violation = "cid10#subjects.3" }, func(f *conformanceFixture) { f.Rule = "unknown" }, func(f *conformanceFixture) { f.Parent = "missing" },
	} {
		changed := f
		mutate(&changed)
		for _, o := range judgeConsumerConformance(conformancePairFixture(changed), changed, "unit-input") {
			if o.Verdict != core.Error || o.Observed == "" {
				t.Fatal(o)
			}
		}
	}
	// The subject's text is archived, but its self-reported rule code is no oracle.
	pair := conformancePairFixture(f)
	pair.Negative.Error = "different actual error code"
	for _, o := range judgeConsumerConformance(pair, f, "unit") {
		if o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
}
func TestConformanceFixtureHelpersPreserveOneFieldDelta(t *testing.T) {
	rows, _ := conformanceFixtures()
	for _, f := range rows {
		positive, _ := core.ParseJSON(f.Positive.Data)
		negative, _ := core.ParseJSON(f.Negative.Data)
		left, _ := replaceFixtureField(positive, f, nil)
		right, _ := replaceFixtureField(negative, f, nil)
		same, _ := checks.EqualJSON(left, right)
		if !same {
			t.Fatal("more than one field changed", f.Name)
		}
		if bad, e := controlledViolation(positive, f); e != nil || bad {
			t.Fatal(f.Name, e)
		}
		if bad, e := controlledViolation(negative, f); e != nil || !bad {
			t.Fatal(f.Name, e)
		}
	}
	doc, _ := core.ParseJSON([]byte(conformanceControl))
	for _, bad := range []conformanceFixture{{Parent: "unknown", Field: "id"}, {Parent: "id", Field: "id"}} {
		if _, err := replaceFixtureField(doc, bad, nil); err == nil {
			t.Fatal("unsupported fixture map")
		}
		if _, err := controlledViolation(doc, bad); err == nil {
			t.Fatal("unsupported fixture map")
		}
	}
	if _, err := controlledViolation(doc, conformanceFixture{Field: "id", Rule: "unknown"}); err == nil {
		t.Fatal("unknown rule")
	}
	if knownConformanceDescriptor(conformanceFixture{}) {
		t.Fatal("unknown descriptor")
	}
}

type conformanceOnly struct{ calls, failCall int }

func (*conformanceOnly) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "unit-conformance"}
}
func (*conformanceOnly) Supports(string, core.Capability) bool { return false }
func (s *conformanceOnly) InspectConsumption(_ context.Context, q ConsumptionRequest) (ConsumptionCapture, error) {
	s.calls++
	if s.calls == s.failCall {
		return ConsumptionCapture{}, errors.New("actual operation unavailable")
	}
	c := consumerFixture(q, "1.1")
	if string(q.Data) != conformanceControl {
		c.Model = nil
		c.Entries = nil
		c.Error = "actual consumer error"
	}
	return c, nil
}
func TestConformanceCasesKeepPairedCallsAndInput(t *testing.T) {
	p := core.Profile{Name: "did-1.1"}
	if e := appendConsumerConformanceCases(&p); e != nil || len(p.Cases) != 9 {
		t.Fatal(e, len(p.Cases))
	}
	for _, c := range p.Cases {
		for _, tc := range []struct {
			s core.Subject
			v core.Verdict
		}{{&conformanceOnly{}, core.Pass}, {&conformanceOnly{failCall: 1}, core.Error}, {&conformanceOnly{failCall: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tc.s) {
				if o.Verdict != tc.v || o.Input == "" {
					t.Fatal(c.ID, o)
				}
			}
		}
	}
	p = core.Profile{Name: "did-core-1.0"}
	if e := appendConsumerConformanceCases(&p); e != nil || len(p.Cases) != 0 {
		t.Fatal("legacy scope changed")
	}
}
