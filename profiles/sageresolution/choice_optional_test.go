package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func TestOptionalMultikeyLocalModelPremise(t *testing.T) {
	f := choiceOptionalFixtures()[0]
	if !optionalPremise(f) {
		t.Fatal("unknown fixture")
	}
	for i, q := range f.Variants {
		v, err := parse(q.Data)
		if err != nil {
			t.Fatal(err)
		}
		methods, _ := v.Get("verificationMethod")
		m := methods.Array[0]
		pub, pp := m.Get("publicKeyMultibase")
		secret, sp := m.Get("secretKeyMultibase")
		if i == 0 && (!pp || pub.Kind != core.KindString || sp) {
			t.Fatal("public control")
		}
		if i == 1 && (pp || !sp || secret.Kind != core.KindString) {
			t.Fatal("secret-only control")
		}
	}
}

type choiceOptionalMock struct {
	noOperation
	failAt, calls int
}

func (s *choiceOptionalMock) InspectConsumption(_ context.Context, q ConsumptionRequest) (ConsumptionCapture, error) {
	s.calls++
	if s.calls == s.failAt {
		return ConsumptionCapture{}, errors.New("capture failed")
	}
	return consumerFixture(q, "1.1"), nil
}
func TestChoiceOptionalDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendChoiceOptionalCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("wrong profile")
	}
	p.Name = "did-1.1"
	appendChoiceOptionalCases(&p)
	if len(p.Cases) != 1 {
		t.Fatal(len(p.Cases))
	}
	c := p.Cases[0]
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		s core.Subject
		v core.Verdict
	}{{&choiceOptionalMock{}, core.Pass}, {&choiceOptionalMock{failAt: 1}, core.Error}, {&choiceOptionalMock{failAt: 2}, core.Error}, {&choiceOptionalMock{failAt: 3}, core.Error}, {noOperation{}, core.NotSupported}} {
		for _, o := range c.Run(t.Context(), tt.s) {
			if o.Verdict != tt.v {
				t.Fatal(o)
			}
		}
	}
}
