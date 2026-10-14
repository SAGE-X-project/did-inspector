package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"strings"
	"testing"
)

type remainingFieldMock struct {
	noOperation
	calls, failAt int
	badProducer   bool
	typedError    bool
}

func (s *remainingFieldMock) InspectConsumption(_ context.Context, q ConsumptionRequest) (ConsumptionCapture, error) {
	s.calls++
	c := consumerFixture(q, "1.1")
	if s.calls == s.failAt {
		return c, errors.New("adapter failed")
	}
	for _, f := range remainingMaterialFixtures() {
		if string(f.Negative.Data) == string(q.Data) {
			c.Model = nil
			c.Entries = nil
			c.Error = "actual refusal"
			c.CaptureError = "no document"
		}
	}
	return c, nil
}
func (s *remainingFieldMock) InspectTypedProduction(_ context.Context, _ TypedProductionRequest) (TypedProductionResult, error) {
	r, _ := typedProductionFixture(false)
	if s.typedError {
		return r, errors.New("adapter failed")
	}
	if s.badProducer {
		r.Calls[0].Error = "producer refused"
	}
	return r, nil
}
func TestRemainingFieldsAndDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendRemainingFieldCases(&p)
		want := 9
		if name != "did-1.1" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s    core.Subject
				want core.Verdict
			}{{&remainingFieldMock{}, core.Pass}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.want || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o.Verdict)
					}
				}
			}
			if strings.Contains(c.ID, "substructures") {
				for _, s := range []*remainingFieldMock{{badProducer: true}, {typedError: true}} {
					o := c.Run(t.Context(), s)[0]
					want := core.NotSupported
					if s.typedError {
						want = core.Error
					}
					if o.Verdict != want {
						t.Fatal(o.Verdict)
					}
				}
				continue
			}
			for _, i := range []int{1, 2} {
				for _, o := range c.Run(t.Context(), &remainingFieldMock{failAt: i}) {
					if o.Verdict != core.Error {
						t.Fatal(c.ID, o.Verdict)
					}
				}
			}
			if !strings.Contains(c.ID, "shape") {
				if c.Run(t.Context(), &remainingFieldMock{failAt: 3})[0].Verdict != core.Error {
					t.Fatal("partial third call")
				}
			}
		}
	}
	for _, f := range remainingFieldFixtures() {
		if !optionalPremise(f) || judgeOptional(f, optionalControl(f), "input")[0].Verdict != core.Pass {
			t.Fatal(f.Name)
		}
	}
	for _, f := range remainingMaterialFixtures() {
		if !libraryDocumentPremise(f) || judgeLibraryDocument(f, documentPairControl(f), "input").Verdict != core.Pass {
			t.Fatal(f.Name)
		}
		for _, bad := range []string{`{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[]}`, `{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[42]}`, `{"id":"did:sage:web:registry.example:agent-1","verificationMethod":42}`} {
			x := f
			x.Positive.Data = []byte(bad)
			if libraryDocumentPremise(x) {
				t.Fatal("malformed method accepted")
			}
		}
		var x libraryDocumentFixture
		b, _ := json.Marshal(f)
		_ = json.Unmarshal(b, &x)
		x.Name = "other"
		if libraryDocumentPremise(x) {
			t.Fatal("unknown fixture")
		}
	}
}
