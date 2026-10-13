package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func documentPairControl(f libraryDocumentFixture) consumerPair {
	p := consumerFixture(f.Positive, "1.1")
	n := consumerFixture(f.Negative, "unknown")
	n.Model = nil
	n.Entries = nil
	n.Error = "actual validation refusal"
	n.CaptureError = "no document"
	return consumerPair{p, n}
}
func TestLibraryDocumentPremisesAndMutationGuards(t *testing.T) {
	fixtures := libraryDocumentFixtures()
	if len(fixtures) != 6 {
		t.Fatal(len(fixtures))
	}
	for _, f := range fixtures {
		if !libraryDocumentPremise(f) || judgeLibraryDocument(f, documentPairControl(f), "input").Verdict != core.Pass {
			t.Fatal(f)
		}
		for _, change := range []func(*consumerPair){func(r *consumerPair) { r.Positive.Input = []byte(`{}`) }, func(r *consumerPair) { r.Negative.MediaType = "application/json" }, func(r *consumerPair) { r.Positive.Error = "always reject" }, func(r *consumerPair) { r.Positive.CaptureError = "lost" }, func(r *consumerPair) { r.Positive.Version = "1.0" }, func(r *consumerPair) { r.Positive.JSONLD = true }, func(r *consumerPair) { r.Positive.DroppedTerms = []string{"id"} }, func(r *consumerPair) { r.Positive.Model = []byte(`{}`) }, func(r *consumerPair) { r.Positive.Entries = []byte(`{"extra":1}`) }, func(r *consumerPair) { r.Negative.Error = "" }, func(r *consumerPair) { r.Negative.Model = []byte(`{}`) }} {
			r := documentPairControl(f)
			change(&r)
			if judgeLibraryDocument(f, r, "input").Verdict == core.Pass {
				t.Fatal("false property PASS", f.Name)
			}
		}
		for _, change := range []func(*libraryDocumentFixture){func(x *libraryDocumentFixture) { x.Positive.Data = []byte("{") }, func(x *libraryDocumentFixture) { x.Negative.Data = x.Positive.Data }, func(x *libraryDocumentFixture) { x.Statement = "other" }, func(x *libraryDocumentFixture) { x.Positive.Data = []byte(`{"id":"other"}`) }, func(x *libraryDocumentFixture) {
			x.Negative.Data = []byte(`{"id":"did:sage:web:registry.example:agent-1","extra":"changed"}`)
		}} {
			x := f
			change(&x)
			if libraryDocumentPremise(x) {
				t.Fatal("bad fixture premise")
			}
		}
	}
}

type documentMock struct {
	noOperation
	failAt int
	calls  int
}

func (s *documentMock) InspectConsumption(_ context.Context, q ConsumptionRequest) (ConsumptionCapture, error) {
	s.calls++
	if s.calls == s.failAt {
		return ConsumptionCapture{}, errors.New("adapter failed")
	}
	for _, f := range libraryDocumentFixtures() {
		if string(q.Data) == string(f.Positive.Data) {
			return documentPairControl(f).Positive, nil
		}
		if string(q.Data) == string(f.Negative.Data) {
			return documentPairControl(f).Negative, nil
		}
	}
	return ConsumptionCapture{}, errors.New("unknown input")
}
func TestLibraryDocumentDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendLibraryDocumentCases(&p)
		want := 6
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
			}{{&documentMock{}, core.Pass}, {&documentMock{failAt: 1}, core.Error}, {&documentMock{failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o)
					}
					if m, ok := tt.s.(*documentMock); ok && m.failAt == 2 {
						var pair consumerPair
						_ = json.Unmarshal([]byte(o.Observed), &pair)
						if len(pair.Positive.Input) == 0 {
							t.Fatal("partial capture lost")
						}
					}
				}
			}
		}
	}
}
