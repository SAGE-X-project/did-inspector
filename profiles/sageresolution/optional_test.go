package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func optionalControl(f optionalFixture) optionalCapture {
	c := optionalCapture{Control: consumerFixture(f.Control, "1.1")}
	for _, q := range f.Variants {
		c.Variants = append(c.Variants, consumerFixture(q, "1.1"))
	}
	return c
}
func TestOptionalFixtureAndObservationGuards(t *testing.T) {
	fs := optionalFixtures()
	if len(fs) != 12 {
		t.Fatal(len(fs))
	}
	for _, f := range fs {
		c := optionalControl(f)
		for _, o := range judgeOptional(f, c, "input") {
			if o.Verdict != core.Pass {
				t.Fatal(f.Name, o.Verdict)
			}
		}
		for _, change := range []func(*ConsumptionCapture){
			func(c *ConsumptionCapture) { c.Input = []byte(`{}`) }, func(c *ConsumptionCapture) { c.MediaType = "text/plain" },
			func(c *ConsumptionCapture) { c.CaptureError = "capture lost" }, func(c *ConsumptionCapture) { c.Version = "1.0" },
			func(c *ConsumptionCapture) { c.JSONLD = true }, func(c *ConsumptionCapture) { c.DroppedTerms = []string{"id"} },
			func(c *ConsumptionCapture) { c.Model = []byte(`{`) }, func(c *ConsumptionCapture) { c.Entries = []byte(`{`) },
			func(c *ConsumptionCapture) { c.Error = "partial refusal" }, func(c *ConsumptionCapture) { c.Model = []byte(`{}`) },
			func(c *ConsumptionCapture) { c.Entries = []byte(`{"unknown":1}`) },
			func(c *ConsumptionCapture) {
				c.Error = "permitted input unsupported"
				c.Model = nil
				c.Entries = nil
				c.CaptureError = "no document"
			},
		} {
			c := optionalControl(f)
			change(&c.Variants[0])
			obs := judgeOptional(f, c, "input")
			if obs[0].Verdict == core.Pass {
				t.Fatal("false optional PASS", f.Name)
			}
			if len(obs) == 2 && obs[1].Verdict != core.Pass {
				t.Fatal("absence changed unrelated form verdict")
			}
			c = optionalControl(f)
			change(&c.Control)
			for _, o := range judgeOptional(f, c, "input") {
				if o.Verdict != core.Error {
					t.Fatal("missing baseline control")
				}
			}
		}
		c = optionalControl(f)
		c.Variants[0].Error = "unsupported"
		c.Variants[0].Model = nil
		c.Variants[0].Entries = nil
		if judgeOptional(f, c, "input")[0].Verdict != core.NotSupported {
			t.Fatal("permission refusal is not MUST violation")
		}
		if len(f.Statements) == 2 {
			for _, index := range []int{1, 2, 3} {
				c = optionalControl(f)
				c.Variants[index].Model = []byte(`{}`)
				o := judgeOptional(f, c, "input")
				if o[0].Verdict != core.Pass || o[1].Verdict != core.NotSupported {
					t.Fatal("coupled absence and form verdict")
				}
			}
		}
		for _, change := range []func(*optionalFixture){func(f *optionalFixture) { f.Name = "unknown" }, func(f *optionalFixture) { f.Statements = []string{"other"} }, func(f *optionalFixture) { f.Variants = nil }, func(f *optionalFixture) { f.Control.Data = []byte(`{}`) }} {
			var x optionalFixture
			b, _ := json.Marshal(f)
			_ = json.Unmarshal(b, &x)
			change(&x)
			if optionalPremise(x) {
				t.Fatal("invalid premise accepted")
			}
		}
		c = optionalControl(f)
		c.Variants = nil
		for _, o := range judgeOptional(f, c, "input") {
			if o.Verdict != core.Error {
				t.Fatal("partial witnesses")
			}
		}
	}
}

type optionalMock struct {
	noOperation
	calls, failAt int
}

func (s *optionalMock) InspectConsumption(_ context.Context, q ConsumptionRequest) (ConsumptionCapture, error) {
	s.calls++
	c := consumerFixture(q, "1.1")
	if s.calls == s.failAt {
		return c, errors.New("adapter failure")
	}
	return c, nil
}
func TestOptionalDispatchAndPartialEvidence(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendOptionalCases(&p)
		want := 12
		if name == "did-core-1.0" {
			want = 0
		}
		if len(p.Cases) != want {
			t.Fatal(len(p.Cases))
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s    core.Subject
				want core.Verdict
			}{{&optionalMock{}, core.Pass}, {&optionalMock{failAt: 1}, core.Error}, {&optionalMock{failAt: 2}, core.Error}, {&optionalMock{failAt: 3}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.want || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o.Verdict)
					}
					if m, ok := tt.s.(*optionalMock); ok && m.failAt > 1 {
						var out optionalCapture
						_ = json.Unmarshal([]byte(o.Observed), &out)
						if len(out.Control.Input) == 0 || len(out.Variants) != m.failAt-1 {
							t.Fatal("partial call evidence lost")
						}
					}
				}
			}
		}
	}
}
func TestOptionalSemanticValues(t *testing.T) {
	for _, f := range optionalFixtures() {
		if f.Name != "exampleExtra" {
			continue
		}
		c := optionalControl(f)
		var model map[string]any
		_ = json.Unmarshal(c.Variants[1].Model, &model)
		extra := model["verificationMethod"].([]any)[0].(map[string]any)["exampleExtra"].(map[string]any)
		extra["sequence"] = []any{true, nil, 2, "ordered"}
		c.Variants[1].Model, _ = json.Marshal(model)
		if judgeOptional(f, c, "input")[0].Verdict != core.NotSupported {
			t.Fatal("ordered extension changed")
		}
	}
}

func TestOptionalDateInstantComparison(t *testing.T) {
	for _, f := range optionalFixtures() {
		if f.Name != "expires" && f.Name != "revoked" {
			continue
		}
		for _, value := range []any{"2030-01-01T09:00:00+09:00", "2030-01-01T00:00:01Z", "invalid", false, nil} {
			c := optionalControl(f)
			var d map[string]any
			_ = json.Unmarshal(c.Variants[1].Model, &d)
			m := d["verificationMethod"].([]any)[0].(map[string]any)
			m[f.Name] = value
			c.Variants[1].Model, _ = json.Marshal(d)
			want := core.NotSupported
			if value == "2030-01-01T09:00:00+09:00" {
				want = core.Pass
			}
			if judgeOptional(f, c, "input")[0].Verdict != want {
				t.Fatal(value)
			}
		}
		c := optionalControl(f)
		var d map[string]any
		_ = json.Unmarshal(c.Variants[1].Model, &d)
		delete(d["verificationMethod"].([]any)[0].(map[string]any), f.Name)
		c.Variants[1].Model, _ = json.Marshal(d)
		if judgeOptional(f, c, "input")[0].Verdict != core.NotSupported {
			t.Fatal("date dropped")
		}
	}
}
