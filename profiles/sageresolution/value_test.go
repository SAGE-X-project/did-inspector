package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func valueControl(f valueFixture) []LibraryValueResult {
	out := []LibraryValueResult{}
	reader, validator, writer := valueActor(f.Kind)
	for _, v := range f.Values {
		x := LibraryValueResult{Request: valueRequest(f, v), Reader: reader}
		if v.Valid {
			x.Validator = validator
			x.Writer = writer
			x.Output = x.Request.Input
		} else {
			x.ReadError = "actual refusal"
		}
		out = append(out, x)
	}
	return out
}
func TestLibraryValueGuards(t *testing.T) {
	fs := valueFixtures()
	if len(fs) != 16 {
		t.Fatal(len(fs))
	}
	for _, f := range fs {
		for _, o := range judgeLibraryValues(f, valueControl(f), "input") {
			if o.Verdict != core.Pass {
				t.Fatal(f.Name, o.Verdict)
			}
		}
		for _, change := range []func(*LibraryValueResult){
			func(c *LibraryValueResult) { c.Request.Input = []byte(`null`) }, func(c *LibraryValueResult) { c.Request.Kind = "other" }, func(c *LibraryValueResult) { c.Request.Subject = "other" }, func(c *LibraryValueResult) { c.Reader = "invented" }, func(c *LibraryValueResult) { c.Validator = "invented" }, func(c *LibraryValueResult) { c.Writer = "invented" }, func(c *LibraryValueResult) {
				c.ReadError = "always reject"
				c.Validator = ""
				c.Writer = ""
				c.Output = nil
			}, func(c *LibraryValueResult) { c.ReadError = "partial" }, func(c *LibraryValueResult) { c.ValidationError = "partial" }, func(c *LibraryValueResult) { c.WriteError = "write failed" }, func(c *LibraryValueResult) { c.Output = []byte(`{`) }, func(c *LibraryValueResult) { c.Output = []byte(`{"changed":42}`) },
		} {
			c := valueControl(f)
			change(&c[0])
			for _, o := range judgeLibraryValues(f, c, "input") {
				if o.Verdict == core.Pass {
					t.Fatal("false value PASS", f.Name)
				}
			}
		}
		if judgeLibraryValues(f, nil, "input")[0].Verdict != core.Error {
			t.Fatal("partial calls")
		}
		bad := f
		bad.Name = "other"
		if judgeLibraryValues(bad, valueControl(f), "input")[0].Verdict != core.Error {
			t.Fatal("bad premise")
		}
		for index, v := range f.Values {
			if v.Valid {
				continue
			}
			for _, change := range []func(*LibraryValueResult){func(c *LibraryValueResult) { c.Validator = "invented"; c.ReadError = "" }, func(c *LibraryValueResult) { c.Output = []byte(`{}`) }, func(c *LibraryValueResult) {
				c.ReadError = ""
				c.Validator = valueControl(f)[0].Validator
				c.ValidationError = "actual validation refusal"
				c.Writer = "invented"
			}, func(c *LibraryValueResult) {
				c.ReadError = ""
				c.Validator = valueControl(f)[0].Validator
				c.Writer = "invented"
			}} {
				c := valueControl(f)
				change(&c[index])
				if judgeLibraryValues(f, c, "input")[0].Verdict == core.Pass {
					t.Fatal("contradictory invalid capture")
				}
			}
			c := valueControl(f)
			c[index].ReadError = ""
			c[index].Validator = c[0].Validator
			c[index].ValidationError = "validator refused"
			if judgeLibraryValues(f, c, "input")[0].Verdict != core.Pass {
				t.Fatal("validation refusal lost")
			}
			c[index].ValidationError = ""
			c[index].Writer = c[0].Writer
			c[index].Output = c[0].Output
			if judgeLibraryValues(f, c, "input")[0].Verdict != core.Pass {
				t.Fatal("conforming repair rejected")
			}
			c[index].Output = c[index].Request.Input
			if judgeLibraryValues(f, c, "input")[0].Verdict != core.Fail {
				t.Fatal("invalid output accepted", f.Name, index)
			}
		}
		if f.Permission {
			c := valueControl(f)
			c[1].ReadError = "permitted unsupported"
			c[1].Validator = ""
			c[1].Writer = ""
			c[1].Output = nil
			if judgeLibraryValues(f, c, "input")[0].Verdict != core.NotSupported {
				t.Fatal("permission is not MUST")
			}
		}
	}
}

type valueMock struct {
	noOperation
	calls, failAt int
}

func (s *valueMock) InspectLibraryValue(_ context.Context, q LibraryValueRequest) (LibraryValueResult, error) {
	s.calls++
	for _, f := range valueFixtures() {
		for i, v := range f.Values {
			if q.Kind == f.Kind && string(q.Input) == string(v.Input) {
				c := valueControl(f)[i]
				if s.calls == s.failAt {
					return c, errors.New("adapter failure")
				}
				return c, nil
			}
		}
	}
	return LibraryValueResult{}, errors.New("unknown")
}
func TestLibraryValueDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendLibraryValueCases(&p)
		want := 16
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
			}{{&valueMock{}, core.Pass}, {&valueMock{failAt: 1}, core.Error}, {&valueMock{failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.want || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o.Verdict)
					}
					if m, ok := tt.s.(*valueMock); ok && m.failAt == 2 {
						var values []LibraryValueResult
						_ = json.Unmarshal([]byte(o.Observed), &values)
						if len(values) != 2 || len(values[0].Request.Input) == 0 {
							t.Fatal("partial captures")
						}
					}
				}
			}
		}
	}
}
func TestLibraryValueOutputFormat(t *testing.T) {
	for _, tt := range []struct {
		field, wire string
		valid       bool
	}{
		{"created", `{"created":"2030-01-01T00:00:00Z"}`, true}, {"created", `{"created":"2030-02-30T00:00:00Z"}`, false}, {"created", `{"created":42}`, false}, {"created", `{}`, true},
		{"nextVersionId", `{"nextVersionId":"한글"}`, false}, {"nextVersionId", `{"nextVersionId":1}`, false},
		{"canonicalId", `{"canonicalId":"not-a-did"}`, false}, {"canonicalId", `{"canonicalId":1}`, false},
		{"equivalentId", `{"equivalentId":"did:example:123"}`, false}, {"equivalentId", `{"equivalentId":[42]}`, false}, {"equivalentId", `{"equivalentId":["did:example:123"]}`, true},
		{"proof", `{"proof":[{}]}`, true}, {"proof", `{"proof":null}`, false}, {"proof", `{"proof":[null]}`, false},
		{"other", `{"other":true}`, false}, {"proof", `null`, false}, {"proof", `{"proof":[],"proof":[]}`, false}, {"proof", `{`, false},
	} {
		if valueOutputConforms(valueFixture{Field: tt.field}, []byte(tt.wire)) != tt.valid {
			t.Fatal(tt)
		}
	}
}
