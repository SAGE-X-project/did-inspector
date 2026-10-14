package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"testing"
)

func preferenceControl() []Result { v := nativeRemainingKeyControl(); return []Result{v, v} }
func TestPreferenceControls(t *testing.T) {
	for _, fn := range []string{"resolve", "dereference"} {
		if judgePreference(fn, preferenceControl(), "input")[0].Verdict != core.Pass {
			t.Fatal(fn)
		}
		if judgePreference(fn, nil, "input")[0].Verdict != core.Error {
			t.Fatal("partial pair")
		}
		for _, change := range []func(*Result){func(r *Result) { r.Metadata = []byte(`{`) }, func(r *Result) { r.ContentMetadata = []byte(`{`) }, func(r *Result) { r.Metadata = []byte(`{"error":{}}`) }, func(r *Result) { r.Metadata = []byte(`{}`) }, func(r *Result) { r.HasContent = false }, func(r *Result) { r.ContentKind = "other" }, func(r *Result) { r.ReturnedID = "other" }, func(r *Result) { r.Native = &NativeObservation{} }, func(r *Result) { r.Exchange = &core.HTTPExchange{} }} {
			v := preferenceControl()
			change(&v[1])
			if judgePreference(fn, v, "input")[0].Verdict == core.Pass {
				t.Fatal("false preference PASS")
			}
		}
	}
	if judgePreference("bad", preferenceControl(), "input")[0].Verdict != core.Error {
		t.Fatal("unknown operation")
	}
}

type preferenceMock struct {
	noOperation
	fail bool
}

func (s preferenceMock) InspectResolution(context.Context, sageprojection.Record, Request) (Result, error) {
	if s.fail {
		return Result{}, errors.New("lost capture")
	}
	return nativeRemainingKeyControl(), nil
}
func TestPreferenceDispatch(t *testing.T) {
	records, _ := sageprojection.Fixtures()
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		appendPreferenceCases(&p, records)
		if name != "did-1.1" && len(p.Cases) > 0 {
			t.Fatal("wrong scope")
		}
		for _, c := range p.Cases {
			for _, tt := range []struct {
				s core.Subject
				v core.Verdict
			}{{preferenceMock{}, core.Pass}, {preferenceMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(o)
					}
				}
			}
		}
	}
}
