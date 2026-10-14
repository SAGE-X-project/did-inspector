package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func conversionControl(f codecFixture) []KeyConversionResult {
	out := []KeyConversionResult{}
	typ := "*ecdsa.PublicKey"
	if f.Name == "Ed25519" {
		typ = "ed25519.PublicKey"
	}
	for _, q := range codecRequests(f) {
		out = append(out, KeyConversionResult{Request: KeyConversionRequest{f.Name, q.Key}, Operation: keyConversionOperation, CryptoType: typ, Before: q.Encoded, After: q.Encoded, BeforeRaw: q.Key, AfterRaw: q.Key, BeforeType: f.Name, AfterType: f.Name})
	}
	return out
}
func TestPublicKeyConversionGuards(t *testing.T) {
	for _, f := range keyConversionFixtures() {
		for _, o := range judgeKeyConversion(f, conversionControl(f), "input") {
			if o.Verdict != core.Pass {
				t.Fatal(o)
			}
		}
		if judgeKeyConversion(f, nil, "")[0].Verdict != core.Error {
			t.Fatal("missing calls")
		}
		for _, change := range []func(*KeyConversionResult){func(v *KeyConversionResult) { v.Operation = "other" }, func(v *KeyConversionResult) { v.Request.Name = "other" }, func(v *KeyConversionResult) { v.BuildError = "invalid key" }, func(v *KeyConversionResult) { v.Before = "wrong" }} {
			v := conversionControl(f)
			change(&v[0])
			if judgeKeyConversion(f, v, "")[0].Verdict != core.Error {
				t.Fatal("invalid premise")
			}
		}
		for _, change := range []func(*KeyConversionResult){func(v *KeyConversionResult) { v.CryptoType = "other" }, func(v *KeyConversionResult) { v.BeforeType = "other" }, func(v *KeyConversionResult) { v.AfterType = "other" }, func(v *KeyConversionResult) { v.BeforeRaw = nil }, func(v *KeyConversionResult) { v.AfterRaw = nil }} {
			v := conversionControl(f)
			change(&v[0])
			if judgeKeyConversion(f, v, "")[1].Verdict != core.Pass {
				t.Fatal("internal diagnostic incorrectly changes external preservation")
			}
		}
		v0 := conversionControl(f)
		v0[0].ConvertError = "refused"
		v0[0].After = ""
		v0[0].AfterRaw = nil
		v0[0].AfterType = ""
		refused := judgeKeyConversion(f, v0, "")
		if refused[0].Verdict != core.NotSupported || refused[1].Verdict != core.Pass {
			t.Fatal("optional refusal conflated", refused)
		}
		v0 = conversionControl(f)
		v0[0].AfterError = "could not serialize"
		v0[0].After = ""
		stage := judgeKeyConversion(f, v0, "")
		if stage[0].Verdict != core.Pass || stage[1].Verdict != core.Error {
			t.Fatal("missing external observation conflated", stage)
		}
		v0 = conversionControl(f)
		v0[0].BeforeError = "initial serialization refused"
		if judgeKeyConversion(f, v0, "")[0].Verdict != core.Error {
			t.Fatal("missing original premise")
		}
		v0 = conversionControl(f)
		v0[0].ConvertError = "refused"
		if judgeKeyConversion(f, v0, "")[0].Verdict != core.Error {
			t.Fatal("contradictory converted output")
		}
		v0 = conversionControl(f)
		for i := range v0 {
			v0[i].ConvertError = "refused"
			v0[i].After = ""
			v0[i].AfterRaw = nil
			v0[i].AfterType = ""
		}
		allRefused := judgeKeyConversion(f, v0, "")
		if allRefused[0].Verdict != core.NotSupported || allRefused[1].Verdict != core.NotApplicable {
			t.Fatal("no applicable conversion", allRefused)
		}
		v0 = conversionControl(f)
		v0[0].ConvertError = "refused"
		v0[0].After = ""
		v0[0].AfterRaw = nil
		v0[0].AfterType = ""
		v0[1].After = "zchanged"
		mixed := judgeKeyConversion(f, v0, "")
		if mixed[0].Verdict != core.NotSupported || mixed[1].Verdict != core.Fail {
			t.Fatal("refusal hid external change", mixed)
		}
		v := conversionControl(f)
		v[0].After = "zwrong"
		o := judgeKeyConversion(f, v, "")
		if o[0].Verdict != core.Pass || o[1].Verdict != core.Fail {
			t.Fatal("conversion and representation conflated", o)
		}
	}
}

type conversionMock struct {
	noOperation
	failAt, calls int
}

func (s *conversionMock) InspectKeyConversion(_ context.Context, q KeyConversionRequest) (KeyConversionResult, error) {
	s.calls++
	if s.calls == s.failAt {
		return KeyConversionResult{}, errors.New("capture failed")
	}
	for _, f := range keyConversionFixtures() {
		for _, v := range conversionControl(f) {
			if v.Request.Name == q.Name && string(v.Request.Key) == string(q.Key) {
				return v, nil
			}
		}
	}
	return KeyConversionResult{}, errors.New("unknown fixture")
}
func TestKeyConversionDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendKeyConversionCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("wrong profile")
	}
	p.Name = "did-1.1"
	appendKeyConversionCases(&p)
	if len(p.Cases) != 3 {
		t.Fatal("missing public types")
	}
	for _, c := range p.Cases {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, tt := range []struct {
			s    core.Subject
			want core.Verdict
		}{{&conversionMock{}, core.Pass}, {&conversionMock{failAt: 1}, core.Error}, {&conversionMock{failAt: 2}, core.Error}, {noOperation{}, core.NotSupported}} {
			for _, o := range c.Run(t.Context(), tt.s) {
				if o.Verdict != tt.want {
					t.Fatal(c.ID, o)
				}
			}
		}
	}
}
