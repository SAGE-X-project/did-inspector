package sageresolution

import (
	"context"
	"errors"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/core/coretest"
)

func choiceCodecControl(f codecFixture) []CodecResult {
	out := codecControl(f)
	bad := out[0]
	bad.Request.Encoded = "z0"
	bad.DecodeError = "malformed base58"
	bad.Decoded = nil
	bad.DecodeName = ""
	bad.DecodePrefix = nil
	bad.DecodeLength = 0
	bad.DecodeSecret = false
	return append(out, bad)
}
func TestChoiceCodecIndependentDirections(t *testing.T) {
	for _, f := range codecFixtures() {
		values := choiceCodecControl(f)
		for _, o := range judgeChoiceCodec(f, values, "input") {
			if o.Verdict != core.Pass {
				t.Fatal(f.Name, o)
			}
		}
		bad := choiceCodecControl(f)
		bad[0].EncodeError = "refused"
		got := judgeChoiceCodec(f, bad, "input")
		if got[0].Verdict != core.Fail || got[1].Verdict != core.Fail || got[2].Verdict != core.Pass {
			t.Fatal(got)
		}
		bad = choiceCodecControl(f)
		bad[0].DecodeError = "refused"
		got = judgeChoiceCodec(f, bad, "input")
		if got[0].Verdict != core.Fail || got[1].Verdict != core.Pass || got[2].Verdict != core.Fail {
			t.Fatal(got)
		}
		if judgeChoiceCodec(f, nil, "")[0].Verdict != core.Error {
			t.Fatal("missing calls accepted")
		}
		bad = choiceCodecControl(f)
		bad[0].Operation = "other"
		if judgeChoiceCodec(f, bad, "")[0].Verdict != core.Error {
			t.Fatal("wrong operation accepted")
		}
		bad = choiceCodecControl(f)
		bad[0].Request.Name = "other"
		if judgeChoiceCodec(f, bad, "")[0].Verdict != core.Error {
			t.Fatal("swapped request accepted")
		}
		for _, change := range []func(*CodecResult){
			func(v *CodecResult) { v.Encoded = "zwrong" }, func(v *CodecResult) { v.Name = "other" }, func(v *CodecResult) { v.Length++ }, func(v *CodecResult) { v.Secret = !v.Secret }, func(v *CodecResult) { v.Prefix = nil },
			func(v *CodecResult) { v.Decoded = nil }, func(v *CodecResult) { v.DecodeName = "other" }, func(v *CodecResult) { v.DecodeLength++ }, func(v *CodecResult) { v.DecodeSecret = !v.DecodeSecret }, func(v *CodecResult) { v.DecodePrefix = nil },
		} {
			bad = choiceCodecControl(f)
			change(&bad[0])
			if judgeChoiceCodec(f, bad, "")[0].Verdict != core.Fail {
				t.Fatal("altered output accepted")
			}
		}
		for _, change := range []func(*CodecResult){func(v *CodecResult) { v.DecodeError = "" }, func(v *CodecResult) { v.Decoded = []byte{1} }, func(v *CodecResult) { v.DecodeName = "Ed25519" }, func(v *CodecResult) { v.DecodePrefix = []byte{1} }, func(v *CodecResult) { v.DecodeLength = 32 }, func(v *CodecResult) { v.DecodeSecret = true }} {
			bad = choiceCodecControl(f)
			change(&bad[len(bad)-1])
			if judgeChoiceCodec(f, bad, "")[2].Verdict != core.Pass {
				t.Fatal("diagnostic input incorrectly changes equivalence verdict")
			}
		}
	}
}

type choiceCodecMock struct {
	*coretest.Fixture
	fail bool
}

func (m choiceCodecMock) InspectCodec(_ context.Context, q CodecRequest) (CodecResult, error) {
	if m.fail {
		return CodecResult{}, errors.New("capture failed")
	}
	for _, f := range codecFixtures() {
		for _, v := range choiceCodecControl(f) {
			if v.Request.Name == q.Name && v.Request.Secret == q.Secret && v.Request.Encoded == q.Encoded {
				return v, nil
			}
		}
	}
	return CodecResult{}, errors.New("unknown request")
}
func TestChoiceCodecCases(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendChoiceCodecCases(&p)
	if len(p.Cases) != 0 {
		t.Fatal("cross-profile cases")
	}
	p.Name = "did-1.1"
	appendChoiceCodecCases(&p)
	if len(p.Cases) != len(codecFixtures()) {
		t.Fatal(len(p.Cases))
	}
	for _, c := range p.Cases {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, tt := range []struct {
			s    core.Subject
			want core.Verdict
		}{{coretest.New(), core.NotSupported}, {choiceCodecMock{coretest.New(), true}, core.Error}, {choiceCodecMock{coretest.New(), false}, core.Pass}} {
			for _, o := range c.Run(context.Background(), tt.s) {
				if o.Verdict != tt.want {
					t.Fatal(c.ID, o)
				}
			}
		}
	}
}
