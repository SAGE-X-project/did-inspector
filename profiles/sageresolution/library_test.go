package sageresolution

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func syntaxControl(g syntaxGroup) []SyntaxResult {
	out := []SyntaxResult{}
	for _, item := range g.Items {
		r := SyntaxResult{Operation: syntaxOperation(item.Request.Kind), Request: item.Request, Value: item.Value}
		if !item.Accepted {
			r.Error = "literal opaque rejection"
		}
		out = append(out, r)
	}
	return out
}
func codecControl(f codecFixture) []CodecResult {
	out := []CodecResult{}
	for _, q := range codecRequests(f) {
		out = append(out, CodecResult{Operation: "github.com/sage-x-project/did-go/vm.EncodeMultikey+DecodeMultikey", Request: q, Name: f.Name, Prefix: append([]byte{}, f.Prefix...), Length: f.Length, Secret: f.Secret, Encoded: q.Encoded, Decoded: append([]byte{}, q.Key...), DecodeName: f.Name, DecodePrefix: append([]byte{}, f.Prefix...), DecodeLength: f.Length, DecodeSecret: f.Secret})
	}
	return out
}
func TestSyntaxLiteralControlsAndMutations(t *testing.T) {
	groups, e := syntaxFixtures()
	if e != nil {
		t.Fatal(e)
	}
	for _, g := range groups {
		for _, o := range judgeSyntax(g, syntaxControl(g), "input") {
			if o.Verdict != core.Pass || o.Observed == "" {
				t.Fatal(o)
			}
		}
		for _, change := range []func([]SyntaxResult){func(r []SyntaxResult) { r[0].Operation = "other" }, func(r []SyntaxResult) { r[0].Request.Input = "other" }, func(r []SyntaxResult) { r[0].Error = "rejected" }, func(r []SyntaxResult) { r[0].Value = "normalized incorrectly" }} {
			r := syntaxControl(g)
			change(r)
			if judgeSyntax(g, r, "input")[0].Verdict == core.Pass {
				t.Fatal("false PASS")
			}
		}
		if judgeSyntax(g, nil, "input")[0].Verdict != core.Error {
			t.Fatal("lost calls")
		}
		for i, item := range g.Items {
			if !item.Accepted {
				r := syntaxControl(g)
				r[i].Error = ""
				if judgeSyntax(g, r, "input")[0].Verdict != core.Fail {
					t.Fatal("accepted invalid input")
				}
				break
			}
		}
	}
	original := librarySyntaxBytes
	librarySyntaxBytes = []byte("{")
	defer func() { librarySyntaxBytes = original }()
	if _, e = syntaxFixtures(); e == nil {
		t.Fatal("bad fixture")
	}
	if e = appendLibrarySyntaxCases(&core.Profile{Name: "did-1.1"}); e == nil {
		t.Fatal("bad profile")
	}
	if syntaxOperation("other") != "" {
		t.Fatal("unknown actor")
	}
}
func TestIndependentBase58Controls(t *testing.T) {
	for _, tt := range []struct {
		in   []byte
		want string
	}{{nil, "z"}, {[]byte{0}, "z1"}, {[]byte{0, 0, 1}, "z112"}, {[]byte{57}, "zz"}, {[]byte{58}, "z21"}, {[]byte{255}, "z5Q"}} {
		if got := btcEncode(tt.in); got != tt.want {
			t.Fatal(got, tt.want)
		}
	}
}
func TestCodecLiteralControlsAndMutations(t *testing.T) {
	for _, f := range codecFixtures() {
		if judgeCodec(f, codecControl(f), "input")[0].Verdict != core.Pass {
			t.Fatal(f)
		}
		if judgeCodec(f, nil, "input")[0].Verdict != core.Error {
			t.Fatal("missing calls")
		}
		for _, change := range []func(*CodecResult){
			func(r *CodecResult) { r.Operation = "other" }, func(r *CodecResult) { r.Request.Name = "other" }, func(r *CodecResult) { r.Name = "other" }, func(r *CodecResult) { r.Prefix[0] ^= 1 }, func(r *CodecResult) { r.Length++ }, func(r *CodecResult) { r.Secret = !r.Secret }, func(r *CodecResult) { r.Encoded = "zwrong" }, func(r *CodecResult) { r.EncodeError = "refused" }, func(r *CodecResult) { r.DecodeError = "refused" }, func(r *CodecResult) { r.DecodeName = "other" }, func(r *CodecResult) { r.DecodePrefix[0] ^= 1 }, func(r *CodecResult) { r.DecodeLength++ }, func(r *CodecResult) { r.DecodeSecret = !r.DecodeSecret }, func(r *CodecResult) { r.Decoded[0] ^= 1 },
		} {
			r := codecControl(f)
			change(&r[0])
			if judgeCodec(f, r, "input")[0].Verdict == core.Pass {
				t.Fatal("false PASS", f.Name)
			}
		}
	}
}

type libraryMock struct {
	noOperation
	fail bool
}

func (s libraryMock) InspectSyntax(_ context.Context, q SyntaxRequest) (SyntaxResult, error) {
	if s.fail {
		return SyntaxResult{}, errors.New("adapter failed")
	}
	groups, _ := syntaxFixtures()
	for _, g := range groups {
		for _, r := range syntaxControl(g) {
			if r.Request == q {
				return r, nil
			}
		}
	}
	return SyntaxResult{}, errors.New("unknown fixture")
}
func (s libraryMock) InspectCodec(_ context.Context, q CodecRequest) (CodecResult, error) {
	if s.fail {
		return CodecResult{}, errors.New("adapter failed")
	}
	for _, f := range codecFixtures() {
		for _, r := range codecControl(f) {
			a, _ := json.Marshal(q)
			b, _ := json.Marshal(r.Request)
			if string(a) == string(b) {
				return r, nil
			}
		}
	}
	return CodecResult{}, errors.New("unknown fixture")
}
func TestLibraryProfileDispatch(t *testing.T) {
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p := core.Profile{Name: name}
		if e := appendLibrarySyntaxCases(&p); e != nil {
			t.Fatal(e)
		}
		appendLibraryCodecCases(&p)
		want := 13
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
			}{{libraryMock{}, core.Pass}, {libraryMock{fail: true}, core.Error}, {noOperation{}, core.NotSupported}} {
				for _, o := range c.Run(t.Context(), tt.s) {
					if o.Verdict != tt.v || o.Input == "" || o.Observed == "" {
						t.Fatal(c.ID, o)
					}
				}
			}
		}
	}
}
