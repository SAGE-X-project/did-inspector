package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/checks/sourcearith"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
	"strings"
	"testing"
)

func multihashControls(t *testing.T) multihashEvidence {
	v := sourceControl(t)
	v.Request = multihashSourceRequest()
	v.Diagnostics = []CodecResult{}
	files, _, err := sourcearith.ArchiveFiles(v.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
	if err != nil {
		t.Fatal(err)
	}
	v.Files = sourcearith.SourceFiles(files, v.Request.Packages)
	e := multihashEvidence{Source: v, Calls: map[string]MultihashResult{}, Errors: map[string]string{}}
	for _, f := range multihashFixtures() {
		operation := "EncodeMultihash"
		if f.Request.Operation == "decode" {
			operation = "DecodeMultihash"
		}
		v := MultihashResult{Observer: ComponentObserver{Module: ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", Compiler: "go1.26.8"}, Request: f.Request, Role: MultihashRole, Operation: IntegerSourceModule + "/internal/multiformats." + operation, Encoded: f.Encoded, Code: f.Code, Digest: f.Digest}
		if f.Reject || f.Diagnostic {
			v.Error = "literal rejection"
		}
		e.Calls[f.Name] = v
	}
	return e
}
func TestMultihashIndependentByteAndLengthOracles(t *testing.T) {
	e := multihashControls(t)
	o := judgeMultihash(t.Context(), e, "unit")
	if len(o) != 2 || o[0].Verdict != core.Pass || o[1].Verdict != core.Pass {
		t.Fatal(o)
	}
	for _, f := range multihashFixtures() {
		v := e.Calls[f.Name]
		want := core.Pass
		if f.Diagnostic {
			want = core.NotApplicable
		}
		if multihashCallVerdict(f, v) != want {
			t.Fatal(f.Name)
		}
		v.Role = "other"
		if multihashCallVerdict(f, v) != core.Error {
			t.Fatal("binding")
		}
	}
	for _, name := range []string{"encode-sha2-256", "decode-sha2-256", "decode-sha2-256-actual-short"} {
		f := multihashFixture{}
		for _, candidate := range multihashFixtures() {
			if candidate.Name == name {
				f = candidate
			}
		}
		v := e.Calls[name]
		v.Encoded = nil
		v.Code = 0
		v.Digest = nil
		v.Error = ""
		if multihashCallVerdict(f, v) != core.Fail {
			t.Fatal(name)
		}
		if !f.Reject {
			v.Error = "rejected valid"
			if multihashCallVerdict(f, v) != core.Fail {
				t.Fatal("valid rejection")
			}
		}
	}
	f := multihashFixtures()[0]
	v := e.Calls[f.Name]
	v.Observer.ReplacementVersion = "(devel)"
	if multihashCallVerdict(f, v) != core.Pass {
		t.Fatal("local development marker")
	}
	v.Observer.ReplacementVersion = "other"
	if multihashCallVerdict(f, v) != core.Error {
		t.Fatal("remote version")
	}
	v.Observer.ReplacementVersion = ""
	v.Observer.ReplacementSum = "h1:other"
	if multihashCallVerdict(f, v) != core.Error {
		t.Fatal("versioned replacement")
	}
	// Diagnostic outcome values and partial rejection data are not a normative oracle.
	for _, f := range multihashFixtures() {
		if f.Diagnostic || f.Reject {
			v := e.Calls[f.Name]
			v.Encoded = []byte("diagnostic")
			v.Code = 999
			v.Digest = []byte("diagnostic")
			if f.Diagnostic {
				v.Error = ""
			}
			e.Calls[f.Name] = v
		}
	}
	o = judgeMultihash(t.Context(), e, "unit")
	if o[0].Verdict != core.Pass || o[1].Verdict != core.Pass {
		t.Fatal("diagnostic coupling")
	}

	// A decoder checking only declared == actual must still fail the independent
	// header-expected-length controls. This changes observations, never subject code.
	e = multihashControls(t)
	for name, v := range e.Calls {
		if strings.Contains(name, "declared-actual-") {
			v.Error = ""
			v.Code = uint64(v.Request.Encoded[0])
			v.Digest = v.Request.Encoded[2:]
			e.Calls[name] = v
		}
	}
	o = judgeMultihash(t.Context(), e, "unit")
	if o[0].Verdict != core.Pass || o[1].Verdict != core.Fail {
		t.Fatal("expected length guard omission not detected")
	}
	e = multihashControls(t)
	delete(e.Calls, "encode-sha2-256")
	o = judgeMultihash(t.Context(), e, "unit")
	if o[0].Verdict != core.Error || o[1].Verdict != core.Pass {
		t.Fatal("independent groups")
	}
	e = multihashControls(t)
	e.Errors["decode-sha2-256"] = "lost"
	o = judgeMultihash(t.Context(), e, "unit")
	if o[0].Verdict != core.Pass || o[1].Verdict != core.Error {
		t.Fatal("independent API errors")
	}
}
func TestMultihashSourceAndScope(t *testing.T) {
	for _, change := range []func(*multihashEvidence){func(e *multihashEvidence) { e.Source.Replaced = true }, func(e *multihashEvidence) { e.Source.Archive = nil }, func(e *multihashEvidence) { e.Source.Files = nil }, func(e *multihashEvidence) { e.Source.Files["internal/multiformats/varint.go"] = []byte("changed") }, func(e *multihashEvidence) { e.Error = "lost" }} {
		e := multihashControls(t)
		change(&e)
		for _, o := range judgeMultihash(t.Context(), e, "unit") {
			if o.Verdict != core.Error {
				t.Fatal(o)
			}
		}
	}
	e := multihashControls(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, o := range judgeMultihash(ctx, e, "unit") {
		if o.Verdict != core.Error {
			t.Fatal(o)
		}
	}
	p := core.Profile{Name: "did-core-1.0"}
	appendMultihashCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("scope")
	}
	p.Name = "did-1.1"
	appendMultihashCase(&p)
	if p.Cases[0].Run(t.Context(), noOperation{})[0].Verdict != core.NotSupported {
		t.Fatal("unsupported")
	}
	for _, tc := range []struct {
		s    multihashMock
		want []core.Verdict
	}{{multihashMock{e: e}, []core.Verdict{core.Pass, core.Pass}}, {multihashMock{e: e, sourceError: true}, []core.Verdict{core.Error, core.Error}}, {multihashMock{e: e, callError: true}, []core.Verdict{core.Error, core.Error}}} {
		o := p.Cases[0].Run(t.Context(), tc.s)
		if o[0].Verdict != tc.want[0] || o[1].Verdict != tc.want[1] {
			t.Fatal(o)
		}
	}
}

type multihashMock struct {
	noOperation
	e                      multihashEvidence
	sourceError, callError bool
}

func (s multihashMock) InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error) {
	if s.sourceError {
		return s.e.Source, errors.New("source lost")
	}
	return s.e.Source, nil
}
func (s multihashMock) InspectMultihash(_ context.Context, q MultihashRequest) (MultihashResult, error) {
	for _, v := range s.e.Calls {
		if reflect.DeepEqual(q, v.Request) {
			if s.callError {
				return v, errors.New("call lost")
			}
			return v, nil
		}
	}
	return MultihashResult{}, errors.New("unknown input")
}
