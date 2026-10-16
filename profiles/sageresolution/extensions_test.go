package sageresolution

import (
	"context"
	"errors"
	"github.com/sage-x-project/did-inspector/core"
	"testing"
)

func extensionControls(t *testing.T) extensionEvidence {
	e := extensionEvidence{Source: multihashControls(t).Source}
	observer := ComponentObserver{Module: ComponentObserverModule, Version: "v0.0.0", Replacement: "../sageprobe", Compiler: "go1.26.8"}
	bq := extensionBaseRequests()
	for i, q := range bq {
		v := CapacityResult{Request: q, Observer: observer, Role: MultihashRole}
		op := "EncodeMultibase"
		if i%2 == 0 {
			v.Encoded = bq[i+1].Encoded
		} else {
			op = "DecodeMultibase"
			v.Header = bq[i-1].Header
			v.Data = bq[i-1].Data
		}
		v.Operation = IntegerSourceModule + "/internal/multiformats." + op
		if i >= 4 {
			v.Encoded = ""
			v.Data = nil
			v.Error = "multiformats: header 'f' is not defined by CID 1.0"
		}
		e.Base = append(e.Base, v)
	}
	hq := extensionHashRequests()
	for i, q := range hq {
		v := MultihashResult{Request: q, Observer: observer, Role: MultihashRole}
		op := "EncodeMultihash"
		if i%2 == 0 {
			v.Encoded = hq[i+1].Encoded
		} else {
			op = "DecodeMultihash"
			v.Code = hq[i-1].Code
			v.Digest = hq[i-1].Digest
		}
		v.Operation = IntegerSourceModule + "/internal/multiformats." + op
		if i >= 8 {
			v.Encoded = nil
			v.Digest = nil
			v.Code = 0
			v.Error = "multiformats: Multihash header 0x13 is not defined by CID 1.0"
		}
		e.Hash = append(e.Hash, v)
	}
	return e
}
func TestExtensionIndependentCapabilities(t *testing.T) {
	e := extensionControls(t)
	obs := judgeExtensions(e, "unit")
	for _, o := range obs {
		if o.Verdict != core.NotSupported {
			t.Fatal(o)
		}
	}
	for _, change := range []func(*extensionEvidence){func(e *extensionEvidence) { e.Error = "lost" }, func(e *extensionEvidence) { e.Source.Sum = "other" }} {
		e := extensionControls(t)
		change(&e)
		for _, o := range judgeExtensions(e, "unit") {
			if o.Verdict != core.Error {
				t.Fatal(o)
			}
		}
	}
	for index, change := range []func(*extensionEvidence){func(e *extensionEvidence) { e.Base = nil }, func(e *extensionEvidence) { e.Hash = nil }, func(e *extensionEvidence) { e.BaseError = "lost" }, func(e *extensionEvidence) { e.HashError = "lost" }} {
		e := extensionControls(t)
		change(&e)
		got := judgeExtensions(e, "unit")
		bad := index % 2
		if got[bad].Verdict != core.Error || got[1-bad].Verdict != core.NotSupported {
			t.Fatal(got)
		}
	}
	for _, change := range []func(*CapacityResult){func(v *CapacityResult) { v.Role = "other" }, func(v *CapacityResult) { v.Request.Header = 0 }, func(v *CapacityResult) { v.Observer.Compiler = "other" }, func(v *CapacityResult) { v.Operation = "other" }, func(v *CapacityResult) { v.Error = "unclassified" }, func(v *CapacityResult) { v.Encoded = "changed" }} {
		e := extensionControls(t)
		change(&e.Base[0])
		got := judgeExtensions(e, "unit")
		if got[0].Verdict != core.Error || got[1].Verdict != core.NotSupported {
			t.Fatal(got)
		}
	}
	for _, change := range []func(*MultihashResult){func(v *MultihashResult) { v.Role = "other" }, func(v *MultihashResult) { v.Request.Code = 0 }, func(v *MultihashResult) { v.Observer.Version = "other" }, func(v *MultihashResult) { v.Operation = "other" }, func(v *MultihashResult) { v.Error = "unclassified" }, func(v *MultihashResult) { v.Encoded = nil }} {
		e := extensionControls(t)
		change(&e.Hash[0])
		got := judgeExtensions(e, "unit")
		if got[1].Verdict != core.Error || got[0].Verdict != core.NotSupported {
			t.Fatal(got)
		}
	}
	for i := 4; i < 6; i++ {
		e := extensionControls(t)
		e.Base[i].Error = "unclassified"
		if judgeExtensions(e, "unit")[0].Verdict != core.Error {
			t.Fatal("base refusal class")
		}
		e = extensionControls(t)
		e.Base[i].Data = []byte{1}
		if judgeExtensions(e, "unit")[0].Verdict != core.Error {
			t.Fatal("base partial")
		}
	}
	for i := 8; i < 10; i++ {
		e := extensionControls(t)
		e.Hash[i].Error = "unclassified"
		if judgeExtensions(e, "unit")[1].Verdict != core.Error {
			t.Fatal("hash refusal class")
		}
		e = extensionControls(t)
		e.Hash[i].Encoded = []byte{1}
		if judgeExtensions(e, "unit")[1].Verdict != core.Error {
			t.Fatal("hash partial")
		}
	}
	// A future successful implementation is compared with independent bytes,
	// rather than being forced into the pinned implementation's refusal outcome.
	e = extensionControls(t)
	bq, hq := extensionBaseRequests(), extensionHashRequests()
	for i := 4; i < 6; i++ {
		e.Base[i].Error = ""
		if i%2 == 0 {
			e.Base[i].Encoded = bq[i+1].Encoded
		} else {
			e.Base[i].Data = bq[i-1].Data
		}
	}
	for i := 8; i < 10; i++ {
		e.Hash[i].Error = ""
		if i%2 == 0 {
			e.Hash[i].Encoded = hq[i+1].Encoded
		} else {
			e.Hash[i].Code = hq[i-1].Code
			e.Hash[i].Digest = hq[i-1].Digest
		}
	}
	for _, o := range judgeExtensions(e, "unit") {
		if o.Verdict != core.Pass {
			t.Fatal(o)
		}
	}
	e.Base[4].Encoded = "other"
	e.Hash[8].Encoded = nil
	for _, o := range judgeExtensions(e, "unit") {
		if o.Verdict != core.Error {
			t.Fatal("unexpected success", o)
		}
	}
}

type extensionMock struct {
	noOperation
	e    extensionEvidence
	fail string
}

func (s extensionMock) InspectIntegerSource(context.Context, IntegerSourceRequest) (IntegerSourceResult, error) {
	if s.fail == "source" {
		return s.e.Source, errors.New("lost")
	}
	return s.e.Source, nil
}
func (s extensionMock) InspectMultibaseExtension(_ context.Context, q CapacityRequest) (CapacityResult, error) {
	if s.fail == "base" {
		return CapacityResult{}, errors.New("lost")
	}
	for _, v := range s.e.Base {
		if v.Request.Operation == q.Operation && v.Request.Header == q.Header && v.Request.Encoded == q.Encoded {
			return v, nil
		}
	}
	return CapacityResult{}, nil
}
func (s extensionMock) InspectMultihash(_ context.Context, q MultihashRequest) (MultihashResult, error) {
	if s.fail == "hash" {
		return MultihashResult{}, errors.New("lost")
	}
	for _, v := range s.e.Hash {
		if v.Request.Operation == q.Operation && v.Request.Code == q.Code && string(v.Request.Encoded) == string(q.Encoded) {
			return v, nil
		}
	}
	return MultihashResult{}, nil
}
func TestExtensionDispatch(t *testing.T) {
	p := core.Profile{Name: "did-core-1.0"}
	appendExtensionCodecCase(&p)
	if len(p.Cases) != 0 {
		t.Fatal("profile")
	}
	p.Name = "did-1.1"
	appendExtensionCodecCase(&p)
	if len(p.Cases) != 1 {
		t.Fatal("case")
	}
	if e := p.Cases[0].Validate(); e != nil {
		t.Fatal(e)
	}
	for _, fail := range []string{"", "source", "base", "hash"} {
		for i, o := range p.Cases[0].Run(t.Context(), extensionMock{e: extensionControls(t), fail: fail}) {
			want := core.NotSupported
			if fail == "source" || (fail == "base" && i == 0) || (fail == "hash" && i == 1) {
				want = core.Error
			}
			if o.Verdict != want || o.Input == "" || o.Observed == "" {
				t.Fatal(fail, o)
			}
		}
	}
	// A missing group interface must not suppress the available other observer.
	full := extensionMock{e: extensionControls(t)}
	for index, subject := range []core.Subject{baseOnly{noOperation: noOperation{}, source: full, base: full}, hashOnly{noOperation: noOperation{}, source: full, hash: full}} {
		got := p.Cases[0].Run(t.Context(), subject)
		missing := 1 - index
		if got[missing].Verdict != core.Error || got[index].Verdict != core.NotSupported {
			t.Fatal(got)
		}
	}

	for _, o := range p.Cases[0].Run(t.Context(), noOperation{}) {
		if o.Verdict != core.Error {
			t.Fatal(o)
		}
	}
}

type baseOnly struct {
	noOperation
	source IntegerSourceSubject
	base   MultibaseExtensionSubject
}

func (s baseOnly) InspectIntegerSource(c context.Context, q IntegerSourceRequest) (IntegerSourceResult, error) {
	return s.source.InspectIntegerSource(c, q)
}
func (s baseOnly) InspectMultibaseExtension(c context.Context, q CapacityRequest) (CapacityResult, error) {
	return s.base.InspectMultibaseExtension(c, q)
}

type hashOnly struct {
	noOperation
	source IntegerSourceSubject
	hash   MultihashSubject
}

func (s hashOnly) InspectIntegerSource(c context.Context, q IntegerSourceRequest) (IntegerSourceResult, error) {
	return s.source.InspectIntegerSource(c, q)
}
func (s hashOnly) InspectMultihash(c context.Context, q MultihashRequest) (MultihashResult, error) {
	return s.hash.InspectMultihash(c, q)
}
