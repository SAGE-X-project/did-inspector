package sage

import (
	"context"
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"os"
	"runtime/debug"
	"testing"
)

func TestActualMultihashAndItemIntegration(t *testing.T) {
	s, _ := sourceTest(t)
	p, err := sageresolution.Profile("did-1.1")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, c := range p.Cases {
		if c.ID == "did-1.1/sage-resolution/multihash-component-operations" || c.ID == "did-1.1/sage-resolution/item-expansion-conditions" {
			found++
			for _, o := range c.Run(t.Context(), s) {
				want := core.Pass
				if o.Statement == "res10-crd20261001#resolving-algorithm.29" {
					want = core.Fail
				}
				if o.Verdict != want {
					t.Fatal(o.Statement, o.Verdict, o.Observed)
				}
			}
		}
	}
	if found != 2 {
		t.Fatal(found)
	}
}
func TestMultihashObserverBoundaries(t *testing.T) {
	s, _ := sourceTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.InspectMultihash(ctx, sageresolution.MultihashRequest{}); err == nil {
		t.Fatal("cancel")
	}
	if _, err := s.InspectMultihash(t.Context(), sageresolution.MultihashRequest{Operation: "other"}); err == nil {
		t.Fatal("unknown")
	}
	raw, err := os.ReadFile("../../profiles/sageresolution/multihash.json")
	if err != nil {
		t.Fatal(err)
	}
	var fs []struct {
		Request sageresolution.MultihashRequest
	}
	if json.Unmarshal(raw, &fs) != nil {
		t.Fatal("fixture")
	}
	for _, f := range fs {
		v, err := s.InspectMultihash(t.Context(), f.Request)
		if err != nil || v.Operation == "" {
			t.Fatal(err)
		}
	}
}

func TestComponentObserverBuildIdentity(t *testing.T) {
	s, _ := sourceTest(t)
	base, _ := s.sourceObserver.build()
	for _, tc := range []struct {
		read func() (*debug.BuildInfo, bool)
		want bool
	}{
		{func() (*debug.BuildInfo, bool) { return base, true }, true},
		{func() (*debug.BuildInfo, bool) { return nil, false }, false},
		{func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{}, true }, false},
	} {
		_, err := componentObserverIdentity(tc.read)
		if (err == nil) != tc.want {
			t.Fatal("identity")
		}
	}
	base.Deps[1].Replace.Version = "(devel)"
	if _, err := componentObserverIdentity(func() (*debug.BuildInfo, bool) { return base, true }); err != nil {
		t.Fatal("development marker", err)
	}
	for _, change := range []func(*debug.Module){func(m *debug.Module) { m.Version = "other" }, func(m *debug.Module) { m.Replace = nil }, func(m *debug.Module) { m.Replace.Version = "other" }, func(m *debug.Module) { m.Replace.Sum = "h1:other" }, func(m *debug.Module) { m.Replace.Path = "other" }} {
		s, _ := sourceTest(t)
		base, _ := s.sourceObserver.build()
		change(base.Deps[1])
		s.sourceObserver.build = func() (*debug.BuildInfo, bool) { return base, true }
		if _, err := s.InspectMultihash(t.Context(), sageresolution.MultihashRequest{Operation: "encode", Code: 0x12, Digest: make([]byte, 32)}); err == nil {
			t.Fatal("unselected observer")
		}
	}
}
