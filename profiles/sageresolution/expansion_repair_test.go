package sageresolution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestRepairedExpansionProfileBounds(t *testing.T) {
	if _, e := RelativeExpansionProfile("unknown"); e == nil {
		t.Fatal("unknown profile")
	}
	if _, e := RelativeExpansionProfile("did-core-1.0"); e == nil {
		t.Fatal("wrong profile")
	}
	p, e := RelativeExpansionProfile("did-1.1")
	if e != nil || len(p.Cases) != 1 {
		t.Fatal(e)
	}
	old := expansionSourceControls(t)
	for _, s := range []expansionSourceMock{{e: old}, {e: old, failSource: true}, {e: old, failRouting: true}} {
		for _, o := range p.Cases[0].Run(t.Context(), s) {
			if o.Verdict == "PASS" {
				t.Fatal("old identity accepted")
			}
		}
	}
	for _, o := range p.Cases[0].Run(t.Context(), noOperation{}) {
		if o.Verdict != "NOT_SUPPORTED" {
			t.Fatal(o)
		}
	}
	original := expansionRepairManifestBytes
	defer func() { expansionRepairManifestBytes = original }()
	expansionRepairManifestBytes = []byte("{")
	if _, e := RelativeExpansionProfile("did-1.1"); e == nil {
		t.Fatal("invalid manifest")
	}
}

func TestRepairSourceBounds(t *testing.T) {
	old := expansionSourceControls(t)
	m := ExpansionRepairManifest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Sum: IntegerSourceSum, SourceFiles: map[string]string{}, FixtureSHA256: fmt.Sprintf("%x", sha256.Sum256(expansionSourceBytes))}
	for name, b := range old.Source.Files {
		m.SourceFiles[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	for _, mode := range []string{"identity", "archive", "count", "bytes", "review", "typed-guard"} {
		e := expansionSourceControls(t)
		local := m
		local.SourceFiles = map[string]string{}
		for n, h := range m.SourceFiles {
			local.SourceFiles[n] = h
		}
		switch mode {
		case "identity":
			e.Source.Version = "other"
		case "archive":
			e.Source.Archive = nil
		case "count":
			e.Source.Files = nil
		case "bytes":
			e.Source.Files["resolver/expand.go"] = []byte("other")
		case "review":
			local.SourceFiles["resolver/expand.go"] = "other"
		}
		if _, _, err := repairSource(t.Context(), e.Source, local); err == nil {
			t.Fatal("unreviewed source accepted", mode)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, e := repairSource(ctx, old.Source, m); e == nil {
		t.Fatal("cancelled analysis")
	}
}

func TestRepairedExpansionJudgeRefusesMissingEvidence(t *testing.T) {
	m, _ := expansionRepairManifest()
	e := expansionRepairEvidence{}
	for _, mode := range []string{"source", "fixture", "cancelled"} {
		local := m
		ctx := t.Context()
		if mode == "fixture" {
			local.FixtureSHA256 = "other"
		}
		if mode == "cancelled" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		for _, o := range judgeRepairedExpansion(ctx, e, local, "unit") {
			if o.Verdict != "ERROR" {
				t.Fatal(mode, o)
			}
			var d expansionRepairEvidence
			if json.Unmarshal([]byte(o.Observed), &d) != nil || d.Error == "" {
				t.Fatal("diagnostic lost")
			}
		}
	}
}
