package sageresolution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sage-x-project/did-inspector/checks/sourcearith"
)

func TestRepairedResourceProfileBounds(t *testing.T) {
	for _, name := range []string{"unknown", "did-core-1.0"} {
		if _, e := PrimaryResourceProfile(name); e == nil {
			t.Fatal("wrong profile")
		}
	}
	p, e := PrimaryResourceProfile("did-1.1")
	if e != nil || len(p.Cases) != 1 || len(p.Cases[0].Statements) != 1 {
		t.Fatal(e)
	}
	old := urlRoleControls(t)
	for _, s := range []urlRoleMock{{e: old}, {e: old, failSource: true}, {e: old, failHandler: true}} {
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
	original := resourceRepairManifestBytes
	defer func() { resourceRepairManifestBytes = original }()
	resourceRepairManifestBytes = []byte("{")
	if _, e := PrimaryResourceProfile("did-1.1"); e == nil {
		t.Fatal("invalid manifest")
	}
}
func TestResourceRepairSourceBounds(t *testing.T) {
	newSource := func() urlRoleEvidence {
		e := urlRoleControls(t)
		m := ResourceRepairManifest{Module: IntegerSourceModule, Version: IntegerSourceVersion}
		e.Source.Request = resourceRepairSourceRequest(m)
		files, _, err := sourcearith.ArchiveFiles(e.Source.Archive, IntegerSourceModule+"@"+IntegerSourceVersion)
		if err != nil {
			t.Fatal(err)
		}
		e.Source.Files = sourcearith.SourceFiles(files, e.Source.Request.Packages)
		return e
	}
	old := newSource()
	m := ResourceRepairManifest{Module: IntegerSourceModule, Version: IntegerSourceVersion, Sum: IntegerSourceSum, SourceFiles: map[string]string{}}
	for n, b := range old.Source.Files {
		m.SourceFiles[n] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	for _, mode := range []string{"identity", "archive", "count", "bytes", "review", "typed-guard"} {
		e := newSource()
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
			e.Source.Files["dereferencer/dereferencer.go"] = []byte("other")
		case "review":
			local.SourceFiles["dereferencer/dereferencer.go"] = "other"
		}
		if _, _, err := resourceRepairSource(t.Context(), e.Source, local); err == nil {
			t.Fatal("unreviewed source accepted", mode)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, e := resourceRepairSource(ctx, old.Source, m); e == nil {
		t.Fatal("cancelled analysis")
	}
}
func TestResourceRepairAuditBounds(t *testing.T) {
	// Authored data controls exercise the verifier, never simulate subject execution.
	for _, mode := range []string{"positive", "roots", "unknown", "steps", "operand", "extraction", "frame", "hex"} {
		var a sourcearith.ServiceAudit
		if json.Unmarshal(urlRoleWitness, &a) != nil {
			t.Fatal("witness")
		}
		a.Steps[0].Correct = true
		a.Steps[0].Expressions = []string{"u.WithoutFragment()"}
		switch mode {
		case "roots":
			a.Roots = nil
		case "unknown":
			a.Unknown = []string{"missing"}
		case "steps":
			a.Steps = nil
		case "operand":
			a.Steps[0].Expressions = []string{"u"}
		case "extraction":
			a.Steps[1].Correct = false
		case "frame":
			delete(a.Frames, a.Roots[0])
		case "hex":
			a.Frames["extra"] = "invalid"
		}
		if err := resourceRepairAudit(a); (err == nil) != (mode == "positive") {
			t.Fatal(mode, err)
		}
	}
}
func TestRepairedResourceJudgeRefusesMissingEvidence(t *testing.T) {
	m, _ := resourceRepairManifest()
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
		for _, o := range judgeRepairedResource(ctx, resourceRepairEvidence{}, local, "unit") {
			if o.Verdict != "ERROR" {
				t.Fatal(mode, o)
			}
			var e resourceRepairEvidence
			if json.Unmarshal([]byte(o.Observed), &e) != nil || e.Error == "" {
				t.Fatal("diagnostic lost")
			}
		}
	}
}
