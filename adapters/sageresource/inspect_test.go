package sageresource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/adapters/sage"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
)

func pinned() (*debug.BuildInfo, bool) {
	return &debug.BuildInfo{Deps: []*debug.Module{{Path: ModulePath, Version: Version, Sum: Sum}}}, true
}
func TestIdentity(t *testing.T) {
	subject, err := identify(pinned)
	if err != nil || subject.Describe().Revision != Revision {
		t.Fatalf("identity: %v", err)
	}
	for _, capability := range core.Capabilities() {
		if subject.Supports("did-1.1", capability) {
			t.Fatal("generic capability advertised")
		}
	}
	for _, mode := range []string{"absent", "nil", "missing", "version", "sum", "replace", "duplicate"} {
		_, err := identify(func() (*debug.BuildInfo, bool) {
			b, _ := pinned()
			switch mode {
			case "absent":
				return nil, false
			case "nil":
				return nil, true
			case "missing":
				b.Deps[0].Path = "other"
			case "version":
				b.Deps[0].Version = "wrong"
			case "sum":
				b.Deps[0].Sum = "wrong"
			case "replace":
				b.Deps[0].Replace = &debug.Module{Path: "local"}
			case "duplicate":
				b.Deps = append(b.Deps, b.Deps[0])
			}
			return b, true
		})
		if err == nil {
			t.Fatalf("accepted identity %s", mode)
		}
	}
	if _, err := subject.InspectRouting(context.Background(), sageresolution.RoutingRequest{}); err == nil {
		t.Fatal("accepted retrieval")
	}
}
func TestResourceProfile(t *testing.T) {
	var b bytes.Buffer
	if err := inspect(&b, "consumer-test", pinned); err != nil {
		t.Fatal(err)
	}
	var e Evidence
	if err := json.Unmarshal(b.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.RuntimeResultsMerged || e.Report.Subject.Revision != Revision || len(e.Raw.Cases) != 1 {
		t.Fatal("scope or identity")
	}
	for _, c := range e.Raw.Cases {
		if len(c.Observations) != 1 {
			t.Fatal("case observation count")
		}
		for _, o := range c.Observations {
			var actual struct {
				Runtime []sageresolution.RoutingResult `json:"runtime"`
			}
			if json.Unmarshal([]byte(o.Observed), &actual) != nil || len(actual.Runtime) != 7 {
				t.Fatal("actual resource calls")
			}
		}

	}
	got := e.Raw.StatementVerdicts()
	expected := []string{"res10-crd20261001#dereferencing-algorithm-resource.11"}
	if len(got) != 1 {
		t.Fatalf("statements: %v", got)
	}
	for _, id := range expected {
		if got[id] != core.Pass {
			var detail struct {
				Error string `json:"analysis_error"`
			}
			_ = json.Unmarshal([]byte(e.Raw.Cases[0].Observations[0].Observed), &detail)
			t.Fatalf("%s: %s (%s)", id, got[id], detail.Error)
		}
	}
	if e.Report.Totals.Pass != 1 || e.Report.Totals.NotRun != 485 {
		t.Fatalf("totals: %+v", e.Report.Totals)
	}
	if err := inspect(io.Discard, "", pinned); err == nil {
		t.Fatal("missing revision")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("writer failed") }
func TestReportFailures(t *testing.T) {
	for _, load := range []func(string) (core.Profile, error){
		func(string) (core.Profile, error) { return core.Profile{}, errors.New("load failed") },
		func(string) (core.Profile, error) { return core.Profile{}, nil },
		func(name string) (core.Profile, error) {
			p, e := sageresolution.PrimaryResourceProfile(name)
			p.SpecKeys = nil
			return p, e
		},
	} {
		if err := write(io.Discard, "test", &Subject{}, load); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	if err := write(failingWriter{}, "test", &Subject{}, sageresolution.PrimaryResourceProfile); err == nil {
		t.Fatal("writer error lost")
	}
}

func TestInspectionRejectsMissingBuildIdentity(t *testing.T) {
	if err := inspect(io.Discard, "test", func() (*debug.BuildInfo, bool) { return nil, false }); err == nil {
		t.Fatal("missing build identity")
	}
}

func TestProductionEntrypoint(t *testing.T) {
	var out bytes.Buffer
	err := Write(&out, "entrypoint-test")
	if err != nil {
		if !strings.Contains(err.Error(), "resource") || out.Len() != 0 {
			t.Fatalf("identity refusal: %v", err)
		}
	} else {
		var receipt Evidence
		if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.Report.Subject.Revision != Revision {
			t.Fatal("invalid receipt")
		}
	}
}

// The native call is real; these authored receipt changes test only refusal.
type brokenRuntime struct {
	Subject
	mode string
}

func (s *brokenRuntime) InspectRouting(ctx context.Context, q sageresolution.RoutingRequest) (sageresolution.RoutingResult, error) {
	out, e := sage.ObserveRouting(ctx, q)
	switch s.mode {
	case "snapshot":
		out.Result.Snapshot = []byte(`{}`)
	case "document":
		out.DataModel = []byte(`{}`)
	case "fragment":
		for i := range out.ResourceHandler {
			// Restore the exact old, original URL only in the receipt. The subject
			// itself always receives the unchanged native request above.
			if _, fragment, present := strings.Cut(q.Request.Input, "#"); present {
				out.ResourceHandler[i].URL.Input = q.Request.Input
				out.ResourceHandler[i].URL.Fragment = fragment
				out.ResourceHandler[i].URL.HasFragment = true
			}
		}
	case "missing":
		out.ResourceHandler = nil
	}
	return out, e
}
func TestRepairedRuntimeControl(t *testing.T) {
	for _, mode := range []string{"document", "fragment", "missing", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			var b bytes.Buffer
			if err := write(&b, "unit-runtime-control", &brokenRuntime{mode: mode}, sageresolution.PrimaryResourceProfile); err != nil {
				t.Fatal(err)
			}
			var e Evidence
			if json.Unmarshal(b.Bytes(), &e) != nil || e.Report.Totals.Error != 1 {
				t.Fatal("missing same-call runtime was not an error")
			}
		})
	}
}
