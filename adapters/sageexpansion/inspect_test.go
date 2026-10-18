package sageexpansion

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
func TestExpansionProfile(t *testing.T) {
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
		if len(c.Observations) != 2 {
			t.Fatal("case observation count")
		}
		for _, o := range c.Observations {
			var actual struct {
				Runtime []sageresolution.RoutingResult `json:"runtime"`
			}
			if json.Unmarshal([]byte(o.Observed), &actual) != nil || len(actual.Runtime) != 5 {
				t.Fatal("actual expansion calls")
			}
		}

	}
	got := e.Raw.StatementVerdicts()
	expected := []string{"res10-crd20261001#resolving-algorithm.28", "res10-crd20261001#resolving-algorithm.29"}
	if len(got) != 2 {
		t.Fatalf("statements: %v", got)
	}
	for _, id := range expected {
		if got[id] != core.Pass {
			t.Fatalf("%s: %s", id, got[id])
		}
	}
	if e.Report.Totals.Pass != 2 || e.Report.Totals.NotRun != 484 {
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
			p, e := sageresolution.RelativeExpansionProfile(name)
			p.SpecKeys = nil
			return p, e
		},
	} {
		if err := write(io.Discard, "test", &Subject{}, load); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	if err := write(failingWriter{}, "test", &Subject{}, sageresolution.RelativeExpansionProfile); err == nil {
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
		if !strings.Contains(err.Error(), "expansion") || out.Len() != 0 {
			t.Fatalf("identity refusal: %v", err)
		}
	} else {
		var receipt Evidence
		if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.Report.Subject.Revision != Revision {
			t.Fatal("invalid receipt")
		}
	}
}

type brokenRuntime struct{ Subject }

func (*brokenRuntime) InspectRouting(ctx context.Context, q sageresolution.RoutingRequest) (sageresolution.RoutingResult, error) {
	out, e := sage.ObserveRouting(ctx, q)
	out.DataModel = []byte(`{}`)
	return out, e
}
func TestRepairedRuntimeControl(t *testing.T) {
	var b bytes.Buffer
	if err := write(&b, "unit-runtime-control", &brokenRuntime{}, sageresolution.RelativeExpansionProfile); err != nil {
		t.Fatal(err)
	}
	var e Evidence
	if json.Unmarshal(b.Bytes(), &e) != nil || e.Report.Totals.Error != 2 {
		t.Fatal("missing same-call runtime was not an error")
	}
}
