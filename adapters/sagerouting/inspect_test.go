package sagerouting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"strings"
	"testing"

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
	if _, err := subject.InspectRouting(context.Background(), sageresolution.RoutingRequest{Request: sageresolution.Request{Function: "resolve"}}); err == nil {
		t.Fatal("accepted retrieval")
	}
}
func TestRoutingProfile(t *testing.T) {
	var b bytes.Buffer
	if err := inspect(&b, "routing-test", pinned); err != nil {
		t.Fatal(err)
	}
	var e Evidence
	if err := json.Unmarshal(b.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.RuntimeResultsMerged || e.Report.Subject.Revision != Revision || len(e.Raw.Cases) != 12 || len(e.Controls) != 2 {
		t.Fatal("scope or identity")
	}
	got := e.Raw.StatementVerdicts()
	if len(got) != 29 || got["res10-crd20261001#dereferencing-algorithm-resource.5"] != core.Pass {
		t.Fatalf("statements: %v", got)
	}
	for id, verdict := range got {
		if verdict != core.Pass {
			t.Fatalf("%s: %s", id, verdict)
		}
	}
	if e.Report.Totals.Pass != 29 || e.Report.Totals.NotRun != 457 {
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
			p, e := sageresolution.Profile(name)
			p.SpecKeys = nil
			return p, e
		},
	} {
		if err := write(io.Discard, "test", &Subject{}, load); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	if err := write(failingWriter{}, "test", &Subject{}, sageresolution.Profile); err == nil {
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
		if !strings.Contains(err.Error(), "routing") || out.Len() != 0 {
			t.Fatalf("identity refusal: %v", err)
		}
	} else {
		var receipt Evidence
		if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.Report.Subject.Revision != Revision {
			t.Fatal("invalid receipt")
		}
	}
}
