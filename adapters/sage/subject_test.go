package sage

import (
	"context"
	"runtime/debug"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/report"
)

func pinned() (*debug.BuildInfo, bool) {
	return &debug.BuildInfo{Deps: []*debug.Module{{Path: ModulePath, Version: Version}, {Path: "github.com/sage-x-project/did-go", Version: "v0.0.0-20261012015322-ed54c505eafe"}}}, true
}
func TestBuildIdentityFailsClosed(t *testing.T) {
	s, e := identify(pinned)
	if e != nil {
		t.Fatal(e)
	}
	if s.Describe().Revision != "2ef282b40ccfe243c6cf3b1c05594e02171126cc" {
		t.Fatal("revision")
	}
	for _, cap := range core.Capabilities() {
		if s.Supports("did-1.1", cap) {
			t.Fatal("generic capability")
		}
	}
	for _, mode := range []string{"absent", "nil", "version", "replace", "root-version"} {
		_, e := identify(func() (*debug.BuildInfo, bool) {
			bi, _ := pinned()
			switch mode {
			case "absent":
				return nil, false
			case "nil":
				return nil, true
			case "version":
				bi.Deps[0].Version = "wrong"
			case "replace":
				bi.Deps[0].Replace = &debug.Module{Path: "local"}
			case "root-version":
				bi.Deps[1].Version = "wrong"
			}
			return bi, true
		})
		if e == nil {
			t.Fatal(mode)
		}
	}
	// Test binaries can omit dependency identity; New must not invent a pin.
	if s, e := New(); e == nil && s.Describe().Version != Version {
		t.Fatal("invented build identity")
	}
}
func TestActualProjectionProfiles(t *testing.T) {
	s, e := identify(pinned)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"did-core-1.0", "did-1.1"} {
		p, e := sageprojection.Profile(name)
		if e != nil {
			t.Fatal(e)
		}
		res, e := (core.Runner{}).Run(t.Context(), p, s)
		if e != nil {
			t.Fatal(e)
		}
		in, e := report.InputFor(p, res, "unit-native")
		if e != nil {
			t.Fatal(e)
		}
		r := report.Build(in)
		if len(r.GateFailures()) != 0 {
			t.Fatal(r.GateFailures())
		}
		want := 16
		if name == "did-1.1" {
			want = 20
		}
		if r.Totals.Pass != want || r.Totals.NotRun == 0 {
			t.Fatal(r.Totals)
		}
		if name == "did-1.1" && r.Totals.Fail != 1 {
			t.Fatal("recommendation drift")
		}
	}
}
func TestPublicRecordRefusals(t *testing.T) {
	s, e := identify(pinned)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := sageprojection.Fixtures()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Project(t.Context(), rows[0], "other"); e == nil {
		t.Fatal("version")
	}
	bad := rows[0]
	bad.DID = "bad"
	if _, e = s.Project(t.Context(), bad, "1.0"); e == nil {
		t.Fatal("DID translation")
	}
	bad = rows[0]
	bad.Keys = append([]sageprojection.Key(nil), bad.Keys...)
	bad.Keys[0].MaterialHex = "zz"
	if _, e = s.Project(t.Context(), bad, "1.0"); e == nil {
		t.Fatal("encoding")
	}
	bad.Keys[0].MaterialHex = "01"
	out, e := s.Project(context.Background(), bad, "1.1")
	if e != nil || out.ProblemCode != "record.invalid" || len(out.Raw) != 0 {
		t.Fatalf("invalid record: %v %+v", e, out)
	}
}
