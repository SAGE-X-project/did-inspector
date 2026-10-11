package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/core/coretest"
	"github.com/sage-x-project/did-inspector/profiles"
	"github.com/sage-x-project/did-inspector/report"
	"github.com/sage-x-project/did-inspector/statements"
)

const selfTestStatement = "did11-cr20260305#did-syntax.1"

func selfTestCase() core.Case {
	return core.Case{
		ID: "did-1.1/self-test/parse-did", Profile: "did-1.1",
		Statements: []string{selfTestStatement},
		Needs:      []core.Capability{core.CapDIDParser},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got, err := s.(core.DIDParser).ParseDID(coretest.ExampleDID)
			if err != nil || got.Method != "example" {
				return []core.Observation{{Statement: selfTestStatement, Verdict: core.Fail, Expected: "example", Observed: got.Method}}
			}
			return []core.Observation{{Statement: selfTestStatement, Verdict: core.Pass}}
		},
	}
}

// testEnv returns an environment whose did-1.1 profile carries the
// self-test case and whose subjects include a broken fixture.
func testEnv(stdout, stderr *bytes.Buffer) env {
	return env{
		stdout: stdout,
		stderr: stderr,
		registry: func() (*profiles.Registry, error) {
			r := profiles.NewRegistry()
			for _, p := range profiles.Builtin() {
				if p.Name == "did-1.1" {
					p.Cases = append(p.Cases, selfTestCase())
				}
				if err := r.Register(p); err != nil {
					return nil, err
				}
			}
			return r, nil
		},
		subjects: map[string]func() core.Subject{
			"fixture": func() core.Subject { return coretest.New() },
			"broken":  func() core.Subject { return coretest.New().With(core.CapDIDParser, coretest.Wrong) },
			"nil":     func() core.Subject { return nil },
		},
		now:      func() time.Time { return time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC) },
		revision: "test-rev",
	}
}

func TestList(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"list"}, testEnv(&out, &errOut)); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, part := range []string{
		"did-core-1.0\t", "did-1.1\t", "spec keys: did11-cr20260305, cid10, res10-crd20261001",
		"did-1.1/self-test/parse-did statements=" + selfTestStatement + " needs=did-parser",
		"subjects: broken, fixture, nil",
	} {
		if !strings.Contains(out.String(), part) {
			t.Errorf("list lacks %q:\n%s", part, out.String())
		}
	}
}

func TestRunWritesReport(t *testing.T) {
	var out, errOut bytes.Buffer
	path := filepath.Join(t.TempDir(), "report.json")
	code := run([]string{"run", "--profile", "did-1.1", "--subject", "fixture", "--out", path}, testEnv(&out, &errOut))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := report.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Profile != "did-1.1" || rep.Inspector.Revision != "test-rev" || len(rep.Specs) != 3 || rep.StartedAt != "2026-10-12T00:00:00Z" {
		t.Fatalf("report header = %+v", rep)
	}
	var total int
	for _, k := range []string{statements.KeyDID11, statements.KeyCID10, statements.KeyRes10} {
		d, err := statements.Load(k)
		if err != nil {
			t.Fatal(err)
		}
		total += len(d.Statements)
	}
	tt := rep.Totals
	if tt.Statements != total || tt.Pass+tt.Fail+tt.NotSupported+tt.NotApplicable+tt.Error+tt.NotRun != total || tt.Pass == 0 || tt.NotRun == total {
		t.Fatalf("totals = %+v (want %d statements, some judged)", rep.Totals, total)
	}
	for _, s := range rep.Statements {
		if s.Scope == "" {
			t.Fatalf("statement %s has no scope", s.ID)
		}
	}
	if !strings.Contains(out.String(), "profile:   did-1.1") || !strings.Contains(out.String(), report.Disclaimer) {
		t.Errorf("summary:\n%s", out.String())
	}
}

func TestRunBrokenSubjectWithoutOut(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"run", "--profile", "did-1.1", "--subject", "broken"}, testEnv(&out, &errOut))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "FAIL "+selfTestStatement) {
		t.Errorf("summary lacks the failure:\n%s", out.String())
	}
}

func TestRunCore10Profile(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"run", "--profile", "did-core-1.0", "--subject", "fixture"}, testEnv(&out, &errOut)); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "spec:      core10 sha256:5e44345740d9bfaa852d3b66c57e98c9beb6c5bf6083b0126dd5daac377b9993") {
		t.Errorf("summary:\n%s", out.String())
	}
}

func TestRunErrors(t *testing.T) {
	cases := []struct {
		args []string
		code int
		msg  string
	}{
		{nil, 2, "usage:"},
		{[]string{"bogus"}, 2, "unknown command"},
		{[]string{"run"}, 2, "needs --profile and --subject"},
		{[]string{"run", "--nope"}, 2, "flag provided but not defined"},
		{[]string{"run", "--profile", "did-1.1", "--subject", "fixture", "extra"}, 2, "unexpected argument"},
		{[]string{"run", "--profile", "did-9", "--subject", "fixture"}, 1, "unknown profile"},
		{[]string{"run", "--profile", "did-1.1", "--subject", "nope"}, 1, "unknown subject"},
		{[]string{"run", "--profile", "did-1.1", "--subject", "nil"}, 1, "nil subject"},
		{[]string{"run", "--profile", "did-1.1", "--subject", "fixture", "--out", "/nonexistent-dir/x/report.json"}, 1, "no such file"},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		code := run(c.args, testEnv(&out, &errOut))
		if code != c.code || !strings.Contains(errOut.String(), c.msg) {
			t.Errorf("%v: exit %d stderr %q, want %d containing %q", c.args, code, errOut.String(), c.code, c.msg)
		}
	}
}

func TestRegistryError(t *testing.T) {
	var out, errOut bytes.Buffer
	e := testEnv(&out, &errOut)
	e.registry = func() (*profiles.Registry, error) { return nil, errors.New("no registry") }
	for _, args := range [][]string{{"list"}, {"run", "--profile", "did-1.1", "--subject", "fixture"}} {
		errOut.Reset()
		if code := run(args, e); code != 1 || !strings.Contains(errOut.String(), "no registry") {
			t.Errorf("%v: exit %d %q", args, code, errOut.String())
		}
	}
}

func TestHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"help"}, testEnv(&out, &errOut)); code != 0 || !strings.Contains(out.String(), "usage:") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

func TestStatements(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"statements"}, testEnv(&out, &errOut)); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	counts, err := statements.CountByScope()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	rows := len(statements.Levels()) + 1
	if len(lines) != 1+rows*(len(counts)+1) || !strings.Contains(lines[0], "not-checkable") || !strings.Contains(lines[0], "level") ||
		!strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), "all") || !strings.Contains(lines[len(lines)-1], "recommendation") {
		t.Fatalf("output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "core10") {
		t.Errorf("output lacks core10:\n%s", out.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteFailures(t *testing.T) {
	var errOut bytes.Buffer
	e := testEnv(&bytes.Buffer{}, &errOut)
	e.stdout = failingWriter{}
	for _, args := range [][]string{{"list"}, {"statements"}, {"run", "--profile", "did-1.1", "--subject", "fixture"}} {
		if code := run(args, e); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestBuildRevision(t *testing.T) {
	info := func(settings ...debug.BuildSetting) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Settings: settings}, true }
	}
	cases := []struct {
		read func() (*debug.BuildInfo, bool)
		want string
	}{
		{func() (*debug.BuildInfo, bool) { return nil, false }, "devel"},
		{info(), "devel"},
		{info(debug.BuildSetting{Key: "vcs.revision", Value: "abc"}), "abc"},
		{info(debug.BuildSetting{Key: "vcs.revision", Value: "abc"}, debug.BuildSetting{Key: "vcs.modified", Value: "true"}), "abc+dirty"},
	}
	for _, c := range cases {
		if got := buildRevision(c.read); got != c.want {
			t.Errorf("buildRevision = %q, want %q", got, c.want)
		}
	}
}

func TestDefaultEnv(t *testing.T) {
	e := defaultEnv()
	if e.stdout != os.Stdout || e.revision == "" || e.subjects["fixture"] == nil || e.now == nil {
		t.Fatalf("env = %+v", e)
	}
	if _, err := e.registry(); err != nil {
		t.Fatal(err)
	}
}
