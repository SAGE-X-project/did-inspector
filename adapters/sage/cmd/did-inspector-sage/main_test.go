package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"context"
	"encoding/json"
	"errors"
	"github.com/sage-x-project/did-inspector/adapters/sage"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageprojection"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"github.com/sage-x-project/did-inspector/report"
	"os/exec"
)

func testEnv() (env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return env{
		stdout:   &out,
		stderr:   &errb,
		subject:  func() (core.Subject, error) { return unitSubject{}, nil },
		now:      func() time.Time { return time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC) },
		revision: "rev",
	}, &out, &errb
}

func TestRunWritesReport(t *testing.T) {
	for _, p := range []string{"did-core-1.0", "did-1.1"} {
		e, out, _ := testEnv()
		path := filepath.Join(t.TempDir(), "r.json")
		if code := run([]string{"--profile", p, "--out", path, "--inspector-revision", "abc"}, e); code != 0 {
			t.Fatalf("%s: exit %d", p, code)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := report.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Profile != p || rep.Subject.Name != "unit-projection" || rep.Inspector.Revision != "abc" || rep.StartedAt == "" {
			t.Errorf("%s: report header %+v", p, rep)
		}
		// did-go must pass the gate at the pinned revision: no
		// requirement-level statement may be FAIL or ERROR.
		if rep.Totals.Error != 0 {
			t.Errorf("%s: %d ERROR", p, rep.Totals.Error)
		}
		for _, st := range rep.GateFailures() {
			t.Errorf("%s: %s %s", p, st.ID, st.Verdict)
		}
		if !strings.Contains(out.String(), "gate:") {
			t.Errorf("%s: summary without gate line", p)
		}
		if !strings.Contains(out.String(), "profile:   "+p) {
			t.Errorf("%s: summary %q", p, out.String())
		}
	}
}

func TestRunDeterministic(t *testing.T) {
	var reports [2][]byte
	for i := range reports {
		e, _, _ := testEnv()
		e.now = time.Now
		path := filepath.Join(t.TempDir(), "r.json")
		if code := run([]string{"--profile", "did-1.1", "--deterministic", "--out", path}, e); code != 0 {
			t.Fatalf("exit %d", code)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		reports[i] = data
	}
	if !bytes.Equal(reports[0], reports[1]) {
		t.Error("two deterministic runs differ")
	}
	if !bytes.Contains(reports[0], []byte(`"started_at": ""`)) || !bytes.Contains(reports[0], []byte(`"revision": "rev"`)) {
		t.Error("deterministic report carries a run time or lost the revision")
	}
}

func TestRunErrors(t *testing.T) {
	cases := []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"--bogus"}, 2},
		{[]string{"--profile", "did-1.1", "extra"}, 2},
		{[]string{"--profile", "did-9"}, 2},
		{[]string{"--profile", "did-1.1", "--case-timeout", "0"}, 2},
		{[]string{"--profile", "did-1.1", "--case-timeout", "-1s"}, 2},
		{[]string{"--profile", "did-1.1", "--case-timeout", "bad"}, 2},
		{[]string{"--profile", "did-1.1", "--out", filepath.Join(t.TempDir(), "missing", "r.json")}, 1},
	}
	for _, c := range cases {
		e, _, errb := testEnv()
		if code := run(c.args, e); code != c.code || errb.Len() == 0 {
			t.Errorf("%v: exit %d (stderr %q), want %d", c.args, code, errb.String(), c.code)
		}
	}
	e, _, _ := testEnv()
	e.subject = func() (core.Subject, error) { return nil, nil }
	if code := run([]string{"--profile", "did-1.1"}, e); code != 1 {
		t.Errorf("nil subject: exit %d", code)
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
	for i, c := range cases {
		if got := buildRevision(c.read); got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
}

type unitSubject struct{}

func (unitSubject) Describe() core.SubjectInfo {
	return core.SubjectInfo{Name: "unit-projection", Revision: "unit"}
}
func (unitSubject) Supports(string, core.Capability) bool { return false }
func (unitSubject) Project(_ context.Context, _ sageprojection.Record, version string) (sageprojection.Result, error) {
	mt := "application/did+json"
	if version == "1.1" {
		mt = "application/did"
	}
	return sageprojection.Result{Raw: []byte(`{"id":"did:sage:web:registry.example:agent-1","verificationMethod":[],"service":[],"@context":"https://www.w3.org/ns/did/v1.1"}`), MediaType: mt}, nil
}
func TestRawEvidenceAndFactoryFailures(t *testing.T) {
	e, out, _ := testEnv()
	raw := filepath.Join(t.TempDir(), "raw.json")
	if run([]string{"--profile", "did-1.1", "--raw-out", raw}, e) != 0 {
		t.Fatal("raw output")
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	var r core.RunResult
	if err = json.Unmarshal(data, &r); err != nil || len(r.Cases) != 6 {
		t.Fatal("raw result", err)
	}
	if !strings.Contains(out.String(), "full standard conformance is NOT_ESTABLISHED") {
		t.Fatal("scope absent")
	}
	e, _, _ = testEnv()
	if run([]string{"--profile", "did-1.1", "--raw-out", filepath.Join(t.TempDir(), "missing", "raw.json")}, e) != 1 {
		t.Fatal("raw write failure")
	}
	e, _, _ = testEnv()
	e.subject = func() (core.Subject, error) { return nil, errors.New("unpinned source") }
	if run([]string{"--profile", "did-1.1"}, e) != 1 {
		t.Fatal("factory error")
	}
	e, _, _ = testEnv()
	e.stdout = failWriter{}
	if run([]string{"--profile", "did-1.1"}, e) != 1 {
		t.Fatal("scope write error")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("fixture output failure") }
func TestNativeProjectionCLI(t *testing.T) {
	goBin := os.Getenv("DID_INSPECTION_GO")
	if goBin == "" {
		goBin = "go"
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "did-inspector-sage")
	command := exec.Command(goBin, "build", "-mod=readonly", "-trimpath", "-o", binary, ".")
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, raw)
	}
	for _, profile := range []string{"did-core-1.0", "did-1.1"} {
		path := filepath.Join(dir, profile+".json")
		rawPath := filepath.Join(dir, profile+"-raw.json")
		command = exec.Command(binary, "--profile", profile, "--deterministic", "--inspector-revision", "native-test", "--out", path, "--raw-out", rawPath)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("runtime: %v %s", err, output)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		r, err := report.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		want := 16
		if profile == "did-1.1" {
			want = 20
		}
		if r.Subject.Name != "did-go/advanced/sage-projection" || r.Subject.Revision != "2ef282b40ccfe243c6cf3b1c05594e02171126cc" || r.Totals.Pass != want || len(r.GateFailures()) != 0 {
			t.Fatal("actual subject/profile drift", r.Totals)
		}
		data, err = os.ReadFile(rawPath)
		if err != nil {
			t.Fatal(err)
		}
		var raw core.RunResult
		if err = json.Unmarshal(data, &raw); err != nil || len(raw.Cases) != 6 {
			t.Fatal("native raw evidence")
		}
		for _, c := range raw.Cases {
			for _, o := range c.Observations {
				if !strings.HasPrefix(o.Input, "{\"did\"") || !strings.Contains(o.Observed, "document=") {
					t.Fatal("lost actual observation bytes")
				}
			}
		}
	}
}

func TestReportAndRawOutputsCannotOverwriteEachOther(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	e, _, _ := testEnv()
	if run([]string{"--profile", "did-1.1", "--out", path, "--raw-out", filepath.Join(dir, ".", "report.json")}, e) != 2 {
		t.Fatal("same output path")
	}
	if err := os.WriteFile(path, []byte("control"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	e, _, _ = testEnv()
	if run([]string{"--profile", "did-1.1", "--out", path, "--raw-out", alias}, e) != 2 {
		t.Fatal("same file alias")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "control" {
		t.Fatal("existing evidence modified")
	}
	e, _, _ = testEnv()
	e.now = func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }
	if run([]string{"--profile", "did-1.1", "--raw-out", filepath.Join(dir, "bad-time.json")}, e) != 1 {
		t.Fatal("invalid raw timestamp accepted")
	}
}

func TestResolutionScopeAndNativeCLI(t *testing.T) {
	e, _, _ := testEnv()
	if run([]string{"--profile", "did-1.1", "--scope", "bad"}, e) != 2 {
		t.Fatal("unknown scope")
	}
	e.subject = func() (core.Subject, error) { return &sage.Subject{}, nil }
	path := filepath.Join(t.TempDir(), "unit.json")
	if run([]string{"--profile", "did-1.1", "--scope", "resolution", "--case-timeout", "30s", "--out", path, "--raw-out", path + ".raw"}, e) != 0 {
		t.Fatal("resolution scope")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := report.Decode(data)
	if err != nil || r.Subject.Name != "did-go/advanced/sage-resolution" || r.Totals.Pass != 340 {
		raw, _ := os.ReadFile(path + ".raw")
		var x struct {
			Cases []struct {
				Case         string             `json:"case"`
				Observations []core.Observation `json:"observations"`
			} `json:"cases"`
		}
		_ = json.Unmarshal(raw, &x)
		for _, c := range x.Cases {
			if strings.HasSuffix(c.Case, "/integer-source-arithmetic") && len(c.Observations) > 0 {
				var v struct {
					Error string `json:"analysis_error"`
				}
				_ = json.Unmarshal([]byte(c.Observations[0].Observed), &v)
				t.Log("source failure", c.Observations[0].Detail, v.Error)
			}
		}
		t.Fatal("scope identity", err, r.Totals)
	}
	binary := filepath.Join(t.TempDir(), "sage-inspector")
	cmd := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-o", binary, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %v %s", err, out)
	}
	// Missing standard-library source is an evidence error, never a PASS.
	missingPath := filepath.Join(t.TempDir(), "missing-source.json")
	missing := exec.Command(binary, "--case-timeout", "30s", "--scope", "resolution", "--profile", "did-1.1", "--deterministic", "--out", missingPath)
	missing.Env = append(os.Environ(), "GOROOT=")
	if output, e := missing.CombinedOutput(); e != nil {
		t.Fatalf("missing-source run failed: %v %s", e, output)
	}
	missingData, err := os.ReadFile(missingPath)
	if err != nil {
		t.Fatal(err)
	}
	missingReport, err := report.Decode(missingData)
	if err != nil || missingReport.Totals.Error != 23 || missingReport.Totals.Pass != 317 {
		t.Fatal("missing source accepted", err, missingReport.Totals)
	}
	missingErrors := map[string]bool{}
	for _, row := range missingReport.Statements {
		if row.Verdict == core.Error {
			missingErrors[row.ID] = true
		}
	}
	if len(missingErrors) != 23 {
		t.Fatal("wrong source error count", missingErrors)
	}
	for _, id := range []string{"cid10#base-encode.1", "cid10#base-decode.1", "cid10#base-encode.8", "cid10#base-encode.9", "cid10#base-encode.10", "cid10#base-decode.9", "cid10#base-decode.10", "cid10#base-decode.11", "cid10#base-encode.6", "cid10#base-encode.11", "cid10#base-decode.2", "cid10#base-decode.7", "cid10#base-decode.12", "cid10#base-decode.13", "cid10#base-encode.5", "cid10#base-encode.12", "cid10#base-decode.6", "cid10#base-encode.2", "cid10#base-encode.3", "cid10#base-decode.3", "cid10#base-decode.4", "cid10#base-encode.7", "cid10#base-decode.8"} {
		if !missingErrors[id] {
			t.Fatal("source errors assigned to wrong clauses", missingErrors)
		}
	}
	// A trimmed binary has no embedded toolchain source path. Supply the
	// installed Go source tree explicitly, as the CI observer does.
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"did-core-1.0", "did-1.1"} {
		dir := t.TempDir()
		reportPath := filepath.Join(dir, "report.json")
		rawPath := filepath.Join(dir, "raw.json")
		cmd = exec.Command(binary, "--case-timeout", "30s", "--scope", "resolution", "--profile", profile, "--deterministic", "--out", reportPath, "--raw-out", rawPath)
		cmd.Env = append(os.Environ(), "GOROOT="+strings.TrimSpace(string(root)))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native %v %s", err, out)
		}
		data, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatal(err)
		}
		r, err = report.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		want, cases := 33, 16
		if profile == "did-1.1" {
			want, cases = 340, 350
		}
		if profile == "did-1.1" && (r.Totals.NotApplicable != 4 || r.Totals.NotRun != 133) {
			t.Fatal("native URL conditional evidence", r.Totals)
		}
		if profile == "did-1.1" && (r.Totals.Fail != 9 || r.TotalsByLevel.Recommendation.Fail != 4 || r.TotalsByLevel.Requirement.Fail != 5) {
			t.Fatal("native alg recommendation failure not preserved", r.Totals)
		}
		if r.Totals.Pass != want || !expectedResolutionGate(r) || r.Subject.Name != "did-go/advanced/sage-resolution" || r.Subject.Revision != "2ef282b40ccfe243c6cf3b1c05594e02171126cc" {
			t.Fatal("native scope", r.Totals, r.Subject)
		}
		data, err = os.ReadFile(rawPath)
		if err != nil {
			t.Fatal(err)
		}
		var raw core.RunResult
		if err = json.Unmarshal(data, &raw); err != nil || len(raw.Cases) != cases {
			t.Fatal("raw", err, len(raw.Cases))
		}
		for _, c := range raw.Cases {
			for _, o := range c.Observations {
				if strings.Contains(c.Case, "/key-policy-") || strings.Contains(c.Case, "/optional-") || strings.Contains(c.Case, "/remaining-") || strings.Contains(c.Case, "/choice-") || strings.Contains(c.Case, "/representation-options-") || strings.Contains(c.Case, "/resource-choice-") || strings.Contains(c.Case, "/integer-source-") {
					if o.Input == "" || o.Observed == "" {
						t.Fatal("lost policy evidence")
					}
				} else if strings.Contains(c.Case, "/library-") {
					if o.Input == "" || o.Observed == "" {
						t.Fatal("lost library evidence")
					}
				} else if strings.Contains(c.Case, "/native-producer-context-") {
					if !strings.Contains(o.Input, `"positive"`) || !strings.Contains(o.Input, `"negative"`) {
						t.Fatal("lost producer input pair")
					}
				} else if strings.Contains(c.Case, "/native-typed-production-") || strings.Contains(c.Case, "/native-representation-input-producer-") {
					if !strings.Contains(o.Input, `"fields"`) || !strings.Contains(o.Input, `"json_ld"`) {
						t.Fatal("lost typed request")
					}
				} else if strings.Contains(c.Case, "/native-consumer-") || (strings.Contains(c.Case, "/native-typed-consumption-") || strings.Contains(c.Case, "/native-representation-input-consumer-")) {
					if !strings.Contains(o.Input, `"data"`) || !strings.Contains(o.Input, `"media_type"`) {
						t.Fatal("lost direct library input")
					}
				} else if !strings.Contains(o.Input, `"record"`) {
					t.Fatal("lost input evidence")
				}
				if strings.Contains(c.Case, "/key-policy-") || strings.Contains(c.Case, "/optional-") || strings.Contains(c.Case, "/remaining-") || strings.Contains(c.Case, "/choice-") || strings.Contains(c.Case, "/representation-options-") || strings.Contains(c.Case, "/resource-choice-") || strings.Contains(c.Case, "/integer-source-") {
					if o.Input == "" || o.Observed == "" {
						t.Fatal("lost policy evidence")
					}
				} else if strings.Contains(c.Case, "/library-") {
					if o.Input == "" || o.Observed == "" {
						t.Fatal("lost library evidence")
					}
				} else if strings.Contains(c.Case, "/native-producer-context-") {
					if !strings.Contains(o.Observed, `"calls"`) || !strings.Contains(o.Observed, `"positive"`) || !strings.Contains(o.Observed, `"negative"`) {
						t.Fatal("lost actual producer pair")
					}
				} else if strings.Contains(c.Case, "/native-metadata-") {
					var capture sageresolution.MetadataResult
					if err := json.Unmarshal([]byte(o.Observed), &capture); err != nil || capture.Resolution.Serializer == "" || capture.Document.Serializer == "" || len(capture.Resolution.Bytes) == 0 || len(capture.Document.Bytes) == 0 {
						t.Fatal("lost direct serializer evidence", err)
					}
				} else if strings.Contains(c.Case, "/native-consumer-") || (strings.Contains(c.Case, "/native-typed-consumption-") || strings.Contains(c.Case, "/native-representation-input-consumer-")) {
					if !strings.Contains(o.Observed, `"operation"`) || !strings.Contains(o.Observed, `"input"`) {
						t.Fatal("lost actual consumer capture")
					}
				} else if strings.Contains(c.Case, "/native-typed-production-") || strings.Contains(c.Case, "/native-representation-input-producer-") {
					if !strings.Contains(o.Observed, `"calls"`) || !strings.Contains(o.Observed, `"controller_shape"`) {
						t.Fatal("lost actual typed witnesses")
					}
				} else if !strings.Contains(o.Observed, `"metadata"`) {
					t.Fatal("lost native result evidence")
				}
			}
		}
	}
}

func expectedResolutionGate(r report.Report) bool {
	expected := map[string]bool{}
	if r.Profile == "did-1.1" {
		for _, id := range []string{"cid10#verification-methods.9", "cid10#verification-methods.11", "cid10#conformance.2", "did11-cr20260305#production-and-consumption.18", "res10-crd20261001#dereferencing-algorithm-resource.5"} {
			expected[id] = true
		}
	}
	actual := r.GateFailures()
	if len(actual) != len(expected) {
		return false
	}
	for _, s := range actual {
		if !expected[s.ID] || s.Verdict != core.Fail {
			return false
		}
	}
	return true
}

// A source importer may need more time under race instrumentation; the budget
// is execution policy only. Expiry still produces evidence ERROR, never PASS.
type deadlineSubject struct {
	unitSubject
	remaining *[]time.Duration
	wait      bool
}

func (s deadlineSubject) Project(ctx context.Context, r sageprojection.Record, v string) (sageprojection.Result, error) {
	deadline, _ := ctx.Deadline()
	*s.remaining = append(*s.remaining, time.Until(deadline))
	if s.wait {
		<-ctx.Done()
		return sageprojection.Result{}, ctx.Err()
	}
	return s.unitSubject.Project(ctx, r, v)
}
func TestCaseTimeoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, flag string
		budget     time.Duration
		expire     bool
	}{
		{"default", "", 5 * time.Second, false},
		{"source budget", "30s", 30 * time.Second, false},
		{"expiry", "1ns", time.Nanosecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := testEnv()
			var remaining []time.Duration
			e.subject = func() (core.Subject, error) { return deadlineSubject{remaining: &remaining, wait: tc.expire}, nil }
			path := filepath.Join(t.TempDir(), "report.json")
			args := []string{"--profile", "did-1.1", "--out", path}
			if tc.flag != "" {
				args = append(args, "--case-timeout", tc.flag)
			}
			if run(args, e) != 0 {
				t.Fatal("run did not complete")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := report.Decode(data)
			if err != nil || len(remaining) != 6 {
				t.Fatal("missing timed observations", err, remaining)
			}
			if tc.expire {
				if rep.Totals.Error == 0 || len(rep.GateFailures()) == 0 {
					t.Fatal("timeout became success", rep.Totals)
				}
			} else {
				if rep.Totals.Error != 0 {
					t.Fatal("unexpected evidence error", rep.Totals)
				}
				for _, d := range remaining {
					if d <= 0 || d > tc.budget || d < tc.budget-time.Second {
						t.Fatal("wrong configured deadline", d, tc.budget)
					}
				}
			}
		})
	}
}
