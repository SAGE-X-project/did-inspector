package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/adapters/didgo"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/report"
)

func testEnv() (env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return env{
		stdout:   &out,
		stderr:   &errb,
		subject:  func() core.Subject { return didgo.New() },
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
		if rep.Profile != p || rep.Subject.Name != didgo.Name || rep.Inspector.Revision != "abc" || rep.StartedAt == "" {
			t.Errorf("%s: report header %+v", p, rep)
		}
		// The exact set of did-go's nonconformances is checked by the
		// adapter's TestProfiles; here only their kind: no ERROR, so every
		// requirement-level failure is a FAIL with observed values.
		if rep.Totals.Error != 0 {
			t.Errorf("%s: %d ERROR", p, rep.Totals.Error)
		}
		for _, st := range rep.GateFailures() {
			if st.Verdict != core.Fail || len(st.Findings) == 0 {
				t.Errorf("%s: %s %s", p, st.ID, st.Verdict)
			}
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
		{[]string{"--profile", "did-1.1", "--out", filepath.Join(t.TempDir(), "missing", "r.json")}, 1},
	}
	for _, c := range cases {
		e, _, errb := testEnv()
		if code := run(c.args, e); code != c.code || errb.Len() == 0 {
			t.Errorf("%v: exit %d (stderr %q), want %d", c.args, code, errb.String(), c.code)
		}
	}
	e, _, _ := testEnv()
	e.subject = func() core.Subject { return nil }
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
