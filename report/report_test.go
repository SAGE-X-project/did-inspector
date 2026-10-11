package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

func sampleInput() Input {
	start := time.Date(2026, 10, 12, 1, 0, 0, 0, time.FixedZone("x", 7200))
	return Input{
		InspectorRevision: "abc123",
		Specs:             []Spec{{Key: "k", URL: "https://example.test/k", Source: "sources/k.html", SHA256: "00ff"}},
		Statements: []StatementRef{
			{ID: "k#a.1", Scope: "pending", Level: statements.LevelRequirement},
			{ID: "k#a.2", Scope: "pending", Level: statements.LevelRequirement},
			{ID: "k#a.3", Scope: "not-checkable", Level: statements.LevelRequirement},
			{ID: "k#a.4", Scope: "pending", Level: statements.LevelRecommendation},
			{ID: "k#a.5", Scope: "pending", Level: statements.LevelRecommendation},
		},
		Result: core.RunResult{
			Profile:    "p",
			Subject:    core.SubjectInfo{Name: "s", Version: "1.0", Revision: "r1"},
			StartedAt:  start,
			FinishedAt: start.Add(1500 * time.Millisecond),
			Cases: []core.CaseResult{
				{Case: "c2", Statements: []string{"k#a.2", "k#a.1", "k#a.5"}, Observations: []core.Observation{
					{Statement: "k#a.2", Verdict: core.Fail, Input: "in", Expected: "x", Observed: "y"},
					{Statement: "k#a.1", Verdict: core.Pass},
					{Statement: "k#a.5", Verdict: core.Fail, Input: "rec", Expected: "should", Observed: "did not"},
				}},
				{Case: "c1", Statements: []string{"k#a.1", "k#a.4", "z#b.1"}, Observations: []core.Observation{
					{Statement: "k#a.1", Verdict: core.Pass},
					{Statement: "k#a.1", Verdict: core.Pass},
					{Statement: "k#a.4", Verdict: core.NotSupported, Detail: "no resolver"},
					{Statement: "z#b.1", Verdict: core.Error, Detail: "boom"},
				}},
			},
		},
	}
}

func TestBuild(t *testing.T) {
	r := Build(sampleInput())
	if r.Format != Format || r.Inspector.Revision != "abc123" || r.Profile != "p" || r.Subject.Revision != "r1" {
		t.Fatalf("header = %+v", r)
	}
	if r.StartedAt != "2026-10-11T23:00:00Z" || r.FinishedAt != "2026-10-11T23:00:01.5Z" {
		t.Fatalf("times = %s %s", r.StartedAt, r.FinishedAt)
	}
	ids := []string{}
	for _, s := range r.Statements {
		ids = append(ids, s.ID+"="+string(s.Verdict))
	}
	want := "k#a.1=PASS,k#a.2=FAIL,k#a.3=NOT_RUN,k#a.4=NOT_SUPPORTED,k#a.5=FAIL,z#b.1=ERROR"
	if strings.Join(ids, ",") != want {
		t.Fatalf("statements = %s", strings.Join(ids, ","))
	}
	a1 := r.Statements[0]
	if strings.Join(a1.Cases, ",") != "c2,c1" || len(a1.Findings) != 0 || a1.Scope != "pending" {
		t.Fatalf("a.1 = %+v", a1)
	}
	a2 := r.Statements[1]
	if len(a2.Findings) != 1 || a2.Findings[0].Case != "c2" || a2.Findings[0].Expected != "x" {
		t.Fatalf("a.2 = %+v", a2)
	}
	unknown := r.Statements[5]
	if !unknown.Unknown || unknown.Scope != "" || unknown.Level != "" {
		t.Fatalf("unknown = %+v", unknown)
	}
	if r.Statements[4].Level != statements.LevelRecommendation || !r.Statements[4].IsRecommendation() || r.Statements[1].IsRecommendation() {
		t.Fatalf("levels = %+v", r.Statements)
	}
	tot := r.Totals
	if tot.Statements != 6 || tot.Pass != 1 || tot.Fail != 2 || tot.NotRun != 1 || tot.NotSupported != 1 || tot.Error != 1 || tot.NotApplicable != 0 {
		t.Fatalf("totals = %+v", tot)
	}
	req, rec := r.TotalsByLevel.For(statements.LevelRequirement), r.TotalsByLevel.For(statements.LevelRecommendation)
	if req.Statements != 4 || req.Fail != 1 || req.Error != 1 || req.Pass != 1 || req.NotRun != 1 {
		t.Fatalf("requirement totals = %+v", req)
	}
	if rec.Statements != 2 || rec.Fail != 1 || rec.NotSupported != 1 {
		t.Fatalf("recommendation totals = %+v", rec)
	}
	var gate []string
	for _, s := range r.GateFailures() {
		gate = append(gate, s.ID)
	}
	if strings.Join(gate, ",") != "k#a.2,z#b.1" {
		t.Fatalf("gate failures = %v", gate)
	}
	if strings.Join(r.NotRun, ",") != "k#a.3" {
		t.Fatalf("not run = %v", r.NotRun)
	}
	if len(r.Cases) != 2 || r.Cases[0].ID != "c2" || r.Cases[0].Verdict != core.Fail || r.Cases[1].Verdict != core.Error || r.Cases[1].Observations != 4 {
		t.Fatalf("cases = %+v", r.Cases)
	}
}

func TestBuildEmpty(t *testing.T) {
	r := Build(Input{})
	data, err := r.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"statements": []`, `"cases": []`, `"not_run": []`, `"started_at": ""`} {
		if !strings.Contains(string(data), part) {
			t.Errorf("empty report lacks %s:\n%s", part, data)
		}
	}
}

func TestNotApplicableTotals(t *testing.T) {
	in := Input{
		Statements: []StatementRef{{ID: "k#a.1"}},
		Result: core.RunResult{Cases: []core.CaseResult{{Case: "c", Statements: []string{"k#a.1"},
			Observations: []core.Observation{{Statement: "k#a.1", Verdict: core.NotApplicable, Detail: "n/a"}}}}},
	}
	r := Build(in)
	if r.Totals.NotApplicable != 1 || r.Totals.Count(core.NotApplicable) != 1 || r.Statements[0].Verdict != core.NotApplicable {
		t.Fatalf("report = %+v", r)
	}
	if r.Totals.Count("BOGUS") != 0 {
		t.Fatal("unknown verdict counted")
	}
}

func TestJSONDeterministicAndRoundTrip(t *testing.T) {
	var a, b bytes.Buffer
	if err := Build(sampleInput()).WriteJSON(&a); err != nil {
		t.Fatal(err)
	}
	if err := Build(sampleInput()).WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("JSON output is not deterministic")
	}
	if !strings.Contains(a.String(), `"PASS": 1`) || !strings.Contains(a.String(), `"case": "c2"`) {
		t.Fatalf("unexpected JSON:\n%s", a.String())
	}
	back, err := Decode(a.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	again, err := back.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, a.Bytes()) {
		t.Fatal("decode and encode changed the report")
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := Decode([]byte("{")); err == nil {
		t.Error("broken JSON decoded")
	}
	if _, err := Decode([]byte(`{"format":"other/1"}`)); err == nil || !strings.Contains(err.Error(), "format") {
		t.Errorf("err = %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteErrors(t *testing.T) {
	r := Build(sampleInput())
	if err := r.WriteJSON(failingWriter{}); err == nil {
		t.Error("WriteJSON ignored a write error")
	}
	if err := r.WriteText(failingWriter{}); err == nil {
		t.Error("WriteText ignored a write error")
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := Build(sampleInput()).WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, part := range []string{
		"subject:   s 1.0 (revision r1)",
		"profile:   p",
		"inspector: revision abc123",
		"spec:      k sha256:00ff",
		"statements: 6",
		"  FAIL            2",
		"requirement statements: 4",
		"recommendation statements: 2",
		"gate:      FAIL (2 requirement-level statement(s) FAIL or ERROR)",
		"recommendation findings (not counted by the gate):\n  NOT_SUPPORTED k#a.4",
		"FAIL k#a.5",
		"  NOT_RUN         1",
		"FAIL k#a.2",
		`[c2] FAIL input="in" expected="x" observed="y"`,
		"NOT_SUPPORTED k#a.4",
		`detail="no resolver"`,
		"ERROR z#b.1",
		Disclaimer,
	} {
		if !strings.Contains(out, part) {
			t.Errorf("text lacks %q:\n%s", part, out)
		}
	}
	if strings.Contains(out, "PASS k#a.1") {
		t.Error("text lists a passing statement as a finding")
	}
	buf.Reset()
	if err := Build(Input{}).WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "revision unknown") || strings.Contains(buf.String(), "findings") ||
		!strings.Contains(buf.String(), "gate:      PASS") {
		t.Errorf("empty text:\n%s", buf.String())
	}
}
