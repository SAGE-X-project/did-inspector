package core_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/core/coretest"
)

const profileName = "test-profile"

// parseCase judges a DID parsing statement against the fixture: PASS when
// the subject splits ExampleDID correctly, FAIL otherwise.
func parseCase(id string, stmts ...string) core.Case {
	return core.Case{
		ID:         id,
		Profile:    profileName,
		Statements: stmts,
		Needs:      []core.Capability{core.CapDIDParser},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			p := s.(core.DIDParser)
			got, err := p.ParseDID(coretest.ExampleDID)
			var obs []core.Observation
			for _, st := range stmts {
				o := core.Observation{Statement: st, Input: coretest.ExampleDID, Expected: "method=example id=123"}
				switch {
				case err != nil:
					o.Verdict, o.Observed = core.Fail, "error: "+err.Error()
				case got.Method != "example" || got.MethodSpecificID != "123":
					o.Verdict, o.Observed = core.Fail, "method="+got.Method+" id="+got.MethodSpecificID
				default:
					o.Verdict, o.Expected = core.Pass, ""
				}
				obs = append(obs, o)
			}
			return obs
		},
	}
}

func fixedCase(id string, needs []core.Capability, obs []core.Observation, stmts ...string) core.Case {
	return core.Case{
		ID: id, Profile: profileName, Statements: stmts, Needs: needs,
		Run: func(context.Context, core.Subject) []core.Observation { return obs },
	}
}

func testProfile(cases ...core.Case) core.Profile {
	return core.Profile{Name: profileName, SpecKeys: []string{"k"}, Cases: cases}
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 10, 12, 1, 2, 3, 0, time.FixedZone("x", 3600))
	return func() time.Time { return t }
}

func run(t *testing.T, s core.Subject, cases ...core.Case) core.RunResult {
	t.Helper()
	res, err := core.Runner{Now: fixedClock()}.Run(context.Background(), testProfile(cases...), s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestRunnerCorrectSubjectPasses(t *testing.T) {
	res := run(t, coretest.New(), parseCase("parse", "k#a.1", "k#a.2"))
	if res.Profile != profileName || res.Subject.Name != "fixture" {
		t.Fatalf("result header = %+v", res)
	}
	if !res.StartedAt.Equal(fixedClock()()) || res.StartedAt.Location() != time.UTC {
		t.Errorf("StartedAt = %v", res.StartedAt)
	}
	v := res.StatementVerdicts()
	if v["k#a.1"] != core.Pass || v["k#a.2"] != core.Pass {
		t.Fatalf("verdicts = %v", v)
	}
}

func TestRunnerWrongSubjectFails(t *testing.T) {
	s := coretest.New().With(core.CapDIDParser, coretest.Wrong)
	res := run(t, s, parseCase("parse", "k#a.1"))
	o := res.Cases[0].Observations[0]
	if o.Verdict != core.Fail || o.Expected == "" || !strings.Contains(o.Observed, "method=123") {
		t.Fatalf("observation = %+v", o)
	}
	s = coretest.New().With(core.CapDIDParser, coretest.Fails)
	res = run(t, s, parseCase("parse", "k#a.1"))
	if o := res.Cases[0].Observations[0]; o.Verdict != core.Fail || !strings.Contains(o.Observed, "fixture failure") {
		t.Fatalf("observation = %+v", o)
	}
}

func TestRunnerUnsupportedCapability(t *testing.T) {
	s := coretest.New().Without(core.CapDIDParser)
	res := run(t, s, parseCase("parse", "k#a.1", "k#a.2"))
	for _, o := range res.Cases[0].Observations {
		if o.Verdict != core.NotSupported || !strings.Contains(o.Detail, "does not support did-parser") {
			t.Fatalf("observation = %+v", o)
		}
	}
	if len(res.Cases[0].Observations) != 2 {
		t.Fatalf("got %d observations", len(res.Cases[0].Observations))
	}
}

func TestRunnerDeclaredButNotImplemented(t *testing.T) {
	res := run(t, coretest.Bare{DeclareAll: true}, parseCase("parse", "k#a.1"))
	if o := res.Cases[0].Observations[0]; o.Verdict != core.Error || !strings.Contains(o.Detail, "does not implement") {
		t.Fatalf("observation = %+v", o)
	}
}

func TestRunnerRecoversFromPanics(t *testing.T) {
	s := coretest.New().With(core.CapDIDParser, coretest.Panics)
	res := run(t, s, parseCase("parse", "k#a.1"), parseCase("after", "k#b.1"))
	if o := res.Cases[0].Observations[0]; o.Verdict != core.Error || !strings.Contains(o.Detail, "panicked") {
		t.Fatalf("observation = %+v", o)
	}
	if len(res.Cases) != 2 {
		t.Fatal("runner stopped after a panic")
	}
}

type panickingSubject struct{ coretest.Bare }

func (panickingSubject) Supports(string, core.Capability) bool { panic("supports") }

func TestRunnerRecoversFromPanickingSupports(t *testing.T) {
	res := run(t, panickingSubject{}, parseCase("parse", "k#a.1"))
	if o := res.Cases[0].Observations[0]; o.Verdict != core.Error {
		t.Fatalf("observation = %+v", o)
	}
}

type panickingDescribe struct{ coretest.Bare }

func (panickingDescribe) Describe() core.SubjectInfo { panic("describe") }

func TestRunnerErrors(t *testing.T) {
	r := core.Runner{}
	if _, err := r.Run(context.Background(), testProfile(), nil); err == nil {
		t.Error("nil subject accepted")
	}
	if _, err := r.Run(context.Background(), core.Profile{}, coretest.New()); err == nil {
		t.Error("invalid profile accepted")
	}
	if _, err := r.Run(context.Background(), testProfile(), panickingDescribe{}); err == nil {
		t.Error("panicking Describe accepted")
	}
	res, err := r.Run(context.Background(), testProfile(), coretest.New())
	if err != nil || len(res.Cases) != 0 || res.StartedAt.IsZero() {
		t.Errorf("empty profile: %+v %v", res, err)
	}
}

func TestRunnerIllFormedObservations(t *testing.T) {
	cases := []struct {
		name   string
		obs    []core.Observation
		detail string
	}{
		{"none", nil, "no observation"},
		{"unnamed statement", []core.Observation{{Statement: "k#other.1", Verdict: core.Pass}}, "does not name"},
		{"not-run verdict", []core.Observation{{Statement: "k#a.1", Verdict: core.NotRun}}, "cannot carry"},
		{"unknown verdict", []core.Observation{{Statement: "k#a.1", Verdict: "MAYBE"}}, "cannot carry"},
		{"fail without values", []core.Observation{{Statement: "k#a.1", Verdict: core.Fail}}, "without expected"},
	}
	for _, c := range cases {
		res := run(t, coretest.New(), fixedCase("c", nil, c.obs, "k#a.1"))
		o := res.Cases[0].Observations[0]
		if o.Verdict != core.Error || !strings.Contains(o.Detail, c.detail) {
			t.Errorf("%s: observation = %+v", c.name, o)
		}
	}
}

func TestRunnerUnnamedStatementKeepsFail(t *testing.T) {
	obs := []core.Observation{
		{Statement: "k#a.1", Verdict: core.Fail, Expected: "x", Observed: "y"},
		{Statement: "k#a.2", Verdict: core.Pass},
		{Statement: "k#zz.1", Verdict: core.Pass},
	}
	res := run(t, coretest.New(), fixedCase("c", nil, obs, "k#a.1", "k#a.2"))
	v := res.StatementVerdicts()
	if v["k#a.1"] != core.Fail || v["k#a.2"] != core.Error {
		t.Fatalf("verdicts = %v", v)
	}
	if _, ok := v["k#zz.1"]; ok {
		t.Fatal("observation of an unnamed statement was kept")
	}
}

func TestRunnerKeepsWellFormedObservations(t *testing.T) {
	obs := []core.Observation{
		{Statement: "k#a.1", Verdict: core.Pass},
		{Statement: "k#a.1", Verdict: core.NotApplicable, Detail: "n/a"},
		{Statement: "k#a.2", Verdict: core.Fail, Expected: "x", Observed: "y"},
	}
	res := run(t, coretest.New(), fixedCase("c", nil, obs, "k#a.1", "k#a.2"))
	if len(res.Cases[0].Observations) != 3 {
		t.Fatalf("observations = %+v", res.Cases[0].Observations)
	}
	v := res.StatementVerdicts()
	if v["k#a.1"] != core.Pass || v["k#a.2"] != core.Fail {
		t.Fatalf("verdicts = %v", v)
	}
	if _, ok := v["k#unjudged.1"]; ok {
		t.Fatal("unjudged statement has a verdict")
	}
}

func TestRunnerCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := core.Runner{}.Run(ctx, testProfile(parseCase("p", "k#a.1")), coretest.New())
	if err != nil {
		t.Fatal(err)
	}
	if o := res.Cases[0].Observations[0]; o.Verdict != core.Error || !strings.Contains(o.Detail, "cancelled") {
		t.Fatalf("observation = %+v", o)
	}
}

func TestRunnerCaseTimeout(t *testing.T) {
	c := core.Case{
		ID: "slow", Profile: profileName, Statements: []string{"k#a.1"},
		Run: func(ctx context.Context, _ core.Subject) []core.Observation {
			<-ctx.Done()
			return []core.Observation{{Statement: "k#a.1", Verdict: core.Error, Detail: ctx.Err().Error()}}
		},
	}
	res, err := core.Runner{CaseTimeout: time.Millisecond}.Run(context.Background(), testProfile(c), coretest.New())
	if err != nil {
		t.Fatal(err)
	}
	if o := res.Cases[0].Observations[0]; !strings.Contains(o.Detail, context.DeadlineExceeded.Error()) {
		t.Fatalf("observation = %+v", o)
	}
}

func TestRunnerCopiesStatements(t *testing.T) {
	c := parseCase("p", "k#a.1")
	res := run(t, coretest.New(), c)
	res.Cases[0].Statements[0] = "mutated"
	if c.Statements[0] != "k#a.1" {
		t.Fatal("result aliases the case's statements")
	}
}
