package did11

import (
	"context"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
	"github.com/sage-x-project/did-inspector/statements"
)

func run(t *testing.T, s core.Subject) core.RunResult {
	t.Helper()
	res, err := core.Runner{}.Run(context.Background(), Profile(), s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestProfile(t *testing.T) {
	p := Profile()
	if p.Name != Name || p.Title == "" || len(p.SpecKeys) != 3 || !slices.Contains(p.SpecKeys, statements.KeyRes10) {
		t.Fatalf("profile = %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Cases {
		for _, st := range c.Statements {
			if strings.HasPrefix(st, statements.KeyCore10+"#") {
				t.Errorf("case %s names a DID Core 1.0 statement %s", c.ID, st)
			}
		}
	}
}

func TestFixtureFiles(t *testing.T) {
	f := LoadFixtures()
	if err := kit.ValidateSyntax(f.Syntax); err != nil {
		t.Error(err)
	}
	if err := kit.ValidateDocs(f.Documents); err != nil {
		t.Error(err)
	}
	if err := kit.ValidateScenarios(f.Resolution); err != nil {
		t.Error(err)
	}
	if err := kit.ValidateScenarios(f.Dereferencing); err != nil {
		t.Error(err)
	}
}

// TestSyntaxFixturesAgreeWithChecks cross-checks the syntax fixtures with
// the inspector's own ABNF parser, so that a fixture and the checks cannot
// silently disagree.
func TestSyntaxFixturesAgreeWithChecks(t *testing.T) {
	for _, g := range LoadFixtures().Syntax.Groups {
		for _, it := range g.Items {
			var err error
			if g.Kind == "did" {
				_, err = checks.ParseDID(it.Input)
			} else {
				_, err = checks.ParseDIDURL(it.Input)
			}
			if (err == nil) != it.Valid {
				t.Errorf("%s: %q valid=%v, checks error %v", g.Case, it.Input, it.Valid, err)
			}
		}
	}
}

// TestConformingMockPasses runs every case against a subject that does what
// the specifications require: no case may report FAIL or ERROR, and every
// case must report at least one PASS.
func TestConformingMockPasses(t *testing.T) {
	res := run(t, newMock())
	for _, c := range res.Cases {
		pass := false
		for _, o := range c.Observations {
			switch o.Verdict {
			case core.Pass:
				pass = true
			case core.Fail, core.Error:
				t.Errorf("%s: %s %s input %q expected %q observed %q %s", c.Case, o.Statement, o.Verdict, o.Input, o.Expected, o.Observed, o.Detail)
			}
		}
		if !pass {
			t.Errorf("%s: no PASS", c.Case)
		}
	}
}

// faults are the violations the mock can commit. Every case must fail under
// at least one of them.
var faults = []string{
	"parser-rejects-all", "parser-accepts-all", "parser-wrong-parts",
	"consumer-rejects-all", "consumer-accepts-all", "consumer-ignores-media-type", "consumer-wrong-media-type-info",
	"consumer-no-representation-entries", "consumer-drops-entries", "consumer-changes-keys", "consumer-loses-entries",
	"producer-rejects-all", "producer-accepts-all", "producer-drops-entries", "producer-drops-context",
	"producer-changes-keys", "producer-reorders-context", "producer-non-object", "producer-wrong-media-type",
	"validator-noisy", "validator-silent",
	"error-type-bare", "error-type-not-url", "error-empty-metadata", "error-with-document", "error-with-metadata", "cid-error-prefix-wrong",
	"ignore-unknown-options", "accept-invalid-options", "reject-accept", "no-cache-error", "ignore-version", "wrong-current-version",
	"failure-not-internal", "deactivated-no-flag", "deactivated-as-error", "deactivated-returns-document", "accept-malformed",
	"reject-relative", "no-expand", "content-type-wrong", "no-content-type", "proof-not-set", "drop-metadata",
	"metadata-fraction", "metadata-non-ascii", "metadata-other-method", "metadata-malformed-ids", "deactivated-flag-on-active",
	"deref-invalid-accepted", "deref-no-metadata", "path-error-type", "fragment-whole-document", "fragment-no-relative",
	"fragment-shallow", "vr-ignored", "vr-reject-all", "content-type-not-ascii", "service-ignore-selection",
	"accept-any-representation", "uri-list-include-maps", "relative-ref-append", "fragment-not-inherited", "fragment-overrides",
	"no-uri-list-content-type",
}

func failingCases(res core.RunResult) []string {
	var out []string
	for _, c := range res.Cases {
		for _, o := range c.Observations {
			if o.Verdict == core.Fail {
				out = append(out, c.Case)
				break
			}
		}
	}
	return out
}

// TestEachCaseDiscriminates shows that every case can fail: each fault makes
// at least one case fail, and every case fails under at least one fault.
func TestEachCaseDiscriminates(t *testing.T) {
	covered := map[string][]string{}
	for _, f := range faults {
		failed := failingCases(run(t, newMock(f)))
		if len(failed) == 0 {
			t.Errorf("fault %s makes no case fail", f)
		}
		for _, c := range failed {
			covered[c] = append(covered[c], f)
		}
	}
	var missing []string
	for _, c := range Profile().Cases {
		if len(covered[c.ID]) == 0 {
			missing = append(missing, c.ID)
		}
	}
	sort.Strings(missing)
	for _, id := range missing {
		t.Errorf("no fault makes %s fail", id)
	}
}

// TestFailuresCarryValues checks that every FAIL names what was expected and
// observed, so that a report can show it.
func TestFailuresCarryValues(t *testing.T) {
	res := run(t, newMock("error-type-bare", "producer-wrong-media-type", "parser-accepts-all"))
	n := 0
	for _, c := range res.Cases {
		for _, o := range c.Observations {
			if o.Verdict == core.Fail {
				n++
				if o.Expected == "" || o.Observed == "" || o.Input == "" && !strings.Contains(c.Case, "/representation/") {
					t.Errorf("%s: %+v", c.Case, o)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no failure")
	}
}

func TestUnsupportedAndBrokenSubjects(t *testing.T) {
	m := newMock()
	for _, c := range core.Capabilities() {
		m.faults["unsupported:"+string(c)] = true
	}
	for _, c := range run(t, m).Cases {
		for _, o := range c.Observations {
			if o.Verdict != core.NotSupported {
				t.Fatalf("%s: %s with every capability unsupported", c.Case, o.Verdict)
			}
		}
	}
	needs := map[string][]core.Capability{}
	for _, c := range Profile().Cases {
		needs[c.ID] = c.Needs
	}
	for _, c := range run(t, newMock("registry-load-fails")).Cases {
		if !slices.Contains(needs[c.Case], core.CapFixtureMethod) {
			continue
		}
		for _, o := range c.Observations {
			if o.Verdict != core.Error {
				t.Fatalf("%s: %s when the registry cannot be loaded", c.Case, o.Verdict)
			}
		}
	}
	for _, c := range run(t, newMock("validator-fails")).Cases {
		if strings.HasSuffix(c.Case, "/validator") && c.Observations[0].Verdict != core.Error {
			t.Fatalf("%s: %s when the validator fails", c.Case, c.Observations[0].Verdict)
		}
	}
}
