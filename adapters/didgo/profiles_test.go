package didgo

import (
	"context"
	"slices"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles"
	"github.com/sage-x-project/did-inspector/profiles/did11"
	"github.com/sage-x-project/did-inspector/report"
)

// knownNonconformances are the requirement-level statements did-go fails
// at the pinned revision. Each is a nonconformance of did-go, not of the
// adapter or the cases: resolution/universal's Handler cannot write the
// vm.Method that did-go's Dereferencer returns for a DID URL with a
// fragment, and answers a successful dereference with 500 INTERNAL_ERROR
// ("content of type vm.Method cannot be written"). The test fails when the
// set changes, so that a fix in did-go or a new failure is noticed.
var knownNonconformances = map[string][]string{
	did11.Name: {
		"res10-crd20261001#bindings-https.11",
		"res10-crd20261001#bindings-https.34",
		"res10-crd20261001#bindings-https.39",
		"res10-crd20261001#bindings-https.40",
		"res10-crd20261001#bindings-https.42",
	},
}

// TestProfiles runs every built-in profile against did-go, as the
// committed evidence reports and the CI job do. A requirement-level FAIL
// or ERROR fails the test unless it is a known nonconformance;
// recommendation-level failures are logged, as the report prints them
// without failing the gate.
func TestProfiles(t *testing.T) {
	for _, p := range profiles.Builtin() {
		t.Run(p.Name, func(t *testing.T) {
			s := New()
			t.Cleanup(func() { _ = s.Close() })
			res, err := core.Runner{}.Run(context.Background(), p, s)
			if err != nil {
				t.Fatal(err)
			}
			in, err := report.InputFor(p, res, "test")
			if err != nil {
				t.Fatal(err)
			}
			rep := report.Build(in)
			var gate []string
			for _, st := range rep.GateFailures() {
				gate = append(gate, st.ID)
			}
			slices.Sort(gate)
			want := slices.Clone(knownNonconformances[p.Name])
			slices.Sort(want)
			if !slices.Equal(gate, want) {
				t.Errorf("requirement-level FAIL or ERROR: %v, known: %v", gate, want)
			}
			for _, st := range rep.Statements {
				if st.IsRecommendation() && (st.Verdict == core.Fail || st.Verdict == core.Error) {
					t.Logf("recommendation %s: %s", st.ID, st.Verdict)
				}
			}
		})
	}
}
