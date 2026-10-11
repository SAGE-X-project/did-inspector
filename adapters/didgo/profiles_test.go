package didgo

import (
	"context"
	"slices"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles"
	"github.com/sage-x-project/did-inspector/report"
)

// knownNonconformances are the requirement-level statements did-go fails
// at the pinned revision (the HTTPS binding nonconformance found earlier,
// bindings-https.11, .34, .39, .40, .42, was fixed in did-go d7c44d9):
//
//   - core10#relative-did-urls.2: did.ParseReference refuses the empty
//     reference, which RFC 3986 §5.4.1 resolves to the base;
//   - cid10#Multikey.5: a secretKeyMultibase of "" is not a Multibase
//     value (CID 1.0 §2.4: "The value starts with a single character
//     header"), but vm.Method holds it as an absent property and
//     vm.Method.Validate reports nothing.
//
// The test fails when the set changes, so that a new failure is noticed.
var knownNonconformances = map[string][]string{
	"did-core-1.0": {"core10#relative-did-urls.2"},
	"did-1.1":      {"cid10#Multikey.5"},
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
