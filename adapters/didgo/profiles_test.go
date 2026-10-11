package didgo

import (
	"context"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles"
)

// TestProfiles runs every built-in profile against did-go and reports
// each statement that is FAIL or ERROR. It is the same run as the
// committed evidence reports and the CI job.
func TestProfiles(t *testing.T) {
	for _, p := range profiles.Builtin() {
		t.Run(p.Name, func(t *testing.T) {
			res, err := core.Runner{}.Run(context.Background(), p, New())
			if err != nil {
				t.Fatal(err)
			}
			for id, v := range res.StatementVerdicts() {
				if v == core.Fail || v == core.Error {
					t.Errorf("%s: %s", id, v)
				}
			}
		})
	}
}
