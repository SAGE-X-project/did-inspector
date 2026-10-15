package sage

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualRelationshipCallsAndFixtureSource(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/fragment-relationship-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				t.Fatal(o.Statement, o.Verdict, o.Observed)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}
