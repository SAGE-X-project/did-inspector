package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualOptionalFieldsAndRelationships(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	cases, clauses, calls := 0, 0, 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/optional-") {
			continue
		}
		cases++
		for i, o := range c.Run(t.Context(), s) {
			clauses++
			if o.Verdict != core.Pass {
				t.Fatal(c.ID, o.Statement, o.Verdict, o.Detail)
			}
			var capture struct {
				Control  sageresolution.ConsumptionCapture   `json:"control"`
				Variants []sageresolution.ConsumptionCapture `json:"variants"`
			}
			if json.Unmarshal([]byte(o.Observed), &capture) != nil || len(capture.Control.Input) == 0 || len(capture.Variants) == 0 {
				t.Fatal("lost raw calls")
			}
			if i == 0 {
				calls += 1 + len(capture.Variants)
			}
		}
	}
	if cases != 12 || clauses != 17 || calls != 46 {
		t.Fatal(cases, clauses, calls)
	}
}
