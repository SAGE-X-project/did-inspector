package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualServiceCallsAndFixtureSource(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/service-source-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				var capture map[string]json.RawMessage
				_ = json.Unmarshal([]byte(o.Observed), &capture)
				t.Fatal(o.Statement, o.Verdict, string(capture["runtime"]))
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}
