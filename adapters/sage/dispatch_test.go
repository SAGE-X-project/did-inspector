package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualResourceDispatchAndFragmentConditions(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/dispatch-source-") {
			continue
		}
		count++
		observations := c.Run(t.Context(), s)
		if len(observations) != 3 {
			t.Fatal("missing dispatch observations", len(observations))
		}
		for _, o := range observations {
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
