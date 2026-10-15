package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualExpansionSourceAndTraversal(t *testing.T) {
	s, _ := sourceTest(t)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/expansion-source-") {
			continue
		}
		count++
		obs := c.Run(t.Context(), s)
		if len(obs) != 2 {
			t.Fatal(len(obs))
		}
		for i, o := range obs {
			want := core.Pass
			if i == 1 {
				want = core.Fail
			}
			if o.Verdict != want {
				var e map[string]json.RawMessage
				_ = json.Unmarshal([]byte(o.Observed), &e)
				t.Fatal(o.Statement, o.Verdict, string(e["analysis_error"]), string(e["runtime"]))
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}
