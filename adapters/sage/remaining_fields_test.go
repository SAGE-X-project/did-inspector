package sage

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualRemainingFields(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/remaining-fields-") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				t.Fatal(c.ID, o.Statement, o.Verdict)
			}
		}
	}
	if count != 9 {
		t.Fatal(count)
	}
}
