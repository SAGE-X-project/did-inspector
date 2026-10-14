package sage

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualRemainingNativeKeys(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/remaining-native-keys") {
			continue
		}
		count++
		for _, o := range c.Run(t.Context(), s) {
			want := core.Pass
			if o.Statement == "cid10#JsonWebKey.5" {
				want = core.Fail
			}
			if o.Statement == "cid10#JsonWebKey.6" || o.Statement == "cid10#JsonWebKey.9" {
				want = core.NotApplicable
			}
			if o.Verdict != want {
				t.Fatal(o.Statement, o.Verdict)
			}
		}
	}
	if count != 1 {
		t.Fatal(count)
	}
}
