package core10

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// RelativeFile is the format of testdata/relative.json: DID URL references
// and the absolute DID URLs that the Reference Resolution algorithm of RFC
// 3986 §5 gives for them against the base DID, with the decomposition of
// DID Core 1.0 §3.2.2 (scheme did, authority
// method-name:method-specific-id).
type RelativeFile struct {
	Base  string         `json:"base"`
	Items []RelativeItem `json:"items"`
}

// RelativeItem is one reference and its resolution.
type RelativeItem struct {
	Ref      string `json:"ref"`
	Expected string `json:"expected"`
	Why      string `json:"why"`
}

// relativeCase resolves every reference of the fixture against the base
// DID and compares the subject's absolute DID URL with the expected one.
func relativeCase(f RelativeFile) core.Case {
	sts := []string{k("relative-did-urls.2")}
	return core.Case{
		ID: Name + "/syntax/relative-reference-resolution", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDIDURLReferenceResolver},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			res := s.(core.DIDURLReferenceResolver)
			var r kit.Recorder
			for _, it := range f.Items {
				input := fmt.Sprintf("reference %q against %s", it.Ref, f.Base)
				got, err := res.ResolveDIDURLReference(f.Base, it.Ref)
				observed := fmt.Sprintf("%q", got)
				if err != nil {
					observed = "refused: " + err.Error()
				}
				r.Judge(sts, input, err == nil && got == it.Expected, fmt.Sprintf("%q (%s)", it.Expected, it.Why), observed, "")
			}
			return r.Observations()
		},
	}
}
