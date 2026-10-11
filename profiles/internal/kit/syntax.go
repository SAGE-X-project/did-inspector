package kit

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/core"
)

// SyntaxFile is the format of testdata/syntax.json: groups of DIDs or DID
// URLs, each valid or invalid under the ABNF, with the components a parser
// must report for the valid ones.
type SyntaxFile struct {
	Groups []SyntaxGroup `json:"groups"`
}

// SyntaxGroup becomes one case.
type SyntaxGroup struct {
	// Case is the case id suffix.
	Case string `json:"case"`
	// Note explains the group; Partial, when set, says what the case does
	// not judge of its statements and is reported with each observation.
	Note    string `json:"note"`
	Partial string `json:"partial,omitempty"`
	// Kind is "did" (ParseDID) or "did-url" (ParseDIDURL).
	Kind       string       `json:"kind"`
	Statements []string     `json:"statements"`
	Items      []SyntaxItem `json:"items"`
}

// SyntaxItem is one input. Component fields that are nil are not checked.
type SyntaxItem struct {
	Input       string  `json:"input"`
	Valid       bool    `json:"valid"`
	Why         string  `json:"why,omitempty"`
	Method      *string `json:"method,omitempty"`
	ID          *string `json:"id,omitempty"`
	DID         *string `json:"did,omitempty"`
	Path        *string `json:"path,omitempty"`
	Query       *string `json:"query,omitempty"`
	Fragment    *string `json:"fragment,omitempty"`
	HasQuery    *bool   `json:"hasQuery,omitempty"`
	HasFragment *bool   `json:"hasFragment,omitempty"`
}

// SyntaxCases returns one case per group.
func SyntaxCases(profile string, f SyntaxFile) []core.Case {
	out := make([]core.Case, 0, len(f.Groups))
	for _, g := range f.Groups {
		out = append(out, core.Case{
			ID:         profile + "/syntax/" + g.Case,
			Profile:    profile,
			Statements: g.Statements,
			Needs:      []core.Capability{core.CapDIDParser},
			Run: func(_ context.Context, s core.Subject) []core.Observation {
				var r Recorder
				p := s.(core.DIDParser)
				for _, it := range g.Items {
					ok, exp, obs := judgeSyntax(p, g.Kind, it)
					r.Judge(g.Statements, it.Input, ok, exp, obs, g.Partial)
				}
				return r.Observations()
			},
		})
	}
	return out
}

func judgeSyntax(p core.DIDParser, kind string, it SyntaxItem) (bool, string, string) {
	var err error
	var got []field
	if kind == "did" {
		var d core.DIDParts
		d, err = p.ParseDID(it.Input)
		got = []field{{"method", it.Method, d.Method}, {"method-specific-id", it.ID, d.MethodSpecificID}}
	} else {
		var u core.DIDURLParts
		u, err = p.ParseDIDURL(it.Input)
		got = []field{
			{"did", it.DID, u.DID.DID}, {"method", it.Method, u.DID.Method}, {"method-specific-id", it.ID, u.DID.MethodSpecificID},
			{"path", it.Path, u.Path}, {"query", it.Query, u.Query}, {"fragment", it.Fragment, u.Fragment},
			{"has query", boolString(it.HasQuery), fmt.Sprint(u.HasQuery)}, {"has fragment", boolString(it.HasFragment), fmt.Sprint(u.HasFragment)},
		}
	}
	if !it.Valid {
		if err == nil {
			return false, "rejected: " + it.Why, "accepted"
		}
		return true, "", ""
	}
	if err != nil {
		return false, "accepted", "rejected: " + err.Error()
	}
	for _, f := range got {
		if f.want != nil && *f.want != f.got {
			return false, fmt.Sprintf("%s %q", f.name, *f.want), fmt.Sprintf("%s %q", f.name, f.got)
		}
	}
	return true, "", ""
}

type field struct {
	name string
	want *string
	got  string
}

func boolString(b *bool) *string {
	if b == nil {
		return nil
	}
	s := fmt.Sprint(*b)
	return &s
}
