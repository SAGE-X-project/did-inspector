package sageresolution

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/sage-x-project/did-inspector/core"
	"reflect"
)

//go:embed library_syntax.json
var librarySyntaxBytes []byte

type syntaxItem struct {
	Request  SyntaxRequest `json:"request"`
	Accepted bool          `json:"accepted"`
	Value    string        `json:"value"`
}
type syntaxGroup struct {
	Name       string       `json:"name"`
	Statements []string     `json:"statements"`
	Items      []syntaxItem `json:"items"`
}

func syntaxFixtures() ([]syntaxGroup, error) {
	var out []syntaxGroup
	err := json.Unmarshal(librarySyntaxBytes, &out)
	return out, err
}
func syntaxOperation(kind string) string {
	switch kind {
	case "did":
		return "github.com/sage-x-project/did-go/did.Parse"
	case "url":
		return "github.com/sage-x-project/did-go/did.ParseURL"
	case "reference":
		return "github.com/sage-x-project/did-go/did.ParseReference+DIDURL.Resolve"
	}
	return ""
}
func judgeSyntax(g syntaxGroup, out []SyntaxResult, input string) []core.Observation {
	verdict := core.Pass
	if len(out) != len(g.Items) {
		verdict = core.Error
	} else {
		for i, item := range g.Items {
			r := out[i]
			if r.Operation != syntaxOperation(item.Request.Kind) || !reflect.DeepEqual(r.Request, item.Request) {
				verdict = core.Error
				break
			}
			if item.Accepted {
				if r.Error != "" || r.Value != item.Value {
					verdict = core.Fail
					break
				}
			} else if r.Error == "" {
				verdict = core.Fail
				break
			}
		}
	}
	raw, _ := json.Marshal(out)
	obs := unavailable(g.Statements, verdict, "Direct pinned library calls against literal ABNF and RFC3986 controls. The selected parser/reference actor is observed, not SAGE resolver ingress, all possible syntax or method authorization. No previously computed generic verdict is copied.")
	for i := range obs {
		obs[i].Input = input
		obs[i].Observed = string(raw)
		obs[i].Expected = "Literal accepted/rejected controls and exact unnormalized relative-reference results"
	}
	return obs
}
func appendLibrarySyntaxCases(p *core.Profile) error {
	if p.Name != "did-1.1" {
		return nil
	}
	groups, err := syntaxFixtures()
	if err != nil {
		return err
	}
	for _, g := range groups {
		p.Cases = append(p.Cases, core.Case{ID: p.Name + "/sage-resolution/library-syntax-" + g.Name, Profile: p.Name, Statements: g.Statements, Run: func(ctx context.Context, target core.Subject) []core.Observation {
			input, _ := json.Marshal(g)
			out := []SyntaxResult{}
			s, ok := target.(SyntaxSubject)
			if !ok {
				return libraryUnavailable(g.Statements, core.NotSupported, "no direct library syntax observer", string(input), out)
			}
			for _, item := range g.Items {
				r, e := s.InspectSyntax(ctx, item.Request)
				if e != nil {
					return libraryUnavailable(g.Statements, core.Error, fmt.Sprint(e), string(input), out)
				}
				out = append(out, r)
			}
			return judgeSyntax(g, out, string(input))
		}})
	}
	return nil
}

func libraryUnavailable(ids []string, v core.Verdict, detail, input string, out any) []core.Observation {
	raw, _ := json.Marshal(out)
	obs := unavailable(ids, v, detail)
	for i := range obs {
		obs[i].Input = input
		obs[i].Observed = string(raw)
	}
	return obs
}
