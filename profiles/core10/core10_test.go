package core10

import (
	"context"
	"slices"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/core/coretest"
	"github.com/sage-x-project/did-inspector/statements"
)

// selfTestStatement is the statement the self-test case names: all DIDs
// conform to the DID Syntax ABNF rules.
const selfTestStatement = "core10#did-syntax.1"

// selfTestCase is a trivial case used only to test the profile's wiring: it
// asks the subject to parse one DID and compares the components.
func selfTestCase() core.Case {
	return core.Case{
		ID:         Name + "/self-test/parse-did",
		Profile:    Name,
		Statements: []string{selfTestStatement},
		Needs:      []core.Capability{core.CapDIDParser},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got, err := s.(core.DIDParser).ParseDID(coretest.ExampleDID)
			o := core.Observation{Statement: selfTestStatement, Input: coretest.ExampleDID}
			if err != nil || got.Method != "example" || got.MethodSpecificID != "123" {
				o.Verdict, o.Expected, o.Observed = core.Fail, "method example, id 123", got.Method+" "+got.MethodSpecificID
				return []core.Observation{o}
			}
			o.Verdict = core.Pass
			return []core.Observation{o}
		},
	}
}

func TestProfile(t *testing.T) {
	p := Profile()
	if p.Name != Name || p.Title == "" || !slices.Contains(p.SpecKeys, statements.KeyCore10) {
		t.Fatalf("profile = %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSelfTestStatementExists(t *testing.T) {
	doc, err := statements.Load(statements.KeyCore10)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(doc.Statements, func(s statements.Statement) bool { return s.ID == selfTestStatement }) {
		t.Fatalf("%s is not an extracted statement", selfTestStatement)
	}
}

func TestSelfTestCase(t *testing.T) {
	p := Profile()
	p.Cases = append(p.Cases, selfTestCase())
	cases := []struct {
		subject core.Subject
		want    core.Verdict
	}{
		{coretest.New(), core.Pass},
		{coretest.New().With(core.CapDIDParser, coretest.Wrong), core.Fail},
		{coretest.New().Without(core.CapDIDParser), core.NotSupported},
	}
	for _, c := range cases {
		res, err := core.Runner{}.Run(context.Background(), p, c.subject)
		if err != nil {
			t.Fatal(err)
		}
		if got := res.StatementVerdicts()[selfTestStatement]; got != c.want {
			t.Errorf("verdict = %s, want %s", got, c.want)
		}
	}
}
