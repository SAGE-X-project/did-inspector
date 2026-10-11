package report

import (
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

func TestInputFor(t *testing.T) {
	p := core.Profile{Name: "p", SpecKeys: []string{statements.KeyCore10}}
	in, err := InputFor(p, core.RunResult{Profile: "p"}, "rev")
	if err != nil {
		t.Fatal(err)
	}
	if in.InspectorRevision != "rev" || len(in.Specs) != 1 || in.Specs[0].Key != statements.KeyCore10 || in.Specs[0].SHA256 == "" {
		t.Fatalf("unexpected input %+v", in.Specs)
	}
	if len(in.Statements) == 0 || in.Statements[0].Scope == "" || in.Statements[0].Level == "" {
		t.Fatalf("statements without scope: %v", in.Statements[:1])
	}
	if _, err := InputFor(core.Profile{SpecKeys: []string{"nosuchkey"}}, core.RunResult{}, ""); err == nil {
		t.Fatal("unknown spec key: no error")
	}
}
