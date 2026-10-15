package sourcearith

import (
	"go/ast"
	"testing"
)

func TestFragmentInitialResultState(t *testing.T) {
	control := fragmentControls(t)
	root := "github.com/sage-x-project/did-go/dereferencer.resolveFragment"
	p := control("", "")
	a := p.FragmentInitialAudit(root)
	if len(a.Unknown) != 0 || len(a.InitialValues) != 2 || a.ResultTypes[0] != "any" || a.ResultTypes[1] != "bool" || a.ResultRoles[0] != "found" || a.ResultRoles[1] != "ok" {
		t.Fatal(a)
	}
	for _, r := range []string{"other", root + "Missing"} {
		if len(p.FragmentInitialAudit(r).Unknown) == 0 {
			t.Fatal(r)
		}
	}
	for _, tc := range [][2]string{
		{`func findFragment(doc *document.Document, match func(string) bool) (any, bool)`, `func findFragment(doc *document.Document, match func(string) bool) (result any, matched bool)`},
		{`findFragment(doc, match)`, `findFragment(&document.Document{}, match)`},
		{`findFragment(doc, match)`, `findFragment(doc, func(s string) bool{return match(s)})`},
		{`found, ok := findFragment(doc, match)`, `found, ok := (func()(any,bool){return findFragment(doc,match)})()`},
	} {
		if a := control(tc[0], tc[1]).FragmentInitialAudit(root); len(a.Unknown) == 0 {
			t.Fatal(tc, a)
		}
	}
	// Unsupported layouts are AST data only; no modified subject is executed.
	for _, change := range []func(*Program){
		func(p *Program) {
			d := p.functions[p.Find(root)]
			d.node.Body.List[1] = &ast.ExprStmt{X: &ast.Ident{Name: "unsupported"}}
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			matcher := d.node.Body.List[1].(*ast.AssignStmt)
			delete(d.unit.info.Defs, matcher.Lhs[0].(*ast.Ident))
		},
	} {
		bad := control("", "")
		change(bad)
		if len(bad.FragmentInitialAudit(root).Unknown) == 0 {
			t.Fatal("unreviewed matcher")
		}
	}
	// Loss of type-checker metadata is a capture error, not a normative failure.
	d := p.functions[p.Find(root)]
	_, found, _, _ := fragmentShape(d.node)
	delete(d.unit.info.Defs, found.Lhs[1].(*ast.Ident))
	if a := p.FragmentInitialAudit(root); len(a.Unknown) == 0 {
		t.Fatal("missing result metadata", a)
	}
}
