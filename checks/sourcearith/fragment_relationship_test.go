package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func TestFragmentRelationshipTypedRoles(t *testing.T) {
	control := fragmentControls(t)
	root := "github.com/sage-x-project/did-go/dereferencer.(*github.com/sage-x-project/did-go/dereferencer.Dereferencer).fragment"
	p := control("", "")
	good := p.FragmentRelationshipAudit(root)
	if len(good.Unknown) != 0 || len(good.Steps) != 2 || !good.Steps[0].Correct || !good.Steps[1].Correct || good.Frame == "" {
		t.Fatal(good)
	}
	b, _ := json.Marshal(good)
	t.Log(string(b))
	for _, tc := range []struct {
		old, replacement string
		bad              []int
	}{
		{`rel := opts.VerificationRelationship`, `rel := opts.Accept`, []int{0, 1}},
		{`case rel != "":`, `case rel == "":`, []int{0}},
		{`verificationMethod(content, u.Fragment(), rel, out.DereferencingMetadata.ContentType)`, `verificationMethod(content, u.Fragment(), opts.Accept, out.DereferencingMetadata.ContentType)`, nil},
	} {
		a := control(tc.old, tc.replacement).FragmentRelationshipAudit(root)
		if tc.bad == nil {
			if len(a.Unknown) == 0 {
				t.Fatal("unsupported call operand", a)
			}
			continue
		}
		if len(a.Unknown) != 0 || a.Frame != good.Frame {
			t.Fatal(a)
		}
		for i, s := range a.Steps {
			bad := false
			for _, j := range tc.bad {
				bad = bad || i == j
			}
			if s.Correct == bad {
				t.Fatal(tc, i, a)
			}
		}
	}
	for _, tc := range [][2]string{{`rel := opts.VerificationRelationship`, `rel := (&opts).VerificationRelationship`}, {`case rel != "":`, `case rel > "":`}} {
		if a := control(tc[0], tc[1]).FragmentRelationshipAudit(root); len(a.Unknown) == 0 {
			t.Fatal("unreviewed equivalent expression", a)
		}
	}
	if len(p.FragmentRelationshipAudit("other").Unknown) == 0 {
		t.Fatal("unknown root")
	}
	missing := NewProgram(t.Context(), p.module, nil)
	if len(missing.FragmentRelationshipAudit(root).Unknown) == 0 {
		t.Fatal("missing source")
	}
	for _, change := range []func(*Program){
		func(p *Program) { d := p.functions[p.Find(root)]; d.node.Body.List = nil },
		func(p *Program) {
			d := p.functions[p.Find(root)]
			start, _, _, _, _ := relationshipShape(d.node)
			start.Rhs[0] = &ast.Ident{Name: "other"}
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			start, _, _, _, _ := relationshipShape(d.node)
			delete(d.unit.info.Defs, start.Lhs[0].(*ast.Ident))
		},
	} {
		bad := control("", "")
		change(bad)
		if len(bad.FragmentRelationshipAudit(root).Unknown) == 0 {
			t.Fatal("unsupported AST data")
		}
	}
}

func TestRelationshipUnsupportedShapeData(t *testing.T) {
	control := fragmentControls(t)
	p := control("", "")
	root := p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).fragment"
	source := sourceExpression(p, p.functions[p.Find(root)].node)
	for _, change := range []func(*ast.FuncDecl){
		func(f *ast.FuncDecl) { f.Body = nil },
		func(f *ast.FuncDecl) { f.Body.List[0] = &ast.EmptyStmt{} },
		func(f *ast.FuncDecl) { f.Body.List[0].(*ast.AssignStmt).Rhs = nil },
		func(f *ast.FuncDecl) { f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0] = &ast.EmptyStmt{} },
		func(f *ast.FuncDecl) { f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).List = nil },
		func(f *ast.FuncDecl) {
			f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0] = &ast.EmptyStmt{}
		},
		func(f *ast.FuncDecl) {
			s := f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0].(*ast.SwitchStmt)
			s.Tag = &ast.Ident{Name: "tag"}
		},
		func(f *ast.FuncDecl) {
			s := f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0].(*ast.SwitchStmt)
			s.Body.List[1] = &ast.EmptyStmt{}
		},
		func(f *ast.FuncDecl) {
			s := f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0].(*ast.SwitchStmt)
			s.Body.List[1].(*ast.CaseClause).Body = nil
		},
		func(f *ast.FuncDecl) {
			s := f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0].(*ast.SwitchStmt)
			s.Body.List[1].(*ast.CaseClause).Body[0] = &ast.EmptyStmt{}
		},
		func(f *ast.FuncDecl) {
			s := f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0].(*ast.SwitchStmt)
			s.Body.List[1].(*ast.CaseClause).Body[0].(*ast.ReturnStmt).Results = nil
		},
		func(f *ast.FuncDecl) {
			s := f.Body.List[1].(*ast.TypeSwitchStmt).Body.List[0].(*ast.CaseClause).Body[0].(*ast.SwitchStmt)
			s.Body.List[1].(*ast.CaseClause).Body[0].(*ast.ReturnStmt).Results[0] = &ast.Ident{Name: "value"}
		},
		func(f *ast.FuncDecl) { _, _, _, c, _ := relationshipShape(f); c.Args = nil },
	} {
		f, e := parser.ParseFile(token.NewFileSet(), "control.go", "package control\n"+source, 0)
		if e != nil {
			t.Fatal(e)
		}
		fn := f.Decls[0].(*ast.FuncDecl)
		change(fn)
		if _, _, _, _, ok := relationshipShape(fn); ok {
			t.Fatal("unsupported shape accepted")
		}
	}
	for _, change := range []func(*Program){
		func(p *Program) {
			f := p.Find(root)
			d := p.functions[f]
			sig := f.Type().(*types.Signature)
			newf := types.NewFunc(f.Pos(), f.Pkg(), f.Name(), types.NewSignatureType(sig.Recv(), nil, nil, types.NewTuple(), sig.Results(), false))
			delete(p.functions, f)
			p.functions[newf] = d
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			_, s, _, _, _ := relationshipShape(d.node)
			s.Assign = &ast.EmptyStmt{}
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			_, s, _, _, _ := relationshipShape(d.node)
			s.Assign.(*ast.AssignStmt).Rhs[0] = &ast.Ident{Name: "other"}
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			_, s, _, _, _ := relationshipShape(d.node)
			s.Assign.(*ast.AssignStmt).Rhs[0].(*ast.TypeAssertExpr).Type = &ast.Ident{Name: "other"}
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			_, s, _, _, _ := relationshipShape(d.node)
			s.Assign.(*ast.AssignStmt).Rhs[0].(*ast.TypeAssertExpr).X = &ast.Ident{Name: "other"}
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			_, s, _, _, _ := relationshipShape(d.node)
			delete(d.unit.info.Implicits, s.Body.List[0])
		},
		func(p *Program) {
			d := p.functions[p.Find(root)]
			_, _, b, _, _ := relationshipShape(d.node)
			b.List[0] = &ast.Ident{Name: "unsupported"}
		},
	} {
		bad := control("", "")
		change(bad)
		if len(bad.FragmentRelationshipAudit(root).Unknown) == 0 {
			t.Fatal("unsupported metadata")
		}
	}
	d := p.functions[p.Find(root)]
	d.node.Body = nil
	if relationshipFrame(p, d) != "" {
		t.Fatal("unreviewed frame")
	}
	d.node = &ast.FuncDecl{Name: &ast.Ident{Name: "for"}, Type: &ast.FuncType{Params: &ast.FieldList{}}}
	if relationshipFrame(p, d) != "" {
		t.Fatal("unparsable frame")
	}
}
