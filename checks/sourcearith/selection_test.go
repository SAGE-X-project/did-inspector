package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"go/types"
	"testing"
)

func TestSelectionTypedRoles(t *testing.T) {
	c := serviceControls(t)
	a := c("", "", "").SelectionAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 4 {
		t.Fatal(a)
	}
	for _, s := range a.Steps {
		if !s.Correct {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(a)
	t.Log(string(b))
	for _, tc := range []struct {
		old, replacement string
		bad              []int
	}{
		{"selected = append(selected, s)", "selected = append(selected, vm.Service{})", []int{0}},
		{"if isDIDMediaType(kind) {", "if !isDIDMediaType(kind) {", []int{2, 3}},
	} {
		a := c("dereferencer/service.go", tc.old, tc.replacement).SelectionAudit()
		if len(a.Unknown) != 0 {
			t.Fatal(a)
		}
		for i, s := range a.Steps {
			bad := false
			for _, j := range tc.bad {
				bad = bad || i == j
			}
			if s.Correct == bad {
				t.Fatal(i, a)
			}
		}
	}
	for _, tc := range []struct{ old, replacement string }{
		{"if isDIDMediaType(kind) {", "if representation.IsDIDMediaType(kind) {"},
		{"for _, s := range selected {", "for _, s := range append([]vm.Service{},selected...) {"},
		{"selected = append(selected, s)", "selected = append(selected, s.Clone())"},
	} {
		a := c("dereferencer/service.go", tc.old, tc.replacement).SelectionAudit()
		if len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
}

// All altered layouts below are parser/type-checker data, never executed.
func TestSelectionFailsClosedForLostBindings(t *testing.T) {
	c := serviceControls(t)
	root := "github.com/sage-x-project/did-go/dereferencer.(*github.com/sage-x-project/did-go/dereferencer.Dereferencer).services"
	end := "github.com/sage-x-project/did-go/dereferencer.endpointURLs"
	for _, change := range []func(*Program, function, selectionParts){
		func(p *Program, d function, s selectionParts) { delete(p.functions, p.Find(end)) },
		func(p *Program, d function, s selectionParts) { d.node.Body = nil },
		func(p *Program, d function, s selectionParts) {
			s.doc.Lhs[0] = &ast.SelectorExpr{X: ast.NewIdent("x"), Sel: ast.NewIdent("y")}
		},
		func(p *Program, d function, s selectionParts) { s.loop.X = ast.NewIdent("missing") },
		func(p *Program, d function, s selectionParts) { s.loop.X.(*ast.CallExpr).Fun = ast.NewIdent("missing") },
		func(p *Program, d function, s selectionParts) {
			s.loop.X.(*ast.CallExpr).Fun.(*ast.SelectorExpr).X = &ast.CallExpr{Fun: ast.NewIdent("copy")}
		},
		func(p *Program, d function, s selectionParts) {
			s.add.Rhs[0].(*ast.CallExpr).Args[1] = &ast.CallExpr{Fun: ast.NewIdent("copy")}
		},
		func(p *Program, d function, s selectionParts) { s.output.Results[0] = ast.NewIdent("missing") },
		func(p *Program, d function, s selectionParts) { s.endpoint.Lhs[0] = ast.NewIdent("missing") },
		func(p *Program, d function, s selectionParts) { s.gate.Cond = ast.NewIdent("missing") },
		func(p *Program, d function, s selectionParts) {
			delete(p.functions, p.Find(p.module+"/dereferencer.uriList"))
		},
		func(p *Program, d function, s selectionParts) { d.node.Body.List[7].(*ast.IfStmt).Body.List = nil },
		func(p *Program, d function, s selectionParts) {
			e := p.functions[p.Find(end)]
			each := e.node.Body.List[1].(*ast.RangeStmt)
			each.Body.List = append(each.Body.List, &ast.BranchStmt{Tok: token.BREAK})
		},
		func(p *Program, d function, s selectionParts) {
			delete(p.functions, p.Find(p.module+"/representation.CoreMediaTypes"))
		},
	} {
		p := c("", "", "")
		d := p.functions[p.Find(root)]
		s, _ := selectionShape(d.node)
		change(p, d, s)
		if a := p.SelectionAudit(); len(a.Unknown) == 0 {
			t.Fatal("lost binding accepted", a)
		}
	}
	if a := NewProgram(t.Context(), "other", nil).SelectionAudit(); len(a.Unknown) == 0 {
		t.Fatal(a)
	}
}
func TestSelectionMalformedFiltersAndNegotiation(t *testing.T) {
	c := serviceControls(t)
	for _, change := range []func(function, selectionParts){
		func(d function, s selectionParts) { d.node.Body.List[1] = &ast.EmptyStmt{} },
		func(d function, s selectionParts) { d.node.Body.List[1].(*ast.AssignStmt).Rhs = nil },
		func(d function, s selectionParts) { s.loop.Body.List[0] = &ast.EmptyStmt{} },
		func(d function, s selectionParts) { s.loop.Body.List[0].(*ast.IfStmt).Cond = ast.NewIdent("missing") },
		func(d function, s selectionParts) {
			s.loop.Body.List[0].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Y = ast.NewIdent("missing")
		},
		func(d function, s selectionParts) {
			s.loop.Body.List[0].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Y.(*ast.UnaryExpr).X = ast.NewIdent("missing")
		},
		func(d function, s selectionParts) {
			s.loop.Body.List[0].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Y.(*ast.UnaryExpr).X.(*ast.CallExpr).Fun = ast.NewIdent("missing")
		},
		func(d function, s selectionParts) {
			s.loop.Body.List[0].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Y.(*ast.UnaryExpr).X.(*ast.CallExpr).Args = nil
		},
		func(d function, s selectionParts) {
			s.loop.Body.List[0].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Y.(*ast.UnaryExpr).X.(*ast.CallExpr).Args[2] = ast.NewIdent("missing")
		},
	} {
		p := c("", "", "")
		f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).services")
		d := p.functions[f]
		s, _ := selectionShape(d.node)
		info := d.unit.info
		sig := f.Type().(*types.Signature)
		doc := info.Defs[s.doc.Lhs[0].(*ast.Ident)]
		item := info.Defs[s.loop.Value.(*ast.Ident)]
		change(d, s)
		if selectionFilters(d, s, sig.Params().At(0), doc, item, p.module) {
			t.Fatal("malformed filter accepted")
		}
	}
	for _, change := range []func(function, selectionParts){
		func(d function, s selectionParts) { s.initial.Rhs[0] = ast.NewIdent("missing") },
		func(d function, s selectionParts) { s.initial.Rhs[0].(*ast.IndexExpr).Index = ast.NewIdent("missing") },
		func(d function, s selectionParts) { d.node.Body.List[7] = &ast.EmptyStmt{} },
		func(d function, s selectionParts) { d.node.Body.List[7].(*ast.IfStmt).Cond = ast.NewIdent("missing") },
		func(d function, s selectionParts) {
			d.node.Body.List[7].(*ast.IfStmt).Cond.(*ast.BinaryExpr).Y = ast.NewIdent("missing")
		},
		func(d function, s selectionParts) { d.node.Body.List[7].(*ast.IfStmt).Body.List[0] = &ast.EmptyStmt{} },
		func(d function, s selectionParts) {
			d.node.Body.List[7].(*ast.IfStmt).Body.List[0].(*ast.AssignStmt).Lhs[0] = ast.NewIdent("missing")
		},
		func(d function, s selectionParts) {
			d.node.Body.List[7].(*ast.IfStmt).Body.List[2].(*ast.IfStmt).Init = nil
		},
	} {
		p := c("", "", "")
		f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).services")
		d := p.functions[f]
		s, _ := selectionShape(d.node)
		kind := d.unit.info.Defs[s.initial.Lhs[0].(*ast.Ident)]
		change(d, s)
		if selectionNegotiation(d, s, kind, f.Type().(*types.Signature).Params().At(2)) {
			t.Fatal("malformed negotiation accepted")
		}
	}
}
func TestSelectionFramesAndFiniteMedia(t *testing.T) {
	c := serviceControls(t)
	p := c("", "", "")
	f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).services")
	d := p.functions[f]
	for _, change := range []func(selectionParts){
		func(s selectionParts) { s.add.Rhs[0] = ast.NewIdent("missing") },
		func(s selectionParts) { s.output.Results[0] = ast.NewIdent("missing") },
	} {
		p := c("", "", "")
		d := p.functions[p.Find(Symbol(f))]
		s, _ := selectionShape(d.node)
		change(s)
		if selectionFrame(p, d, false) != "" {
			t.Fatal("malformed frame")
		}
	}
	bad := function{node: &ast.FuncDecl{Name: ast.NewIdent("f"), Type: &ast.FuncType{Params: &ast.FieldList{}}}}
	for _, endpoint := range []bool{false, true} {
		if selectionFrame(p, bad, endpoint) != "" {
			t.Fatal("empty frame")
		}
	}
	bad.node.Name = ast.NewIdent("not valid")
	if selectionFrame(p, bad, false) != "" {
		t.Fatal("invalid syntax")
	}
	s, _ := selectionShape(d.node)
	decl := d.node.Body.List[3].(*ast.DeclStmt).Decl.(*ast.GenDecl)
	decl.Specs = nil
	if _, ok := selectionShape(d.node); ok {
		t.Fatal("missing declaration")
	}
	_ = s
	if selectionSymbol(d.unit.info, ast.NewIdent("missing")) != "" {
		t.Fatal("untyped symbol")
	}
	p = c("", "", "")
	d = p.functions[p.Find(Symbol(f))]
	outer := d.node.Body.List[7].(*ast.IfStmt)
	outer.Body.List = nil
	if _, ok := p.selectionMedia(d); ok {
		t.Fatal("URI offer absent")
	}
}
