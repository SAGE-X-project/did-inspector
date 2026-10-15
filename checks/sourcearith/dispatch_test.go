package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"testing"
)

func TestDispatchTypedRoles(t *testing.T) {
	c := serviceControls(t)
	a := c("", "", "").DispatchAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 3 {
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
		file, old, next string
		bad             int
	}{
		{"dereferencer/dereferencer.go", "d.resource(ctx, u, params, res, opts)", "d.resource(ctx, u, params, resolution.Result{}, opts)", 0},
		{"dereferencer/dereferencer.go", `u.Path() == "" && onlyResolutionParameters(params)`, `u.Path() == "" || onlyResolutionParameters(params)`, 1},
		{"dereferencer/fragment.go", "if u.HasFragment() {", "if !u.HasFragment() {", 2},
	} {
		a := c(tc.file, tc.old, tc.next).DispatchAudit()
		if len(a.Unknown) != 0 {
			t.Fatal(a)
		}
		for i, s := range a.Steps {
			if s.Correct == (i == tc.bad) {
				t.Fatal(i, a)
			}
		}
	}
	for _, tc := range []struct{ file, old, next string }{
		{"dereferencer/dereferencer.go", "d.resource(ctx, u, params, res, opts)", "d.resource(ctx, u, params, func() resolution.Result{return res}(), opts)"},
		{"dereferencer/dereferencer.go", `u.Path() == "" && onlyResolutionParameters(params)`, `u.Path() == "" && (onlyResolutionParameters(params)==true)`},
		{"dereferencer/fragment.go", "if u.HasFragment() {", `if u.Fragment()!="" {`},
	} {
		if a := c(tc.file, tc.old, tc.next).DispatchAudit(); len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
}

// These malformed AST/type bindings are data only; altered subjects never run.
func TestDispatchMissingStructureAndBindings(t *testing.T) {
	c := serviceControls(t)
	nodes := func(p *Program) []function {
		out := []function{}
		for _, n := range []string{"Dereference", "resource", "fragment"} {
			out = append(out, p.functions[p.Find(p.module+"/dereferencer.(*"+p.module+"/dereferencer.Dereferencer)."+n)])
		}
		return out
	}
	for i, change := range []func(*Program, []function, dispatchParts){
		func(p *Program, n []function, s dispatchParts) {
			delete(p.functions, p.Find(p.module+"/dereferencer.(*"+p.module+"/dereferencer.Dereferencer).Dereference"))
		},
		func(p *Program, n []function, s dispatchParts) { n[0].node.Body = nil },
		func(p *Program, n []function, s dispatchParts) { s.resolved.Rhs = nil },
		func(p *Program, n []function, s dispatchParts) { s.uri.List = nil },
		func(p *Program, n []function, s dispatchParts) { s.guard.Body.List = nil },
		func(p *Program, n []function, s dispatchParts) { s.guard.Body.List[0] = &ast.EmptyStmt{} },
		func(p *Program, n []function, s dispatchParts) { s.resolve.Args = nil },
		func(p *Program, n []function, s dispatchParts) { s.resolved.Lhs[0] = ast.NewIdent("missing") },
		func(p *Program, n []function, s dispatchParts) {
			s.resource.Args[3] = &ast.CallExpr{Fun: ast.NewIdent("copy")}
		},
		func(p *Program, n []function, s dispatchParts) { s.resolve.Fun = ast.NewIdent("missing") },
		func(p *Program, n []function, s dispatchParts) { n[0].node.Body.List[6] = &ast.EmptyStmt{} },
		func(p *Program, n []function, s dispatchParts) {
			n[0].node.Body.List[6].(*ast.IfStmt).Cond = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			n[1].node.Body.List[2].(*ast.SwitchStmt).Body.List[1].(*ast.CaseClause).Body = nil
		},
		func(p *Program, n []function, s dispatchParts) {
			n[1].node.Body.List[2].(*ast.SwitchStmt).Body.List[1].(*ast.CaseClause).Body[0] = &ast.EmptyStmt{}
		},
		func(p *Program, n []function, s dispatchParts) {
			n[1].node.Body.List[2].(*ast.SwitchStmt).Body.List[1].(*ast.CaseClause).Body[0].(*ast.ReturnStmt).Results[0] = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			delete(p.functions, p.Find(p.module+"/dereferencer.(*"+p.module+"/dereferencer.Dereferencer).services"))
		},
		func(p *Program, n []function, s dispatchParts) {
			p.functions[p.Find(p.module+"/dereferencer.(*"+p.module+"/dereferencer.Dereferencer).services")].node.Body = nil
		},
		func(p *Program, n []function, s dispatchParts) {
			p.functions[p.Find(p.module+"/dereferencer.(*"+p.module+"/dereferencer.Dereferencer).services")].node.Body.List[0] = &ast.EmptyStmt{}
		},
		func(p *Program, n []function, s dispatchParts) {
			n[1].node.Body.List[2].(*ast.SwitchStmt).Body.List[1].(*ast.CaseClause).List[0] = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			s.fallback.(*ast.BinaryExpr).X = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			s.fallback.(*ast.BinaryExpr).X.(*ast.BinaryExpr).X = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			s.fallback.(*ast.BinaryExpr).Y.(*ast.CallExpr).Args[0] = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			n[2].node.Body.List[1].(*ast.TypeSwitchStmt).Assign = &ast.EmptyStmt{}
		},
		func(p *Program, n []function, s dispatchParts) {
			n[2].node.Body.List[1].(*ast.TypeSwitchStmt).Assign.(*ast.AssignStmt).Rhs[0].(*ast.TypeAssertExpr).Type = ast.NewIdent("other")
		},
		func(p *Program, n []function, s dispatchParts) { s.guard.Cond = ast.NewIdent("missing") },
		func(p *Program, n []function, s dispatchParts) {
			s.guard.Cond.(*ast.CallExpr).Fun.(*ast.SelectorExpr).X = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) { n[0].node.Body.List[9] = &ast.EmptyStmt{} },
		func(p *Program, n []function, s dispatchParts) {
			n[0].node.Body.List[9].(*ast.ReturnStmt).Results[0] = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s dispatchParts) {
			delete(p.functions, p.Find(p.module+"/dereferencer.inheritFragment"))
		},
	} {
		p := c("", "", "")
		n := nodes(p)
		s, _ := dispatchShape(n[0].node, n[1].node, n[2].node)
		change(p, n, s)
		if a := p.DispatchAudit(); len(a.Unknown) == 0 {
			t.Fatal(i, "missing evidence accepted", a)
		}
	}
	p := c("", "", "")
	if dispatchFrames(p, nil) != nil {
		t.Fatal("missing frames")
	}
	bad := function{node: &ast.FuncDecl{Name: ast.NewIdent("f"), Type: &ast.FuncType{Params: &ast.FieldList{}}}}
	if dispatchFrames(p, []function{bad, bad, bad}) != nil {
		t.Fatal("empty frames")
	}
	bad.node.Name = ast.NewIdent("invalid name")
	if dispatchFrames(p, []function{bad, bad, bad}) != nil {
		t.Fatal("invalid frames")
	}
	n := nodes(p)
	n[0].node.Body.List[0] = &ast.BranchStmt{Tok: token.BREAK}
	if f := dispatchFrames(p, n); len(f) != 3 {
		t.Fatal("frame format control")
	}
}
