package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/token"
	"os"
	"strings"
	"testing"
)

func expansionControls(t *testing.T) func(string, string, string) *Program {
	b, e := os.ReadFile("testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	files, _, e := ArchiveFiles(b, "github.com/sage-x-project/did-go@v0.0.0-20261012015322-ed54c505eafe")
	if e != nil {
		t.Fatal(e)
	}
	source := SourceFiles(files, []string{"resolver", "method", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"})
	standard := importer.ForCompiler(token.NewFileSet(), "source", nil)
	return func(file, old, next string) *Program {
		input := map[string][]byte{}
		for k, v := range source {
			input[k] = v
		}
		if old != "" {
			if !strings.Contains(string(input[file]), old) {
				t.Fatal(old)
			}
			input[file] = []byte(strings.Replace(string(input[file]), old, next, 1))
		}
		p := NewProgram(t.Context(), "github.com/sage-x-project/did-go", input)
		p.standard = standard
		if _, e := p.Import(p.module + "/resolver"); e != nil {
			t.Fatal(e)
		}
		return p
	}
}
func TestExpansionSourceTypedConditions(t *testing.T) {
	c := expansionControls(t)
	a := c("", "", "").ExpansionAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 2 || !a.Steps[0].Correct || a.Steps[1].Correct {
		t.Fatal(a)
	}
	b, _ := json.Marshal(a)
	t.Log(string(b))
	a = c("resolver/resolver.go", "if opts.ExpandRelativeURLs {", "if !opts.ExpandRelativeURLs {").ExpansionAudit()
	if len(a.Unknown) != 0 || a.Steps[0].Correct || a.Steps[1].Correct {
		t.Fatal(a)
	}
	if a := c("resolver/resolver.go", "if opts.ExpandRelativeURLs {", "if opts.ExpandRelativeURLs == true {").ExpansionAudit(); len(a.Unknown) == 0 {
		t.Fatal(a)
	}
}

// Malformed bindings and source variants are analysis data only, never run.
func TestExpansionSourceMissingBindings(t *testing.T) {
	c := expansionControls(t)
	for _, mutate := range []func(*Program, function, function){
		func(p *Program, o, e function) {
			delete(p.functions, p.Find(p.module+"/resolver.(*"+p.module+"/resolver.DefaultResolver).output"))
		},
		func(p *Program, o, e function) { delete(p.functions, p.Find(p.module+"/resolver.expand")) },
		func(p *Program, o, e function) { o.node.Body = nil },
		func(p *Program, o, e function) { o.node.Body.List = o.node.Body.List[:1] },
		func(p *Program, o, e function) { o.node.Body.List[4] = &ast.EmptyStmt{} },
		func(p *Program, o, e function) { expansionGuard(o.node).Cond = ast.NewIdent("missing") },
		func(p *Program, o, e function) {
			delete(p.functions, p.Find(p.module+"/resolver.(*"+p.module+"/resolver.DefaultResolver).Resolve"))
		},
		func(p *Program, o, e function) { e.node.Body = nil },
		func(p *Program, o, e function) { e.node.Body.List = nil },
		func(p *Program, o, e function) { e.node.Body.List[len(e.node.Body.List)-1] = &ast.EmptyStmt{} },
		func(p *Program, o, e function) {
			e.node.Body.List[len(e.node.Body.List)-1].(*ast.ReturnStmt).Results = nil
		},
		func(p *Program, o, e function) {
			e.node.Body.List[len(e.node.Body.List)-1].(*ast.ReturnStmt).Results[0] = ast.NewIdent("missing")
		},
		func(p *Program, o, e function) {
			e.node.Body.List[len(e.node.Body.List)-1].(*ast.ReturnStmt).Results[0].(*ast.CallExpr).Args = nil
		},
		func(p *Program, o, e function) { o.node.Body.List[0] = &ast.EmptyStmt{} },
		func(p *Program, o, e function) { o.node.Body.List[0].(*ast.AssignStmt).Lhs = nil },
		func(p *Program, o, e function) { o.node.Body.List[0].(*ast.AssignStmt).Lhs[0] = &ast.BasicLit{} },
		func(p *Program, o, e function) {
			delete(o.unit.info.Defs, o.node.Body.List[0].(*ast.AssignStmt).Lhs[0].(*ast.Ident))
		},
		func(p *Program, o, e function) { expansionGuard(o.node).Body.List = nil },
		func(p *Program, o, e function) { expansionGuard(o.node).Body.List[0] = &ast.EmptyStmt{} },
		func(p *Program, o, e function) { expansionGuard(o.node).Body.List[0].(*ast.IfStmt).Init = nil },
		func(p *Program, o, e function) {
			expansionGuard(o.node).Body.List[0].(*ast.IfStmt).Init.(*ast.AssignStmt).Rhs = nil
		},
		func(p *Program, o, e function) {
			expansionGuard(o.node).Body.List[0].(*ast.IfStmt).Init.(*ast.AssignStmt).Rhs[0] = ast.NewIdent("missing")
		},
		func(p *Program, o, e function) {
			expansionGuard(o.node).Body.List[0].(*ast.IfStmt).Init.(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Args = nil
		},
		func(p *Program, o, e function) { delete(p.functions, p.Find(p.module+"/resolver.expandMethod")) },
	} {
		p := c("", "", "")
		o := p.functions[p.Find(p.module+"/resolver.(*"+p.module+"/resolver.DefaultResolver).output")]
		e := p.functions[p.Find(p.module+"/resolver.(*"+p.module+"/resolver.DefaultResolver).Resolve")]
		mutate(p, o, e)
		if a := p.ExpansionAudit(); len(a.Unknown) == 0 {
			t.Fatal("missing binding accepted", a)
		}
	}
	p := c("", "", "")
	original := string(p.source["resolver/expand.go"])
	next := strings.Replace(original, "m.ID = absolute(m.ID, base)", "_ = m.Extra; m.ID = absolute(m.ID, base)", 1)
	next = strings.Replace(next, "s.ID = absoluteString(s.ID, base)", "_ = s.Extra; s.ID = absoluteString(s.ID, base)", 1)
	a := c("resolver/expand.go", original, next).ExpansionAudit()
	if len(a.Unknown) != 0 || a.Roles["method_extensions"] != "true" || a.Roles["service_extensions"] != "true" {
		t.Fatal(a)
	}
	// A read is necessary, never sufficient. The changed helper frames must
	// remain distinct from the reviewed production witness.
	if a.Frames[p.module+"/resolver.expandMethod"] == p.ExpansionAudit().Frames[p.module+"/resolver.expandMethod"] {
		t.Fatal("unreviewed helper frame accepted")
	}
	f := p.functions[p.Find(p.module+"/resolver.(*"+p.module+"/resolver.DefaultResolver).output")]
	f.node.Body.List = f.node.Body.List[:1]
	if expansionFrame(p, f) != "" {
		t.Fatal("missing frame structure")
	}
	f.node.Name = &ast.Ident{Name: "invalid name"}
	if expansionFrame(p, f) != "" {
		t.Fatal("bad frame")
	}
}
