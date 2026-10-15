package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

func urlRoleControls(t *testing.T) func(string, string, string) *Program {
	t.Helper()
	b, e := os.ReadFile("testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	all, _, e := ArchiveFiles(b, "github.com/sage-x-project/did-go@v0.0.0-20261012015322-ed54c505eafe")
	if e != nil {
		t.Fatal(e)
	}
	files := SourceFiles(all, []string{"dereferencer", "relyingparty", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"})
	if len(files) != 39 {
		t.Fatal(len(files))
	}
	standard := importer.ForCompiler(token.NewFileSet(), "source", nil)
	return func(file, old, next string) *Program {
		copy := map[string][]byte{}
		for n, b := range files {
			copy[n] = append([]byte(nil), b...)
		}
		if file != "" {
			if !strings.Contains(string(copy[file]), old) {
				t.Fatal(old)
			}
			copy[file] = []byte(strings.Replace(string(copy[file]), old, next, 1))
		}
		p := NewProgram(t.Context(), "github.com/sage-x-project/did-go", copy)
		p.standard = standard
		for _, n := range []string{"dereferencer", "relyingparty"} {
			if _, e := p.Import(p.module + "/" + n); e != nil {
				t.Fatal(e)
			}
		}
		return p
	}
}
func TestURLRolesTyped(t *testing.T) {
	c := urlRoleControls(t)
	p := c("", "", "")
	a := p.URLRolesAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 2 || a.Steps[0].Correct || !a.Steps[1].Correct {
		t.Fatal(a)
	}
	b, _ := json.Marshal(a)
	t.Log(string(b))
	for _, tc := range []struct {
		file, old, next string
		index           int
	}{
		{"dereferencer/dereferencer.go", "h(ctx, u, res, opts)", "h(ctx, u.WithoutFragment(), res, opts)", 0},
		{"did/url.go", "u.fragment, u.hasFragment = s[i+1:end], true", "u.fragment, u.hasFragment = s[i+0:end], true", 1},
		{"did/url.go", "s[i] == '#'", "s[i] == '?'", 1},
	} {
		a := c(tc.file, tc.old, tc.next).URLRolesAudit()
		if len(a.Unknown) != 0 || len(a.Steps) != 2 {
			t.Fatal(a)
		}
		want := tc.index == 0
		if a.Steps[tc.index].Correct != want {
			t.Fatal(a)
		}
	}
}

// Malformed source/AST controls are data only, never executed as a subject.
func TestURLRolesMissingShapesAndTypedBindings(t *testing.T) {
	c := urlRoleControls(t)
	nodes := func(p *Program) []function {
		names := []string{p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).resource", p.module + "/did.parseQueryFragment", p.module + "/did.(" + p.module + "/did.DIDURL).Fragment"}
		out := []function{}
		for _, n := range names {
			out = append(out, p.functions[p.Find(n)])
		}
		return out
	}
	for i, change := range []func(*Program, []function, urlRoleSites){
		func(p *Program, n []function, s urlRoleSites) {
			delete(p.functions, p.Find(p.module+"/document.findMethod"))
		},
		func(p *Program, n []function, s urlRoleSites) { n[0].node.Body = nil },
		func(p *Program, n []function, s urlRoleSites) { n[1].node.Body = nil },
		func(p *Program, n []function, s urlRoleSites) { s.loop.Body.List = nil },
		func(p *Program, n []function, s urlRoleSites) { n[1].node.Body.List[1].(*ast.IfStmt).Body.List = nil },
		func(p *Program, n []function, s urlRoleSites) { s.loop.Body.List[0] = &ast.EmptyStmt{} },
		func(p *Program, n []function, s urlRoleSites) {
			n[1].node.Body.List[1].(*ast.IfStmt).Cond = ast.NewIdent("missing")
		},
		func(p *Program, n []function, s urlRoleSites) {
			s.loop.Body.List[0].(*ast.IfStmt).Init = &ast.EmptyStmt{}
		},
		func(p *Program, n []function, s urlRoleSites) { s.extraction.Rhs = nil },
		func(p *Program, n []function, s urlRoleSites) { s.handler.Args = nil },
		func(p *Program, n []function, s urlRoleSites) { s.extraction.Rhs[0] = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) { s.loop.Value = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) { s.handler.Args[0] = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) { s.handler.Args[1] = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) {
			s.handler.Args[1] = &ast.CallExpr{Fun: ast.NewIdent("missing")}
		},
		func(p *Program, n []function, s urlRoleSites) { s.value.Low = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) { s.guard.Y = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) { s.value.High = ast.NewIdent("missing") },
		func(p *Program, n []function, s urlRoleSites) {
			n[1].unit.info.Types[s.extraction.Rhs[1]] = types.TypeAndValue{Type: types.Typ[types.Bool], Value: constant.MakeBool(false)}
		},
		func(p *Program, n []function, s urlRoleSites) { n[2].node.Body = nil },
		func(p *Program, n []function, s urlRoleSites) { n[2].node.Body.List[0] = &ast.EmptyStmt{} },
		func(p *Program, n []function, s urlRoleSites) {
			delete(p.functions, p.Find(p.module+"/did.scanQueryChars"))
		},
		func(p *Program, n []function, s urlRoleSites) { n[0].node.Name.Name = "invalid\n}" },
		func(p *Program, n []function, s urlRoleSites) {
			f := p.Find(p.module + "/document.findMethod")
			d := p.functions[f]
			ast.Inspect(d.node, func(x ast.Node) bool {
				if sel, ok := x.(*ast.SelectorExpr); ok && sel.Sel.Name == "Fragment" {
					sel.X = ast.NewIdent("missing")
				}
				return true
			})
		},
	} {
		p := c("", "", "")
		n := nodes(p)
		sites, ok := urlSites(n[0].node, n[1].node)
		if !ok {
			t.Fatal("control")
		}
		change(p, n, sites)
		a := p.URLRolesAudit()
		if len(a.Unknown) == 0 {
			t.Fatal(i, a)
		}
	}
	p := c("", "", "")
	n := nodes(p)
	if urlRoleArgument(p, nil, "missing", 0, nil) {
		t.Fatal("missing role")
	}
	n[0].node.Body = nil
	if urlRoleFrames(p, n[0], n[1]) != nil {
		t.Fatal("missing frame")
	}
	n = nodes(c("", "", ""))
	if _, ok := urlSites(&ast.FuncDecl{}, n[1].node); ok {
		t.Fatal("shape")
	}
}
