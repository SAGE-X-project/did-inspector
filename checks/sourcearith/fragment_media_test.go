package sourcearith

import (
	"encoding/json"
	"go/ast"
	"os"
	"testing"
)

func TestPlainJSONFragmentSelectionRoles(t *testing.T) {
	p := fragmentControls(t)("", "")
	a := p.FragmentMediaAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 2 {
		t.Fatal(a)
	}
	for _, s := range a.Steps {
		if !s.Correct {
			b, _ := json.Marshal(a)
			t.Fatal(string(b))
		}
	}
	if file := os.Getenv("SAGE_CAPTURE_MEDIA_WITNESS"); file != "" {
		b, _ := json.MarshalIndent(a, "", "  ")
		if err := os.WriteFile(file, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFragmentMediaUnknownSourceRoles(t *testing.T) {
	for _, mode := range []string{"missing", "body", "edge", "layout", "assignment", "calls", "storage", "return", "return-count", "result", "result-shape", "no-stream", "wrong-candidate"} {
		p := fragmentControls(t)("", "")
		f := p.Find(p.module + "/dereferencer.verificationMethod")
		d := p.functions[f]
		selectFn := p.functions[p.Find(p.module+"/document.SelectMethod")]
		switch mode {
		case "missing":
			delete(p.functions, p.Find(p.module+"/document.allMethods"))
		case "body":
			d.node.Body = nil
		case "edge":
			selectFn.node.Body.List[4].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Fun = ast.NewIdent("unbound")
		case "layout":
			d.node.Body.List = append(d.node.Body.List, &ast.EmptyStmt{})
		case "assignment":
			d.node.Body.List[2] = &ast.EmptyStmt{}
		case "calls":
			d.node.Body.List[2].(*ast.AssignStmt).Rhs[0] = ast.NewIdent("unbound")
		case "storage":
			d.node.Body.List[2].(*ast.AssignStmt).Lhs[0] = ast.NewIdent("unbound")
		case "return":
			selectFn.node.Body.List[10] = &ast.EmptyStmt{}
		case "return-count":
			selectFn.node.Body.List[10].(*ast.ReturnStmt).Results = nil
		case "result":
			d.node.Body.List[6] = &ast.EmptyStmt{}
		case "result-shape":
			d.node.Body.List[6].(*ast.ReturnStmt).Results[0] = ast.NewIdent("unbound")
		case "no-stream":
			d.node.Body.List[6].(*ast.ReturnStmt).Results[0].(*ast.CompositeLit).Elts = []ast.Expr{ast.NewIdent("unbound")}
		case "wrong-candidate":
			d.node.Body.List[6].(*ast.ReturnStmt).Results[0].(*ast.CompositeLit).Elts[0].(*ast.KeyValueExpr).Value = ast.NewIdent("unbound")
		}
		a := p.FragmentMediaAudit()
		if len(a.Unknown) == 0 {
			good := true
			for _, s := range a.Steps {
				good = good && s.Correct
			}
			if good {
				t.Fatal(mode, a)
			}
		}
	}
}
