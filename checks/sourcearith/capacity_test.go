package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"os"
	"testing"
)

func TestCapacitySelectedU64(t *testing.T) {
	p := carryControl(t, "", "")
	a := p.CapacityAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 2 {
		t.Fatal(a)
	}
	for _, s := range a.Steps {
		if !s.Correct {
			t.Fatal(a)
		}
	}
	b, _ := json.MarshalIndent(a, "", "  ")
	t.Log(string(b))
	if os.Getenv("SAGE_CAPTURE_CAPACITY_WITNESS") != "" {
		if err := os.WriteFile(os.Getenv("SAGE_CAPTURE_CAPACITY_WITNESS"), append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCapacityFormulaAndUnknownFrames(t *testing.T) {
	p := carryControl(t, "", "")
	base := p.CapacityAudit()
	for _, c := range []struct{ old, new string }{{"+ 1\n}", "+ 2\n}"}, {"expansion(len(data)-zeroes, 256, base)", "expansion(len(data), 256, base)"}, {"expansion(len(encoded)-zeroes, base, 256)", "expansion(len(encoded)-zeroes, 256, base)"}} {
		a := carryControl(t, c.old, c.new).CapacityAudit()
		if len(a.Unknown) != 0 {
			t.Fatal(a)
		}
		if a.Steps[0].Correct && a.Steps[1].Correct {
			t.Fatal(a)
		}
		if len(a.Frames) != 8 {
			t.Fatal(a)
		}
	}
	a := carryControl(t, "base := len(alphabet)", "base := len(alphabet);base++").CapacityAudit()
	if a.Frames["BaseEncode"] == base.Frames["BaseEncode"] {
		t.Fatal("surrounding context hidden")
	}
	a = NewProgram(t.Context(), "test", nil).CapacityAudit()
	if len(a.Unknown) == 0 {
		t.Fatal(a)
	}
}

func TestCapacityUnknownMetadata(t *testing.T) {
	for _, mode := range []string{"alphabet", "frame", "shape", "helper-body", "helper-return", "helper-value", "call-edge", "call", "allocation", "storage", "zero-type", "arguments", "count"} {
		p := carryControl(t, "", "")
		fn := p.Find("test/internal/multiformats.BaseEncode")
		d := p.functions[fn]
		helper := p.functions[p.Find("test/internal/multiformats.expansion")]
		switch mode {
		case "alphabet":
			delete(p.functions, p.Find("test/internal/multiformats.alphabetFor"))
		case "frame":
			d.node.Name = ast.NewIdent("func")
		case "shape":
			d.node.Body.List[4] = &ast.EmptyStmt{}
		case "helper-body":
			helper.node.Body.List = append(helper.node.Body.List, &ast.ReturnStmt{Results: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "1"}}})
		case "helper-return":
			helper.node.Body.List[0] = &ast.ExprStmt{X: ast.NewIdent("unknown")}
		case "helper-value":
			helper.node.Body.List[0].(*ast.ReturnStmt).Results = nil
		case "call-edge":
			delete(p.functions, p.Find("test/internal/multiformats.floorLog2"))
		case "call":
			d.node.Body.List[4].(*ast.AssignStmt).Rhs[0] = ast.NewIdent("unknown")
		case "allocation":
			d.node.Body.List[5].(*ast.AssignStmt).Rhs[0] = ast.NewIdent("unknown")
		case "storage":
			d.node.Body.List[5].(*ast.AssignStmt).Lhs[0] = ast.NewIdent("unknown")
		case "zero-type":
			d.node.Body.List[5].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Args[1] = &ast.BasicLit{Kind: token.INT, Value: "2"}
		case "arguments":
			d.node.Body.List[4].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Args = nil
		case "count":
			delete(p.functions, p.Find("test/internal/multiformats.ceilLog2"))
		}
		if a := p.CapacityAudit(); len(a.Unknown) == 0 {
			t.Fatal(mode, a)
		}
	}
	for _, f := range []*ast.FuncDecl{{}, {Body: &ast.BlockStmt{List: []ast.Stmt{}}}} {
		if _, _, ok := capacityShape(f, true); ok {
			t.Fatal("shape")
		}
	}
}
