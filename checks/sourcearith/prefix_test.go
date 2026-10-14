package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"go/types"
	"testing"
)

func TestPrefixStateProjection(t *testing.T) {
	p := carryControl(t, "", "")
	for _, name := range []string{"BaseEncode", "BaseDecode"} {
		a := p.PrefixAudit("test/internal/multiformats." + name)
		if a.Frame == "" || len(a.Unknown) != 0 || len(a.Steps) != 2 || len(a.Projection) != 4 || a.Roles["first_length_use"] == "" || a.Roles["input_end"] == "" {
			t.Fatal(a)
		}
		for _, s := range a.Steps {
			if !s.Correct {
				t.Fatal(a)
			}
		}
		data, _ := json.Marshal(a)
		t.Log(string(data))
	}
}
func TestPrefixPredicatesAndIndependentInitialization(t *testing.T) {
	for _, tc := range []struct {
		old, replacement, root string
		initial, count         bool
	}{
		{"length := 0", "length := 1", "BaseEncode", false, true},
		{"decoded := make([]int, size)\n\tlength := 0", "decoded := make([]int, size)\n\tlength := 1", "BaseDecode", false, true},
		{"zeroes := 0", "zeroes := 1", "BaseEncode", false, false},
		{"zeroes := 0\n\tfor zeroes < len(encoded)", "zeroes := 1\n\tfor zeroes < len(encoded)", "BaseDecode", false, false},
		{"data[zeroes] == 0", "data[zeroes] == 1", "BaseEncode", true, false},
		{"data[zeroes] == 0", "data[zeroes] != 0", "BaseEncode", true, false},
		{"zeroes < len(data)", "zeroes <= len(data)", "BaseEncode", true, false},
		{"zeroes < len(data) &&", "zeroes < len(data) ||", "BaseEncode", true, false},
		{"zeroes++\n\t}", "zeroes--\n\t}", "BaseEncode", true, false},
		{"data[zeroes] == 0", "data[base] == 0", "BaseEncode", true, false},
		{"range data[zeroes:]", "range data[length:]", "BaseEncode", true, false},
		{"encoded[zeroes] == alphabet[0]", "encoded[zeroes] == alphabet[1]", "BaseDecode", true, false},
		{"encoded[zeroes] == alphabet[0]", "alphabet[zeroes] == alphabet[0]", "BaseDecode", true, false},
		{"idx := zeroes;", "idx := length;", "BaseDecode", true, false},
	} {
		a := carryControl(t, tc.old, tc.replacement).PrefixAudit("test/internal/multiformats." + tc.root)
		if len(a.Unknown) != 0 || len(a.Steps) != 2 || a.Steps[0].Correct != tc.initial || a.Steps[1].Correct != tc.count {
			t.Fatal(tc, a)
		}
	}
}
func TestPrefixUnsupportedEquivalenceAndContext(t *testing.T) {
	baseline := carryControl(t, "", "")
	for _, tc := range []struct{ old, replacement, root string }{
		{"zeroes++\n\t}", "zeroes+=1\n\t}", "BaseEncode"},
		{"data[zeroes] == 0", "data[zeroes+0] == 0", "BaseEncode"},
		{"range data[zeroes:]", "range data[zeroes+0:]", "BaseEncode"},
		{"length := 0", "length := zeroes", "BaseEncode"},
		{"zeroes < len(data)", "zeroes < cap(data)", "BaseEncode"},
		{"alphabet[0] {\n\t\tzeroes++", "alphabet[zeroes] {\n\t\tzeroes++", "BaseDecode"},
		{"zeroes++\n\t}", "zeroes++; _=&data\n\t}", "BaseEncode"},
		{"length := 0", "length := 0; data[0]=1", "BaseEncode"},
	} {
		a := carryControl(t, tc.old, tc.replacement).PrefixAudit("test/internal/multiformats." + tc.root)
		b := baseline.PrefixAudit("test/internal/multiformats." + tc.root)
		if len(a.Unknown) == 0 && a.Frame == b.Frame {
			t.Fatal("unproved context/equivalence accepted", tc, a)
		}
	}
	for _, root := range []string{"other", "test/internal/multiformats.Missing"} {
		if a := baseline.PrefixAudit(root); len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
	empty := NewProgram(t.Context(), "test", nil)
	if a := empty.PrefixAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) == 0 {
		t.Fatal("missing source accepted")
	}
}
func TestMissingPrefixShapeAndBindings(t *testing.T) {
	for _, mode := range []string{"body", "zero-definition", "zero-value", "length-binding", "condition", "guard", "update", "count", "call", "current", "update-binding", "offset", "builtin", "zero-symbol", "ascii", "alphabet-symbol", "alphabet-binding", "first-read", "end-input", "end-shape", "end-call", "end-builtin", "range-shape", "range-high", "decode-init", "length-shape", "scan-init"} {
		p := carryControl(t, "", "")
		name := "BaseEncode"
		if mode == "ascii" || mode == "alphabet-symbol" || mode == "alphabet-binding" || mode == "end-shape" || mode == "end-call" || mode == "end-builtin" || mode == "decode-init" {
			name = "BaseDecode"
		}
		d := p.functions[p.Find("test/internal/multiformats."+name)]
		shape, _ := prefixStructure(d.node, name == "BaseEncode")
		state, _ := codecStateShape(d.node, name == "BaseEncode")
		cond := shape.scan.Cond.(*ast.BinaryExpr)
		limit := cond.X.(*ast.BinaryExpr)
		value := cond.Y.(*ast.BinaryExpr)
		bad := &ast.Ident{Name: "unbound"}
		switch mode {
		case "body":
			d.node.Body = nil
		case "zero-definition":
			shape.zero.Tok = token.ASSIGN
		case "zero-value":
			delete(d.unit.info.Types, shape.zero.Rhs[0])
		case "length-binding":
			state.length.Lhs[0] = bad
		case "condition":
			shape.scan.Cond = bad
		case "guard":
			cond.X = bad
		case "update":
			shape.scan.Body.List[0] = &ast.EmptyStmt{}
		case "count":
			limit.X = bad
		case "call":
			limit.Y = bad
		case "current":
			value.X = bad
		case "update-binding":
			shape.scan.Body.List[0].(*ast.IncDecStmt).X = bad
		case "offset":
			state.outer.(*ast.RangeStmt).X.(*ast.SliceExpr).Low = bad
		case "builtin":
			limit.Y.(*ast.CallExpr).Fun = bad
		case "zero-symbol":
			value.Y = bad
		case "ascii":
			p.functions[p.Find("test/internal/multiformats.EncodeMultibase")].node.Body = nil
		case "alphabet-symbol":
			value.Y = bad
		case "alphabet-binding":
			value.Y.(*ast.IndexExpr).X = bad
		case "first-read":
			length := definedLocal(d.unit.info, shape.length)
			first := &ast.Ident{Name: "length", NamePos: shape.length.Pos() - 1}
			d.unit.info.Uses[first] = length
			d.node.Body.List = append([]ast.Stmt{&ast.ExprStmt{X: first}}, d.node.Body.List...)
		case "end-input":
			state.outer.(*ast.RangeStmt).X.(*ast.SliceExpr).X = bad
		case "end-shape":
			state.outer.(*ast.ForStmt).Cond = bad
		case "end-call":
			state.outer.(*ast.ForStmt).Cond.(*ast.BinaryExpr).Y = bad
		case "end-builtin":
			state.outer.(*ast.ForStmt).Cond.(*ast.BinaryExpr).Y.(*ast.CallExpr).Fun = bad
		case "range-shape":
			state.outer.(*ast.RangeStmt).X = bad
		case "range-high":
			state.outer.(*ast.RangeStmt).X.(*ast.SliceExpr).High = bad
		case "decode-init":
			state.outer.(*ast.ForStmt).Init = &ast.EmptyStmt{}
		case "length-shape":
			shape.length.Rhs = nil
		case "scan-init":
			shape.scan.Init = &ast.EmptyStmt{}
		}
		if a := p.PrefixAudit("test/internal/multiformats." + name); len(a.Unknown) == 0 {
			t.Fatal(mode, a)
		}
	}
}
func TestPrefixFrameInvalidSourceAndLengthPhase(t *testing.T) {
	p := carryControl(t, "", "")
	d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	d.node.Name = &ast.Ident{Name: "func"}
	if prefixFrame(p, d, true) != "" {
		t.Fatal("malformed frame accepted")
	}
	d.node.Name = &ast.Ident{Name: "BaseEncode"}
	d.node.Body = nil
	if prefixFrame(p, d, true) != "" {
		t.Fatal("missing shape accepted")
	}
	// A disconnected initializer cannot give phase evidence for an unrelated
	// storage object, even when the surrounding source has a length variable.
	p = carryControl(t, "", "")
	d = p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	shape, _ := prefixStructure(d.node, true)
	if _, ok := firstLengthRead(p, d, shape.length, types.NewVar(token.NoPos, nil, "unrelated", types.Typ[types.Int])); ok {
		t.Fatal("missing length uses accepted")
	}
	if _, ok := inputLoopEnd(p, function{node: &ast.FuncDecl{}}, true, nil); ok {
		t.Fatal("missing input loop accepted")
	}
}
