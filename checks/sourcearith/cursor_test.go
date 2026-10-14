package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/types"
	"strings"
	"testing"
)

func TestCursorProjectionBindings(t *testing.T) {
	p := carryControl(t, "", "")
	for _, name := range []string{"BaseEncode", "BaseDecode"} {
		a := p.CursorAudit("test/internal/multiformats." + name)
		if a.Frame == "" || len(a.Unknown) != 0 || len(a.Projection) == 0 || len(a.Roles) == 0 {
			t.Fatal(a)
		}
		for _, s := range a.Steps {
			if !s.Correct {
				t.Fatal(a)
			}
		}
		b, _ := json.Marshal(a)
		t.Log(string(b))
	}
	if a := p.StateAudit("test/internal/multiformats.BaseDecode"); len(a.Unknown) != 0 || len(a.Steps) != 4 {
		t.Fatal("AST changed", a)
	}
}
func TestWrongCursorComponentsAreIndependent(t *testing.T) {
	for _, tt := range []struct {
		old, replacement, root string
		bad                    int
	}{
		{"range data[zeroes:]", "range data[length:]", "BaseEncode", 0},
		{"length = i\n\t}\n\tpos := size - length\n\tfor pos < size && digits", "length += i\n\t}\n\tpos := size - length\n\tfor pos < size && digits", "BaseEncode", 1},
		{"idx := zeroes;", "idx := length;", "BaseDecode", 0},
		{"idx < len(encoded)", "idx <= len(encoded)", "BaseDecode", 0},
		{"idx++ {", "idx-- {", "BaseDecode", 0},
	} {
		a := carryControl(t, tt.old, tt.replacement).CursorAudit("test/internal/multiformats." + tt.root)
		if tt.root == "BaseDecode" {
			for _, p := range a.Projection {
				if !strings.HasPrefix(p, "expected relation:") {
					t.Fatal("failed projection portrayed as observed success", a)
				}
			}
		}
		if len(a.Unknown) != 0 || a.Steps[tt.bad].Correct {
			t.Fatal(tt, a)
		}
		for i, s := range a.Steps {
			if i != tt.bad && !s.Correct {
				t.Fatal("verdict coupling", tt, a)
			}
		}
	}
}
func TestUnsupportedCursorFormsAndContext(t *testing.T) {
	baseline := carryControl(t, "", "")
	for _, tt := range []struct{ old, replacement, root string }{
		{"range data[zeroes:]", "range data[zeroes+0:]", "BaseEncode"},
		{"range data[zeroes:]", "range data[zeroes:len(data)]", "BaseEncode"},
		{"length = i\n\t}\n\tpos := size - length\n\tfor pos < size && digits", "length = i+0\n\t}\n\tpos := size - length\n\tfor pos < size && digits", "BaseEncode"},
		{"idx := zeroes;", "idx := zeroes+0;", "BaseDecode"},
		{"idx < len(encoded)", "idx < len(encoded+\"\")", "BaseDecode"},
		{"idx++ {", "idx+=1 {", "BaseDecode"},
		{"zeroes++\n\t}", "zeroes+=1\n\t}", "BaseEncode"},
		{"zeroes := 0", "zeroes := 1", "BaseEncode"},
		{"zeroes < len(data)", "zeroes <= len(data)", "BaseEncode"},
		{"zeroes < len(data)", "zeroes < cap(data)", "BaseEncode"},
		{"zeroes < len(data)", "zeroes < len(alphabet)", "BaseEncode"},
		{"zeroes++\n\t}", "zeroes--\n\t}", "BaseEncode"},
	} {
		a := carryControl(t, tt.old, tt.replacement).CursorAudit("test/internal/multiformats." + tt.root)
		if len(a.Unknown) == 0 {
			t.Fatal("unproved equivalence accepted", tt, a)
		}
	}
	for _, extra := range []string{"data[zeroes]=1", "_= &data", "continue"} {
		p := carryControl(t, "length = i\n\t}\n\tpos := size - length\n\tfor pos < size && digits", "length = i;"+extra+"\n\t}\n\tpos := size - length\n\tfor pos < size && digits")
		a := p.CursorAudit("test/internal/multiformats.BaseEncode")
		if len(a.Unknown) == 0 && a.Frame == baseline.CursorAudit("test/internal/multiformats.BaseEncode").Frame {
			t.Fatal("mutation/escape/transfer accepted", extra)
		}
	}
	p := baseline
	for _, root := range []string{"other", "test/internal/multiformats.Missing"} {
		if a := p.CursorAudit(root); len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
	for _, encode := range []bool{true, false} {
		name := "BaseDecode"
		if encode {
			name = "BaseEncode"
		}
		p := carryControl(t, "", "")
		d := p.functions[p.Find("test/internal/multiformats."+name)]
		shape, _ := codecStateShape(d.node, encode)
		if encode {
			d.node.Body = nil
		} else {
			shape.outer.(*ast.ForStmt).Init = &ast.EmptyStmt{}
		}
		if cursorFrame(p, d, encode) != "" {
			t.Fatal("missing frame accepted")
		}
	}
	p = carryControl(t, "", "")
	d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	d.node.Name = &ast.Ident{Name: "func"}
	if cursorFrame(p, d, true) != "" {
		t.Fatal("malformed frame accepted")
	}
}

func TestMissingCursorEvidence(t *testing.T) {
	for _, mode := range []string{"shape", "state", "range-key", "length", "decode-operand", "decode-length"} {
		p := carryControl(t, "", "")
		name := "BaseEncode"
		if mode == "decode-operand" || mode == "decode-length" {
			name = "BaseDecode"
		}
		d := p.functions[p.Find("test/internal/multiformats."+name)]
		shape, _ := codecStateShape(d.node, name == "BaseEncode")
		switch mode {
		case "shape":
			d.node.Body = nil
		case "state":
			shape.carry.Lhs[0] = &ast.Ident{Name: "unbound"}
		case "range-key":
			shape.outer.(*ast.RangeStmt).Key = &ast.Ident{Name: "named"}
		case "length":
			shape.length.Rhs[0] = &ast.Ident{Name: "unbound"}
		case "decode-operand":
			shape.outer.(*ast.ForStmt).Cond.(*ast.BinaryExpr).X = &ast.Ident{Name: "unbound"}
		case "decode-length":
			call := shape.outer.(*ast.ForStmt).Cond.(*ast.BinaryExpr).Y.(*ast.CallExpr)
			fun := &ast.Ident{Name: "cap"}
			d.unit.info.Uses[fun] = types.Universe.Lookup("cap")
			call.Fun = fun
		}
		if a := p.CursorAudit("test/internal/multiformats." + name); len(a.Unknown) == 0 {
			t.Fatal(mode, a)
		}
	}
}
