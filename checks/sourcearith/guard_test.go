package sourcearith

import (
	"encoding/json"
	"go/ast"
	"testing"
)

func TestGuardInitializationAndReachableBounds(t *testing.T) {
	p := carryControl(t, "", "")
	for _, name := range []string{"BaseEncode", "BaseDecode"} {
		a := p.GuardAudit("test/internal/multiformats." + name)
		if len(a.Unknown) != 0 || a.Frame == "" || len(a.Steps) != 1 || !a.Steps[0].Correct || len(a.Roles) != 6 || len(a.Scope) != 4 {
			t.Fatal(a)
		}
		data, _ := json.Marshal(a)
		t.Log(string(data))
	}
	// These semantic boundaries check the projected guard's reachable domain,
	// independently of executing any modified subject source.
	for _, size := range []int{0, 1, 8} {
		for pos := size - 1; pos >= -1; pos-- {
			if (pos >= 0) != (pos != -1) {
				t.Fatal(size, pos)
			}
			for _, carry := range []int{0, 1} {
				for _, length := range []int{0, 1, size} {
					i := size - 1 - pos
					actual := (carry != 0 || i < length) && pos >= 0
					reference := (carry != 0 || i < length) && pos != -1
					if actual != reference {
						t.Fatal(size, pos, carry, length)
					}
				}
			}
		}
	}
}
func TestGuardRecognizedVariantsAndViolations(t *testing.T) {
	for _, tc := range []struct {
		old, replacement string
		want             bool
	}{
		{"i := 0", "i := 1", false},
		{"pos := size - 1", "pos := size - 2", false},
		{"pos := size - 1", "pos := base - 1", false},
		{"pos := size - 1", "pos := size + (-1)", true},
		{"carry != 0", "carry == 0", false},
		{"carry != 0", "carry != 1", false},
		{"carry != 0", "base != 0", false},
		{"carry != 0 ||", "carry != 0 &&", false},
		{"i < length", "i <= length", false},
		{"i < length", "pos < length", false},
		{"i < length", "i < size", false},
		{"&& pos >= 0", "|| pos >= 0", false},
		{"pos >= 0", "pos > 0", false},
		{"pos >= 0", "i >= 0", false},
		{"pos >= 0", "pos >= 1", false},
		{"pos >= 0", "pos != -1", true},
		{"pos >= 0", "pos > -1", true},
	} {
		a := carryControl(t, tc.old, tc.replacement).GuardAudit("test/internal/multiformats.BaseEncode")
		if len(a.Unknown) != 0 || len(a.Steps) != 1 || a.Steps[0].Correct != tc.want {
			t.Fatal(tc, a)
		}
	}
	// A wrong encoder guard cannot copy its failure to the decoder.
	p := carryControl(t, "carry != 0", "carry == 0")
	if !p.GuardAudit("test/internal/multiformats.BaseDecode").Steps[0].Correct {
		t.Fatal("coupled roots")
	}
}
func TestGuardUnsupportedContextAndOperands(t *testing.T) {
	baseline := carryControl(t, "", "").GuardAudit("test/internal/multiformats.BaseEncode")
	for _, tc := range []struct{ old, replacement string }{
		{"pos >= 0", "pos+0 >= 0"},
		{"pos := size - 1", "pos := size - base"},
		{"i := 0", "i := length"},
		{"pos-- {", "pos-=1 {"},
		{"i++\n\t\t}", "i+=1\n\t\t}"},
		{"make([]int, size)", "make([]int, base)"},
		{"length := 0", "length := 0;size++"},
		{"i++\n\t\t}", "i++; _=&pos\n\t\t}"},
		{"i++\n\t\t}", "i++;break\n\t\t}"},
	} {
		a := carryControl(t, tc.old, tc.replacement).GuardAudit(baseline.Root)
		if len(a.Unknown) == 0 && a.Frame == baseline.Frame {
			t.Fatal("unsupported context accepted", tc, a)
		}
	}
	for _, root := range []string{"other", "test/internal/multiformats.Missing"} {
		if len(carryControl(t, "", "").GuardAudit(root).Unknown) == 0 {
			t.Fatal(root)
		}
	}
	p := NewProgram(t.Context(), "test", nil)
	if len(p.GuardAudit("test/internal/multiformats.BaseEncode").Unknown) == 0 {
		t.Fatal("missing source")
	}
}
func TestMissingGuardEvidence(t *testing.T) {
	for _, mode := range []string{"body", "counter-shape", "init", "store", "cell", "buffer", "counter", "start", "condition", "group", "choice", "bound", "nonzero", "prior", "post", "increment", "constant", "operand", "make", "make-args", "make-builtin", "make-slice", "make-size"} {
		p := carryControl(t, "", "")
		d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
		s, _ := codecStateShape(d.node, true)
		bad := &ast.Ident{Name: "unbound"}
		cond := s.inner.Cond.(*ast.BinaryExpr)
		choice := cond.X.(*ast.ParenExpr).X.(*ast.BinaryExpr)
		switch mode {
		case "body":
			d.node.Body = nil
		case "counter-shape":
			s.counter.Rhs = nil
		case "init":
			s.inner.Init = &ast.EmptyStmt{}
		case "store":
			s.inner.Body.List[1] = &ast.EmptyStmt{}
		case "cell":
			s.inner.Body.List[1].(*ast.AssignStmt).Lhs[0] = bad
		case "buffer":
			s.inner.Body.List[1].(*ast.AssignStmt).Lhs[0].(*ast.IndexExpr).X = bad
		case "counter":
			s.counter.Tok = 0
		case "start":
			s.inner.Init.(*ast.AssignStmt).Rhs[0] = bad
		case "condition":
			s.inner.Cond = bad
		case "group":
			cond.X = bad
		case "choice":
			cond.X.(*ast.ParenExpr).X = bad
		case "bound":
			cond.Y = bad
		case "nonzero":
			choice.X = bad
		case "prior":
			choice.Y = bad
		case "post":
			s.inner.Post = &ast.EmptyStmt{}
		case "increment":
			s.inner.Body.List[3] = &ast.EmptyStmt{}
		case "constant":
			delete(d.unit.info.Types, s.counter.Rhs[0])
		case "operand":
			choice.Y.(*ast.BinaryExpr).X = bad
		default:
			for _, stmt := range d.node.Body.List {
				a, ok := stmt.(*ast.AssignStmt)
				if !ok || !singleAssignment(a) {
					continue
				}
				call, ok := a.Rhs[0].(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					continue
				}
				switch mode {
				case "make":
					a.Rhs[0] = bad
				case "make-args":
					call.Args = nil
				case "make-builtin":
					call.Fun = bad
				case "make-slice":
					tv := d.unit.info.Types[call]
					tv.Type = d.unit.info.TypeOf(call.Args[1])
					d.unit.info.Types[call] = tv
				case "make-size":
					call.Args[1] = bad
				}
				break
			}
		}
		if a := p.GuardAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) == 0 {
			t.Fatal(mode, a)
		}
	}
	p := carryControl(t, "", "")
	d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	d.node.Name = &ast.Ident{Name: "func"}
	if guardFrame(p, d, true) != "" {
		t.Fatal("bad frame")
	}
	d.node.Name = &ast.Ident{Name: "BaseEncode"}
	s, _ := codecStateShape(d.node, true)
	s.counter.Rhs = nil
	if guardFrame(p, d, true) != "" {
		t.Fatal("missing frame structure")
	}
	p = carryControl(t, "", "")
	d = p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	s, _ = codecStateShape(d.node, true)
	s.inner.Init = &ast.EmptyStmt{}
	if guardFrame(p, d, true) != "" {
		t.Fatal("missing frame init")
	}
	d.node.Body = nil
	if guardFrame(p, d, true) != "" {
		t.Fatal("bodyless function frame accepted")
	}
}
