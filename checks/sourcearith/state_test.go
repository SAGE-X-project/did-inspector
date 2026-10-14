package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

func TestCodecStateTransitions(t *testing.T) {
	p := carryControl(t, "", "")
	for _, tt := range []struct {
		name  string
		count int
	}{{"BaseEncode", 2}, {"BaseDecode", 4}} {
		a := p.StateAudit("test/internal/multiformats." + tt.name)
		if a.Frame == "" || len(a.Unknown) != 0 || len(a.Steps) != tt.count {
			t.Fatal(a)
		}
		for _, step := range a.Steps {
			if !step.Correct || len(step.Expressions) == 0 {
				t.Fatal(a)
			}
		}
		b, _ := json.Marshal(a)
		t.Log(string(b))
	}
	if a := p.IntegerAudit("test/internal/multiformats.BaseDecode"); len(a.Operations) != 39 || !allInteger(a) {
		t.Fatal(a)
	}
	if a := p.CarryAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) != 0 || len(a.Steps) != 3 {
		t.Fatal(a)
	}
}
func TestStateWrongUpdatesAreIndependent(t *testing.T) {
	for _, tt := range []struct {
		old, replacement, root string
		bad                    int
	}{
		{"i++\n\t\t}", "i--\n\t\t}", "BaseEncode", 1},
		{"pos-- {", "pos++ {", "BaseEncode", 1},
		{"carry /= 256\n\t\t\ti++", "carry /= 256\n\t\t\ti--", "BaseDecode", 2},
		{"idx++ {", "idx-- {", "BaseDecode", 3},
		{"length = i\n\t}\n\tpos := size - length\n\tfor pos < size && decoded", "length += i\n\t}\n\tpos := size - length\n\tfor pos < size && decoded", "BaseDecode", 3},
		{"values[alphabet[i]] = i", "values[alphabet[i]] = base", "BaseDecode", 0},
		{"carry := values[encoded[idx]]", "carry := values[encoded[zeroes]]", "BaseDecode", 1},
	} {
		p := carryControl(t, tt.old, tt.replacement)
		a := p.StateAudit("test/internal/multiformats." + tt.root)
		if len(a.Unknown) != 0 || a.Steps[tt.bad].Correct {
			t.Fatal(tt, a)
		}
		// Map construction and current-character lookup have separate predicates.
		for i, s := range a.Steps {
			if i != tt.bad && !s.Correct {
				t.Fatal("unrelated step changed", tt, a)
			}
		}
	}
}
func TestUnreviewedStateShapes(t *testing.T) {
	for _, tt := range []struct{ old, replacement, root string }{
		{"carry := int(b)", "carry := int(b)+1", "BaseEncode"},
		{"carry := int(b)", "carry := int(b+0)", "BaseEncode"},
		{"carry := int(b)", "carry := int(byte(b))", "BaseEncode"},
		{"carry := values[encoded[idx]]", "carry := values[encoded[idx+0]]", "BaseDecode"},
		{"carry := values[encoded[idx]]", "carry := values[encoded[0]]", "BaseDecode"},
		{"carry := values[encoded[idx]]", "carry := values[encoded[idx]]+1", "BaseDecode"},

		{"i++\n\t\t}", "i+=1\n\t\t}", "BaseEncode"},
		{"pos-- {", "pos-=1 {", "BaseEncode"},
		{"idx++ {", "idx+=1 {", "BaseDecode"},
		{"values[i] = -1", "values[i] = 0", "BaseDecode"},
		{"values[alphabet[i]] = i", "values[i] = i", "BaseDecode"},
		{"values[alphabet[i]] = i", "values[alphabet[i]] = i+0", "BaseDecode"},
		{"values[alphabet[i]] = i", "values[alphabet[i+0]] = i", "BaseDecode"},
		{"values[alphabet[i]] = i", `values[(alphabet+"")[i]] = i`, "BaseDecode"},
		{"carry := values[encoded[idx]]", `carry := values[(encoded+"")[idx]]`, "BaseDecode"},
		{"length = i\n\t}\n\tpos := size - length\n\tfor pos < size && decoded", "length = i+0\n\t}\n\tpos := size - length\n\tfor pos < size && decoded", "BaseDecode"},
		{"i := 0\n\t\tfor pos", "i := 1\n\t\tfor pos", "BaseEncode"},
	} {
		a := carryControl(t, tt.old, tt.replacement).StateAudit("test/internal/multiformats." + tt.root)
		if len(a.Unknown) == 0 {
			t.Fatal("unknown state accepted", tt, a)
		}
	}
	p := carryControl(t, "", "")
	for _, root := range []string{"other", "test/internal/multiformats.Missing"} {
		if a := p.StateAudit(root); len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
	for _, replacement := range []string{"base++", "_=&base"} {
		a := carryControl(t, "base := len(alphabet)", "base := len(alphabet);"+replacement).StateAudit("test/internal/multiformats.BaseEncode")
		if a.Frame == p.StateAudit("test/internal/multiformats.BaseEncode").Frame {
			t.Fatal("unreviewed context hidden")
		}
	}
	d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	d.node.Name = &ast.Ident{Name: "func"}
	if stateFrame(p, d, true) != "" {
		t.Fatal("invalid frame")
	}
}
func TestASCIISelectorAndNoAliasWrites(t *testing.T) {
	original := carryControl(t, "", "")
	for _, tt := range []struct{ file, old, replacement string }{
		{"base.go", "AlphabetBase58BTC = \"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz\"", "AlphabetBase58BTC = \"Unicode-alphabet\""},
		{"multibase.go", "return \"\"\n}", "return \"non-standard\"\n}"},
		{"multibase.go", "switch header {", "switch header = 'u'; header {"},
		{"multibase.go", "alphabet := alphabetFor(header)", "alphabet := alphabetFor(header);alphabet=\"non-standard\""},
		{"multibase.go", "alphabet := alphabetFor(header)", "alphabet := alphabetFor(header);_= &alphabet"},
	} {
		files := map[string][]byte{}
		for k, v := range original.source {
			files[k] = v
		}
		key := "internal/multiformats/" + tt.file
		if !strings.Contains(string(files[key]), tt.old) {
			t.Fatal(tt)
		}
		files[key] = []byte(strings.Replace(string(files[key]), tt.old, tt.replacement, 1))
		p := NewProgram(t.Context(), "test", files)
		if _, e := p.Import("test/internal/multiformats"); e != nil {
			t.Fatal(e)
		}
		if p.asciiSelector() {
			t.Fatal("unproved alphabet scope accepted", tt)
		}
		if a := p.StateAudit("test/internal/multiformats.BaseDecode"); len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
}

func TestStateMissingOrMisattributedEvidence(t *testing.T) {
	for _, mode := range []string{"body", "carry-role", "counter-role", "index-init", "recurrence", "guard", "paren", "disjunction", "counter-guard", "range-byte", "conversion", "decode-cursor", "current-byte", "map-storage", "body-update", "length-role", "parameters"} {
		p := carryControl(t, "", "")
		name := "BaseEncode"
		if mode == "decode-cursor" || mode == "current-byte" || mode == "map-storage" {
			name = "BaseDecode"
		}
		f := p.Find("test/internal/multiformats." + name)
		d := p.functions[f]
		shape, _ := codecStateShape(d.node, name == "BaseEncode")
		info := d.unit.info
		switch mode {
		case "body":
			d.node.Body = nil
		case "carry-role":
			shape.carry.Lhs[0] = &ast.Ident{Name: "unbound"}
		case "counter-role":
			shape.counter.Tok = token.ASSIGN
		case "index-init":
			shape.inner.Init = &ast.EmptyStmt{}
		case "recurrence":
			shape.inner.Body.List[0].(*ast.AssignStmt).Rhs = nil
		case "guard":
			shape.inner.Cond = &ast.Ident{Name: "unknown"}
		case "paren":
			shape.inner.Cond.(*ast.BinaryExpr).X = &ast.Ident{Name: "unknown"}
		case "disjunction":
			shape.inner.Cond.(*ast.BinaryExpr).X.(*ast.ParenExpr).X = &ast.Ident{Name: "unknown"}
		case "counter-guard":
			shape.inner.Cond.(*ast.BinaryExpr).X.(*ast.ParenExpr).X.(*ast.BinaryExpr).Y = &ast.Ident{Name: "unknown"}
		case "range-byte":
			shape.outer.(*ast.RangeStmt).Value = &ast.Ident{Name: "unbound"}
		case "conversion":
			shape.carry.Rhs[0].(*ast.CallExpr).Fun = &ast.Ident{Name: "unknown"}
		case "decode-cursor":
			shape.outer.(*ast.ForStmt).Init = &ast.EmptyStmt{}
		case "current-byte":
			shape.carry.Rhs[0].(*ast.IndexExpr).Index = &ast.Ident{Name: "unknown"}
		case "map-storage":
			x := shape.carry.Rhs[0].(*ast.IndexExpr).X.(*ast.Ident)
			info.Uses[x] = info.Defs[shape.counter.Lhs[0].(*ast.Ident)]
		case "body-update":
			shape.inner.Body.List[3].(*ast.IncDecStmt).X = &ast.Ident{Name: "unbound"}
		case "length-role":
			shape.length.Lhs[0] = &ast.Ident{Name: "unbound"}
		case "parameters":
			delete(p.functions, f)
			sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(), f.Type().(*types.Signature).Results(), false)
			p.functions[types.NewFunc(f.Pos(), f.Pkg(), f.Name(), sig)] = d
		}
		if a := p.StateAudit("test/internal/multiformats." + name); len(a.Unknown) == 0 {
			t.Fatal(mode, a)
		}
	}
	p := checked(t, `package alg;var global int;func Root(){x:=0;_ = x}`)
	d := p.functions[p.Find("test/alg.Root")]
	a := d.node.Body.List[0].(*ast.AssignStmt)
	id := a.Lhs[0].(*ast.Ident)
	if v := definedLocal(d.unit.info, a); v == nil {
		t.Fatal("local missing")
	}
	a.Lhs[0] = &ast.IndexExpr{}
	if definedLocal(d.unit.info, a) != nil {
		t.Fatal("selector accepted")
	}
	a.Lhs[0] = id
	d.unit.info.Defs[id] = d.unit.pkg.Scope().Lookup("global")
	if definedLocal(d.unit.info, a) != nil {
		t.Fatal("global accepted")
	}
	a.Rhs = nil
	if definedLocal(d.unit.info, a) != nil {
		t.Fatal("invalid assignment")
	}
}
