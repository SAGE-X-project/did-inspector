package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// Each control has fresh subject AST/type objects. Only immutable installed
// standard-library packages are cached within a test, avoiding repeated std
// parsing without sharing mutated subject objects or executing control source.
func outputControls(t *testing.T) func(string, string) *Program {
	t.Helper()
	archive, e := os.ReadFile("testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	files, _, e := ArchiveFiles(archive, "github.com/sage-x-project/did-go@v0.0.0-20261012015322-ed54c505eafe")
	if e != nil {
		t.Fatal(e)
	}
	source := SourceFiles(files, []string{"internal/multiformats"})
	standard := importer.ForCompiler(token.NewFileSet(), "source", nil)
	return func(old, replacement string) *Program {
		t.Helper()
		input := map[string][]byte{}
		for k, b := range source {
			input[k] = b
		}
		if old != "" {
			s := string(input["internal/multiformats/base.go"])
			if !strings.Contains(s, old) {
				t.Fatal("missing control", old)
			}
			input["internal/multiformats/base.go"] = []byte(strings.Replace(s, old, replacement, 1))
		}
		p := NewProgram(t.Context(), "test", input)
		p.standard = standard
		if _, e := p.Import("test/internal/multiformats"); e != nil {
			t.Fatal(e)
		}
		return p
	}
}
func TestOutputSourceBindingsAndPhaseProjection(t *testing.T) {
	control := outputControls(t)
	p := control("", "")
	for _, name := range []string{"BaseEncode", "BaseDecode"} {
		a := p.OutputAudit("test/internal/multiformats." + name)
		count := 3
		if name == "BaseDecode" {
			count = 2
		}
		if a.Frame == "" || len(a.Unknown) != 0 || len(a.Steps) != count || len(a.Roles) != 7 {
			t.Fatal(a)
		}
		for _, step := range a.Steps {
			if !step.Correct {
				t.Fatal(a)
			}
		}
		b, _ := json.Marshal(a)
		t.Log(string(b))
	}
	// The decoder's logical target size is realized progressively. These owned
	// small slices illustrate the phase relation, not execute a subject codec.
	for _, prefix := range []int{0, 1, 3} {
		for _, suffix := range []int{0, 1, 4} {
			out := make([]byte, prefix, prefix+suffix)
			if len(out) != prefix {
				t.Fatal("capacity treated as initial length")
			}
			for k := 0; k < suffix; k++ {
				out = append(out, byte(k+1))
				if len(out) != prefix+k+1 {
					t.Fatal("growth")
				}
			}
			if len(out) != prefix+suffix {
				t.Fatal("final size")
			}
			for _, v := range out[:prefix] {
				if v != 0 {
					t.Fatal("prefix changed")
				}
			}
		}
	}
}
func TestOutputPredicatesRemainIndependent(t *testing.T) {
	control := outputControls(t)
	for _, tc := range []struct {
		old, replacement, root string
		bad                    int
	}{
		{"strings.Repeat(alphabet[:1], zeroes)", "strings.Repeat(alphabet[:1], size)", "BaseEncode", 0},
		{"strings.Repeat(alphabet[:1], zeroes)", "strings.Repeat(alphabet[:2], zeroes)", "BaseEncode", 0},
		{"for ; pos < size; pos++", "for ; pos <= size; pos++", "BaseEncode", 1},
		{"for ; pos < size; pos++", "for ; zeroes < size; pos++", "BaseEncode", 1},
		{"sb.WriteByte(alphabet[digits[pos]])", "sb.WriteByte(alphabet[digits[zeroes]])", "BaseEncode", 1},
		{"for ; pos < size; pos++", "for ; pos < base; pos++", "BaseEncode", 1},
		{"for ; pos < size; pos++", "for ; pos < size; pos--", "BaseEncode", 1},
		{"pos := size - length\n\tfor pos < size && decoded[pos] == 0", "pos := size + length\n\tfor pos < size && decoded[pos] == 0", "BaseDecode", 0},
		{"decoded[pos] == 0", "decoded[pos] != 0", "BaseDecode", 0},
		{"decoded[pos] == 0", "decoded[pos] == 1", "BaseDecode", 0},
		{"pos < size && decoded[pos]", "pos <= size && decoded[pos]", "BaseDecode", 0},
		{"pos < size && decoded[pos]", "pos < size || decoded[pos]", "BaseDecode", 0},
		{"decoded[pos] == 0", "decoded[zeroes] == 0", "BaseDecode", 0},
		{"decoded[pos] == 0", "values[pos] == 0", "BaseDecode", 0},
		{"decoded[pos] == 0 {\n\t\tpos++", "decoded[pos] == 0 {\n\t\tpos--", "BaseDecode", 0},
		{"out := make([]byte, zeroes, zeroes+size-pos)", "out := make([]byte, size, zeroes+size-pos)", "BaseDecode", 1},
	} {
		a := control(tc.old, tc.replacement).OutputAudit("test/internal/multiformats." + tc.root)
		if len(a.Unknown) != 0 {
			t.Fatal(tc, a)
		}
		for i, step := range a.Steps {
			if step.Correct == (i == tc.bad) {
				t.Fatal(tc, a)
			}
		}
	}
	// A returned constant is an unreviewed expression, never an inferred PASS.
	if a := control("return sb.String(), nil", "return alphabet, nil").OutputAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) == 0 {
		t.Fatal(a)
	}
}
func TestOutputUnsupportedContextAndCapacityPolicy(t *testing.T) {
	control := outputControls(t)
	for _, tc := range []struct{ old, replacement, root string }{
		{"sb.Grow(zeroes + size - pos)", "sb.Grow(zeroes + size - pos);sb.Reset()", "BaseEncode"},
		{"var sb strings.Builder", "var sb = &strings.Builder{}", "BaseEncode"},
		{"sb.WriteByte(alphabet[digits[pos]])", "sb.WriteByte(alphabet[digits[pos]]);sb.Reset()", "BaseEncode"},
		{"return sb.String(), nil", "return sb.String()[:1], nil", "BaseEncode"},
		{"alphabet[:1]", "alphabet[1:2]", "BaseEncode"},
		{"alphabet[digits[pos]]", "alphabet[digits[pos+0]]", "BaseEncode"},
		{"zeroes+size-pos", "zeroes+size-pos+1", "BaseDecode"},
		{"zeroes+size-pos", "zeroes+base-pos", "BaseDecode"},
		{"out = append(out, byte(decoded[pos]))", "out = append(out, byte(decoded[pos]),0)", "BaseDecode"},
		{"out = append(out, byte(decoded[pos]))", "out = append(out, byte(decoded[pos]));out[0]=1", "BaseDecode"},
		{"return out, nil", "return out[:1], nil", "BaseDecode"},
		{"length := 0", "length := 1", "BaseEncode"},
		{"i := 0", "i := 1", "BaseEncode"},
	} {
		p := control(tc.old, tc.replacement)
		a := p.OutputAudit("test/internal/multiformats." + tc.root)
		base := control("", "").OutputAudit(a.Root)
		if len(a.Unknown) == 0 && a.Frame == base.Frame {
			t.Fatal("changed context accepted", tc, a)
		}
	}
	p := control("", "")
	for _, name := range []string{"other", "test/internal/multiformats.Missing"} {
		if len(p.OutputAudit(name).Unknown) == 0 {
			t.Fatal(name)
		}
	}
	p = NewProgram(t.Context(), "test", nil)
	if len(p.OutputAudit("test/internal/multiformats.BaseEncode").Unknown) == 0 {
		t.Fatal("missing source")
	}
}
func TestMissingOutputEvidence(t *testing.T) {
	control := outputControls(t)
	for _, mode := range []string{"body", "store", "cell", "size", "position", "ascii", "counter", "prefix", "prefix-arg", "builder", "builder-method", "repeat", "repeat-fun", "repeat-slice", "repeat-bound", "repeat-count", "suffix-cond", "suffix-post", "suffix-body", "suffix-write", "suffix-builder", "suffix-symbol", "suffix-cell", "suffix-operand", "return", "return-builder", "scan-start", "scan-cond", "scan-guard", "scan-post", "scan-symbol", "scan-operand", "allocation", "allocation-args", "allocation-output", "allocation-type", "capacity", "capacity-sum", "capacity-operand", "growth-guard", "growth-post", "growth-store", "append", "append-builtin", "convert", "convert-cell", "final-return"} {
		p := control("", "")
		encode := !strings.HasPrefix(mode, "scan-") && !strings.HasPrefix(mode, "allocation") && !strings.HasPrefix(mode, "capacity") && !strings.HasPrefix(mode, "growth") && !strings.HasPrefix(mode, "append") && !strings.HasPrefix(mode, "convert") && mode != "final-return"
		name := "BaseEncode"
		if !encode {
			name = "BaseDecode"
		}
		d := p.functions[p.Find("test/internal/multiformats."+name)]
		s, _ := outputStructure(d.node, encode)
		state, _ := codecStateShape(d.node, encode)
		bad := &ast.Ident{Name: "unbound"}
		switch mode {
		case "body":
			d.node.Body = nil
		case "store":
			state.inner.Body.List[1] = &ast.EmptyStmt{}
		case "cell":
			state.inner.Body.List[1].(*ast.AssignStmt).Lhs[0] = bad
		case "size":
			state.inner.Body.List[1].(*ast.AssignStmt).Lhs[0].(*ast.IndexExpr).X = bad
		case "position":
			s.position.Tok = token.ASSIGN
		case "ascii":
			p.functions[p.Find("test/internal/multiformats.EncodeMultibase")].node.Body = nil
		case "counter":
			state.counter.Rhs[0] = bad
		case "prefix":
			s.prefix.X = bad
		case "prefix-arg":
			s.prefix.X.(*ast.CallExpr).Args = nil
		case "builder":
			s.prefix.X.(*ast.CallExpr).Fun = bad
		case "builder-method":
			s.prefix.X.(*ast.CallExpr).Fun.(*ast.SelectorExpr).Sel = bad
		case "repeat":
			s.prefix.X.(*ast.CallExpr).Args[0] = bad
		case "repeat-fun":
			s.prefix.X.(*ast.CallExpr).Args[0].(*ast.CallExpr).Fun = bad
		case "repeat-slice":
			s.prefix.X.(*ast.CallExpr).Args[0].(*ast.CallExpr).Args[0] = bad
		case "repeat-bound":
			s.prefix.X.(*ast.CallExpr).Args[0].(*ast.CallExpr).Args[0].(*ast.SliceExpr).High = bad
		case "repeat-count":
			s.prefix.X.(*ast.CallExpr).Args[0].(*ast.CallExpr).Args[1] = bad
		case "suffix-cond":
			s.suffix.Cond = bad
		case "suffix-post":
			s.suffix.Post = &ast.EmptyStmt{}
		case "suffix-body":
			s.suffix.Body.List[0] = &ast.EmptyStmt{}
		case "suffix-write":
			s.suffix.Body.List[0].(*ast.ExprStmt).X = bad
		case "suffix-builder":
			s.suffix.Body.List[0].(*ast.ExprStmt).X.(*ast.CallExpr).Fun = bad
		case "suffix-symbol":
			s.suffix.Body.List[0].(*ast.ExprStmt).X.(*ast.CallExpr).Args[0] = bad
		case "suffix-cell":
			s.suffix.Body.List[0].(*ast.ExprStmt).X.(*ast.CallExpr).Args[0].(*ast.IndexExpr).Index = bad
		case "suffix-operand":
			s.suffix.Cond.(*ast.BinaryExpr).X = bad
		case "return":
			s.result.Results[0] = bad
		case "return-builder":
			s.result.Results[0].(*ast.CallExpr).Fun = bad
		case "scan-start":
			s.position.Rhs[0] = bad
		case "scan-cond":
			s.scan.Cond = bad
		case "scan-guard":
			s.scan.Cond.(*ast.BinaryExpr).X = bad
		case "scan-post":
			s.scan.Body.List[0] = &ast.EmptyStmt{}
		case "scan-symbol":
			s.scan.Cond.(*ast.BinaryExpr).Y.(*ast.BinaryExpr).X = bad
		case "scan-operand":
			s.scan.Cond.(*ast.BinaryExpr).X.(*ast.BinaryExpr).X = bad
		case "allocation":
			s.allocation.Rhs[0] = bad
		case "allocation-args":
			s.allocation.Rhs[0].(*ast.CallExpr).Args = nil
		case "allocation-output":
			s.allocation.Tok = token.ASSIGN
		case "allocation-type":
			s.allocation.Rhs[0].(*ast.CallExpr).Fun = bad
		case "capacity":
			s.allocation.Rhs[0].(*ast.CallExpr).Args[2] = bad
		case "capacity-sum":
			s.allocation.Rhs[0].(*ast.CallExpr).Args[2].(*ast.BinaryExpr).X = bad
		case "capacity-operand":
			s.allocation.Rhs[0].(*ast.CallExpr).Args[2].(*ast.BinaryExpr).Y = bad
		case "growth-guard":
			s.suffix.Cond = bad
		case "growth-post":
			s.suffix.Post = &ast.EmptyStmt{}
		case "growth-store":
			s.suffix.Body.List[0] = &ast.EmptyStmt{}
		case "append":
			s.suffix.Body.List[0].(*ast.AssignStmt).Rhs[0] = bad
		case "append-builtin":
			s.suffix.Body.List[0].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Fun = bad
		case "convert":
			s.suffix.Body.List[0].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Args[1] = bad
		case "convert-cell":
			s.suffix.Body.List[0].(*ast.AssignStmt).Rhs[0].(*ast.CallExpr).Args[1].(*ast.CallExpr).Args[0] = bad
		case "final-return":
			s.result.Results[0] = bad
		}
		if a := p.OutputAudit("test/internal/multiformats." + name); len(a.Unknown) == 0 {
			t.Fatal(mode, a)
		}
	}
	p := control("", "")
	d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
	d.node.Name = &ast.Ident{Name: "func"}
	if outputFrame(p, d, true) != "" {
		t.Fatal("invalid frame")
	}
	d.node.Name = &ast.Ident{Name: "BaseEncode"}
	d.node.Body = nil
	if outputFrame(p, d, true) != "" {
		t.Fatal("missing frame body")
	}
}
func TestOutputLengthDomainUnavailableBindings(t *testing.T) {
	control := outputControls(t)
	for _, mode := range []string{"init", "start", "bound", "post", "inc", "counter", "initial-length", "missing-length"} {
		p := control("", "")
		d := p.functions[p.Find("test/internal/multiformats.BaseEncode")]
		state, _ := codecStateShape(d.node, true)
		length := bareLocal(d.unit.info, state.length.Lhs[0])
		cell := state.inner.Body.List[1].(*ast.AssignStmt).Lhs[0].(*ast.IndexExpr)
		size := allocatedSize(d, bareLocal(d.unit.info, cell.X))
		bad := &ast.Ident{Name: "unbound"}
		switch mode {
		case "init":
			state.inner.Init = &ast.EmptyStmt{}
		case "start":
			state.inner.Init.(*ast.AssignStmt).Rhs[0] = bad
		case "bound":
			state.inner.Cond.(*ast.BinaryExpr).Y = bad
		case "post":
			state.inner.Post = &ast.EmptyStmt{}
		case "inc":
			state.inner.Body.List[3] = &ast.EmptyStmt{}
		case "counter":
			state.counter.Rhs[0] = bad
		case "initial-length":
			for _, stmt := range d.node.Body.List {
				if a, ok := stmt.(*ast.AssignStmt); ok && definedLocal(d.unit.info, a) == length {
					a.Rhs[0] = bad
				}
			}
		case "missing-length":
			length = types.NewVar(token.NoPos, nil, "unknown", types.Typ[types.Int])
		}
		if outputLengthDomain(d, state, size, length) {
			t.Fatal(mode)
		}
	}
}

func TestOutputEquivalentGuardsOnBoundedDomain(t *testing.T) {
	control := outputControls(t)
	for _, tc := range []struct{ old, replacement, root string }{
		{"for ; pos < size; pos++", "for ; pos != size; pos++", "BaseEncode"},
		{"pos < size && decoded[pos] == 0", "pos != size && decoded[pos] == 0", "BaseDecode"},
	} {
		a := control(tc.old, tc.replacement).OutputAudit("test/internal/multiformats." + tc.root)
		base := control("", "").OutputAudit(a.Root)
		if len(a.Unknown) != 0 || a.Frame != base.Frame {
			t.Fatal(tc, a)
		}
		for _, step := range a.Steps {
			if !step.Correct {
				t.Fatal("equivalent guard failed", tc, a)
			}
		}
	}
	for _, size := range []int{0, 1, 8} {
		for start := 0; start <= size; start++ {
			for pos := start; pos <= size; pos++ {
				if (pos < size) != (pos != size) {
					t.Fatal(size, start, pos)
				}
			}
		}
	}
}
