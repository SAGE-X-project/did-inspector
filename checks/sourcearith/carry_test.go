package sourcearith

import (
	"encoding/json"
	"go/ast"
	"os"
	"strings"
	"testing"
)

func carryControl(t *testing.T, old, replacement string) *Program {
	t.Helper()
	z, e := os.ReadFile("testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	files, _, e := ArchiveFiles(z, "github.com/sage-x-project/did-go@v0.0.0-20261012015322-ed54c505eafe")
	if e != nil {
		t.Fatal(e)
	}
	files = SourceFiles(files, []string{"internal/multiformats"})
	if old != "" {
		source := string(files["internal/multiformats/base.go"])
		if !strings.Contains(source, old) {
			t.Fatal("missing control")
		}
		files["internal/multiformats/base.go"] = []byte(strings.Replace(source, old, replacement, 1))
	}
	p := NewProgram(t.Context(), "test", files)
	if _, e := p.Import("test/internal/multiformats"); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestCarryArithmeticSourceBindings(t *testing.T) {
	p := carryControl(t, "", "")
	for _, name := range []string{"BaseEncode", "BaseDecode"} {
		a := p.CarryAudit("test/internal/multiformats." + name)
		if a.Frame == "" || len(a.Unknown) != 0 || len(a.Steps) != 3 || a.Base != "base" || a.Carry != "carry" || a.Index != "pos" {
			t.Fatal(a)
		}
		for _, s := range a.Steps {
			if !s.Correct || !s.Operation.Integer || s.Expression == "" {
				t.Fatal(a)
			}
		}
		b, _ := json.Marshal(a)
		t.Log(string(b))
	}
	// No AST mutation of the audited source is used to construct a frame.
	if a := p.IntegerAudit("test/internal/multiformats.BaseEncode"); !allInteger(a) || len(a.Operations) != 33 {
		t.Fatal(a)
	}
}
func TestCarryWrongArithmeticIsNotAccepted(t *testing.T) {
	for _, tt := range []struct {
		old, replacement, root string
		bad                    int
	}{
		{"carry += 256 * digits[pos]", "carry -= 256 * digits[pos]", "BaseEncode", 0},
		{"carry += 256 * digits[pos]", "carry += 255 * digits[pos]", "BaseEncode", 0},
		{"digits[pos] = carry % base", "digits[pos] = carry / base", "BaseEncode", 1},
		{"carry /= base", "carry *= base", "BaseEncode", 2},
		{"decoded[pos] = carry % 256", "decoded[pos] = carry % 255", "BaseDecode", 1},
		{"carry /= 256", "carry /= 255", "BaseDecode", 2},
	} {
		p := carryControl(t, tt.old, tt.replacement)
		a := p.CarryAudit("test/internal/multiformats." + tt.root)
		if len(a.Unknown) != 0 || len(a.Steps) != 3 || a.Steps[tt.bad].Correct {
			t.Fatal(tt, a)
		}
	}
}
func TestUnsupportedCarryShapesAndContext(t *testing.T) {
	baseline := carryControl(t, "", "").CarryAudit("test/internal/multiformats.BaseEncode").Frame
	for _, tt := range []struct{ old, replacement, root string }{
		{"carry += 256 * digits[pos]", "carry += 256 * digits[pos+1]", "BaseEncode"},
		{"carry /= base", "carry /= size", "BaseEncode"},
		{"carry += 256 * digits[pos]", "carry += base * digits[pos]", "BaseEncode"},
		{"carry += base * decoded[pos]", "carry += size * decoded[pos]", "BaseDecode"},
		{"carry /= 256", "carry /= base", "BaseDecode"},
		{"carry += 256 * digits[pos]", "carry = carry", "BaseEncode"},
		{"digits[pos] = carry % base", "digits[pos] = carry", "BaseEncode"},
		{"for pos := size - 1;", "for pos, unused := size - 1, 0;", "BaseEncode"},
		{"i++\n\t\t}", "i++;carry++\n\t\t}", "BaseEncode"},
	} {
		// Keep the multi-variable control valid Go by using its second variable.
		replacement := tt.replacement
		if strings.Contains(replacement, "unused") {
			replacement = "for pos, _ := size - 1, 0;"
		}
		a := carryControl(t, tt.old, replacement).CarryAudit("test/internal/multiformats." + tt.root)
		if len(a.Unknown) == 0 {
			t.Fatal("unsupported shape accepted", tt, a)
		}
	}
	// A changed surrounding function is outside the reviewed context, even if
	// its three equations still look right. The profile must reject the frame.
	for _, extra := range []string{"base++", "base = 58", "_ = &base"} {
		a := carryControl(t, "base := len(alphabet)", "base := len(alphabet);"+extra).CarryAudit("test/internal/multiformats.BaseEncode")
		if a.Frame == baseline {
			t.Fatal("context change concealed", extra)
		}
	}
	p := carryControl(t, "", "")
	for _, root := range []string{"other", "test/internal/multiformats.Missing"} {
		a := p.CarryAudit(root)
		if len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
	f := p.Find("test/internal/multiformats.BaseEncode")
	d := p.functions[f]
	d.node.Name = &ast.Ident{Name: "func"}
	if recurrenceFrame(p, d) != "" {
		t.Fatal("malformed frame accepted")
	}
}

func TestMissingBaseBindingAndRecurrenceEvidence(t *testing.T) {
	for _, source := range []string{
		`package alg;func Root()int{return 0}`,
		`package alg;func Root(a []byte,b string)int{var base int;return base}`,
		`package alg;var base int;func Root(a []byte,b string)int{base=len(b);return base}`,
		`package alg;func Root(a []byte,b string)int{base,other:=len(b),0;return base+other}`,
		`package alg;func Root(a []byte,b string)int{base:=1;return base}`,
		`package alg;func Root(a []byte,b string)int{base:=cap(a);return base}`,
		`package alg;func Root(a []byte,b string)int{base:=len(a);return base}`,
		`package alg;func length()int{return 1};func Root(a []byte,b string)int{base:=length();return base}`,
		`package alg;func length(a string)int{return len(a)};func Root(a []byte,b string)int{base:=length(b);return base}`,
		`package alg;func Root(a []byte,b,c string)int{base:=len(b);return base}`,
	} {
		p := checked(t, source)
		d := p.functions[p.Find("test/alg.Root")]
		if baseObject(d) != nil {
			t.Fatal("unbound base accepted", source)
		}
	}
	p := NewProgram(t.Context(), "test", nil)
	if a := p.CarryAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) == 0 {
		t.Fatal(a)
	}
	p = NewProgram(t.Context(), "test", map[string][]byte{"internal/multiformats/a.go": []byte(`package multiformats;func BaseEncode(a []byte,b string)(string,error)`)})
	if _, e := p.Import("test/internal/multiformats"); e != nil {
		t.Fatal(e)
	}
	if a := p.CarryAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) == 0 {
		t.Fatal(a)
	}
	for _, tt := range []struct{ old, replacement string }{
		{"carry += 256 * digits[pos]", "carry, length = carry, length"},
		{"digits[pos] = carry % base", "length = carry % base"},
		{"carry /= base", "_ = carry/base"},
		{"carry /= base", "i++"},
		{"digits := make([]int, size)", "digits = make([]int, size)"},
	} {
		var p *Program
		if tt.old == "digits := make([]int, size)" {
			p = carryControl(t, "", "")
			// Declaring a package buffer is data only; no initializer is executed.
			z := p.source["internal/multiformats/base.go"]
			z = []byte(strings.Replace(string(z), tt.old, tt.replacement, 1))
			z = []byte(strings.Replace(string(z), "var errEmptyAlphabet", "var digits []int\nvar errEmptyAlphabet", 1))
			files := p.source
			files["internal/multiformats/base.go"] = z
			p = NewProgram(t.Context(), "test", files)
			if _, e := p.Import("test/internal/multiformats"); e != nil {
				t.Fatal(e)
			}
		} else {
			p = carryControl(t, tt.old, tt.replacement)
		}
		if a := p.CarryAudit("test/internal/multiformats.BaseEncode"); len(a.Unknown) == 0 {
			t.Fatal(tt, a)
		}
	}
}

func TestCarryStorageCannotBeGlobalOrSharedField(t *testing.T) {
	for _, mode := range []string{"global-carry", "local-decoy", "shared-buffer-field", "different-carry-fields", "array-map"} {
		p := carryControl(t, "", "")
		files := p.source
		source := string(files["internal/multiformats/base.go"])
		switch mode {
		case "global-carry":
			source = strings.Replace(source, "var errEmptyAlphabet", "var gc int\nvar errEmptyAlphabet", 1)
			source = strings.Replace(source, "carry += 256 * digits[pos]", "gc += 256 * digits[pos]", 1)
			source = strings.Replace(source, "digits[pos] = carry % base", "digits[pos] = gc % base", 1)
			source = strings.Replace(source, "carry /= base", "gc /= base", 1)
		case "local-decoy":
			source = strings.Replace(source, "carry += 256 * digits[pos]", "i += 256 * digits[pos]", 1)
			source = strings.Replace(source, "digits[pos] = carry % base", "digits[pos] = i % base", 1)
			source = strings.Replace(source, "carry /= base", "i /= base", 1)
		case "shared-buffer-field":
			source = strings.Replace(source, "var errEmptyAlphabet", "type holder struct{buf []int};var left,right holder\nvar errEmptyAlphabet", 1)
			source = strings.Replace(source, "carry += 256 * digits[pos]", "carry += 256 * left.buf[pos]", 1)
			source = strings.Replace(source, "digits[pos] = carry % base", "right.buf[pos] = carry % base", 1)
		case "different-carry-fields":
			source = strings.Replace(source, "var errEmptyAlphabet", "type holder struct{carry int};var left,right holder\nvar errEmptyAlphabet", 1)
			source = strings.Replace(source, "carry += 256 * digits[pos]", "left.carry += 256 * digits[pos]", 1)
			source = strings.Replace(source, "digits[pos] = carry % base", "digits[pos] = right.carry % base", 1)
			source = strings.Replace(source, "carry /= base", "right.carry /= base", 1)
		case "array-map":
			source = strings.Replace(source, "carry += base * decoded[pos]", "carry += base * values[pos]", 1)
			source = strings.Replace(source, "decoded[pos] = carry % 256", "values[pos] = carry % 256", 1)
		}
		files["internal/multiformats/base.go"] = []byte(source)
		p = NewProgram(t.Context(), "test", files)
		if _, e := p.Import("test/internal/multiformats"); e != nil {
			t.Fatal(e)
		}
		root := "test/internal/multiformats.BaseEncode"
		if mode == "array-map" {
			root = "test/internal/multiformats.BaseDecode"
		}
		if a := p.CarryAudit(root); len(a.Unknown) == 0 {
			t.Fatal("storage substituted", mode, a)
		}
	}
}
