package sourcearith

import (
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func fragmentControls(t *testing.T) func(string, string) *Program {
	t.Helper()
	b, e := os.ReadFile("testdata/did-go-pinned.zip")
	if e != nil {
		t.Fatal(e)
	}
	files, _, e := ArchiveFiles(b, "github.com/sage-x-project/did-go@v0.0.0-20261012015322-ed54c505eafe")
	if e != nil {
		t.Fatal(e)
	}
	source := SourceFiles(files, []string{"dereferencer", "did", "document", "internal/multiformats", "representation", "resolution", "spec", "vm"})
	standard := importer.ForCompiler(token.NewFileSet(), "source", nil)
	return func(old, replacement string) *Program {
		t.Helper()
		input := map[string][]byte{}
		for k, v := range source {
			input[k] = v
		}
		if old != "" {
			s := string(input["dereferencer/fragment.go"])
			if !strings.Contains(s, old) {
				t.Fatal("missing control", old)
			}
			input["dereferencer/fragment.go"] = []byte(strings.Replace(s, old, replacement, 1))
		}
		p := NewProgram(t.Context(), "github.com/sage-x-project/did-go", input)
		p.standard = standard
		if _, e := p.Import("github.com/sage-x-project/did-go/dereferencer"); e != nil {
			t.Fatal(e)
		}
		return p
	}
}

func TestFragmentSourceBindings(t *testing.T) {
	control := fragmentControls(t)
	root := "github.com/sage-x-project/did-go/dereferencer.resolveFragment"
	good := control("", "").FragmentAudit(root)
	if len(good.Unknown) != 0 || len(good.Steps) != 3 || len(good.Roles) != 4 || len(good.Frames) < 10 {
		t.Fatal(good)
	}
	for _, s := range good.Steps {
		if !s.Correct {
			t.Fatal(good)
		}
	}
	b, _ := json.Marshal(good)
	t.Log(string(b))
	for _, tc := range []struct {
		old, replacement string
		bad              []int
	}{
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().Method()+"#"+frag, "#"+frag`, []int{0, 1}},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String()+"?"+frag, "#"+frag`, []int{1}},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String()+"#"+docType, "#"+frag`, []int{1}},
		{`ContentStream:         found,`, `ContentStream:         []any{found},`, []int{2}},
	} {
		a := control(tc.old, tc.replacement).FragmentAudit(root)
		if len(a.Unknown) != 0 || len(a.Steps) != 3 || a.Frames[root] != good.Frames[root] {
			t.Fatal(a)
		}
		for i, s := range a.Steps {
			bad := false
			for _, j := range tc.bad {
				bad = bad || i == j
			}
			if s.Correct == bad {
				t.Fatal(tc, i, a)
			}
		}
	}
}

func TestFragmentUnsupportedSourceAndContext(t *testing.T) {
	control := fragmentControls(t)
	root := "github.com/sage-x-project/did-go/dereferencer.resolveFragment"
	p := control("", "")
	for _, r := range []string{"other", root + "Missing"} {
		if len(p.FragmentAudit(r).Unknown) == 0 {
			t.Fatal(r)
		}
	}
	missing := NewProgram(t.Context(), "github.com/sage-x-project/did-go", nil)
	if len(missing.FragmentAudit(root).Unknown) == 0 {
		t.Fatal("missing source")
	}
	for _, tc := range [][2]string{
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String()+"#"+(frag+""), "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String()+"#"+string(frag), "#"+frag`},
		{`ContentStream:         found,`, `ContentStream:         (func() any {return found})(),`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().URL().String()+"#"+frag, "#"+frag`},
		{`func resolveFragment(doc *document.Document, frag, docType string)`, `func resolveFragment(doc *document.Document, frag, docType string, extra ...string)`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := (func() string {return doc.ID().String()})()+"#"+frag, "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := (did.DID{}).String()+"#"+frag, "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := (func() did.DID {return doc.ID()})().String()+"#"+frag, "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String(), "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String()+frag, "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := "fixed"+"#"+frag, "#"+frag`},
		{`full, short := doc.ID().String()+"#"+frag, "#"+frag`, `full, short := doc.ID().String()+string([]byte{35})+frag, "#"+frag`},
	} {
		if a := control(tc[0], tc[1]).FragmentAudit(root); len(a.Unknown) == 0 {
			t.Fatal(tc, a)
		}
	}
	good := p.FragmentAudit(root)
	changed := control(`if !ok {`, `if ok {`).FragmentAudit(root)
	if len(changed.Unknown) != 0 || changed.Frames[root] == good.Frames[root] {
		t.Fatal("unreviewed miss control not retained", changed)
	}
	fn := p.functions[p.Find(root)].node
	start, found, payload, ok := fragmentShape(fn)
	if !ok || start == nil || found == nil || payload == nil {
		t.Fatal("shape")
	}
}

// Unsupported layouts and incomplete analysis metadata must not produce
// binding evidence. These parser/AST controls are data and never executed.
func TestFragmentMalformedLayoutAndMissingMetadata(t *testing.T) {
	for _, source := range []string{
		"func f()",
		"func f(){a();b();c();d();return}",
		"func f(){full,short:=1,2;b();found,ok:=1,2;d();return x}",
		"func f(){full,short:=1,2;b();found,ok:=g();d();return found}",
		"func f(){full,short:=1,2;b();found,ok:=g();d();return struct{X any}{found}}",
		"func f(){full,short:=1,2;b();found,ok:=g();d();return struct{X any}{X:found}}",
	} {
		file, e := parser.ParseFile(token.NewFileSet(), "data.go", "package data\n"+source, 0)
		if e != nil {
			t.Fatal(e)
		}
		fn := file.Decls[0].(*ast.FuncDecl)
		if _, _, _, ok := fragmentShape(fn); ok {
			t.Fatal("unknown layout accepted", source)
		}
		if frame := fragmentFrame(NewProgram(t.Context(), "data", nil), function{node: fn}); frame != "" {
			t.Fatal("unknown frame", frame)
		}
	}
	p := fragmentControls(t)("", "")
	root := "github.com/sage-x-project/did-go/dereferencer.resolveFragment"
	d := p.functions[p.Find(root)]
	fn := d.node
	old := fn.Name.Name
	fn.Name.Name = "invalid{"
	if fragmentFrame(p, d) != "" {
		t.Fatal("invalid syntax frame")
	}
	fn.Name.Name = old
	start, _, _, _ := fragmentShape(fn)
	id := start.Lhs[0].(*ast.Ident)
	obj := d.unit.info.Defs[id]
	delete(d.unit.info.Defs, id)
	if len(p.FragmentAudit(root).Unknown) == 0 {
		t.Fatal("missing local identity")
	}
	d.unit.info.Defs[id] = obj
	callee := p.Find("github.com/sage-x-project/did-go/dereferencer.findFragment")
	delete(p.functions, callee)
	if len(p.FragmentAudit(root).Unknown) == 0 {
		t.Fatal("missing actual call edge")
	}
}
