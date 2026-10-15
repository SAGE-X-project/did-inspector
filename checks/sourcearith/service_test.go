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

func serviceControls(t *testing.T) func(string, string, string) *Program {
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
	return func(file, old, replacement string) *Program {
		input := map[string][]byte{}
		for k, v := range source {
			input[k] = v
		}
		if old != "" {
			s := string(input[file])
			if !strings.Contains(s, old) {
				t.Fatal(old)
			}
			input[file] = []byte(strings.Replace(s, old, replacement, 1))
		}
		p := NewProgram(t.Context(), "github.com/sage-x-project/did-go", input)
		p.standard = standard
		if _, e := p.Import(p.module + "/dereferencer"); e != nil {
			t.Fatal(e)
		}
		return p
	}
}
func TestServiceTypedGuardRoles(t *testing.T) {
	c := serviceControls(t)
	a := c("", "", "").ServiceAudit()
	if len(a.Unknown) != 0 || len(a.Steps) != 4 {
		t.Fatal(a)
	}
	for _, s := range a.Steps {
		if !s.Correct {
			t.Fatal(a)
		}
	}
	b, _ := json.Marshal(a)
	t.Log(string(b))
	for _, tc := range []struct {
		file, old, replacement string
		bad                    int
	}{
		{"dereferencer/dereferencer.go", `case hasService || hasType:`, `case hasService && hasType:`, 0},
		{"dereferencer/service.go", `if _, ok := params.Get(did.ParamRelativeRef); !ok {`, `if _, ok := params.Get(did.ParamRelativeRef); ok {`, 1},
		{"dereferencer/service.go", `base, err := url.Parse(u)`, `base, err := url.Parse(u+"")`, -1},
		{"dereferencer/service.go", `ref, err := url.Parse(params.RelativeRef)`, `ref, err := url.Parse(params.Service)`, 3},
	} {
		a := c(tc.file, tc.old, tc.replacement).ServiceAudit()
		if tc.bad < 0 {
			if len(a.Unknown) == 0 {
				t.Fatal("unsupported operand")
			}
			continue
		}
		if len(a.Unknown) != 0 {
			t.Fatal(a)
		}
		for i, s := range a.Steps {
			if s.Correct == (i == tc.bad) {
				t.Fatal(i, a)
			}
		}
	}
	if a := NewProgram(t.Context(), "other", nil).ServiceAudit(); len(a.Unknown) == 0 {
		t.Fatal(a)
	}
}

// These controls are parsed and type-checked only. No altered subject is run.
func TestServiceEquivalentKeysAndUnreviewedSource(t *testing.T) {
	c := serviceControls(t)
	for _, guard := range []string{"hasType || hasService", "hasService || hasType"} {
		p := c("dereferencer/dereferencer.go", "case hasService || hasType:", "case "+guard+":")
		f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).resource")
		d := p.functions[f]
		shape, _ := serviceShape(d.node)
		left, _ := assignedCall(shape.first)
		right, _ := assignedCall(shape.second)
		left.Args[0], right.Args[0] = right.Args[0], left.Args[0]
		a := p.ServiceAudit()
		if len(a.Unknown) != 0 || !a.Steps[0].Correct {
			t.Fatal(a)
		}
	}
	cases := []struct{ file, old, replacement string }{
		{"dereferencer/dereferencer.go", "case hasService || hasType:", "case hasService == hasType:"},
		{"dereferencer/service.go", "if _, ok := params.Get(did.ParamRelativeRef); !ok {", "if _, ok := params.Get(did.ParamRelativeRef); ok == false {"},
		{"dereferencer/service.go", "base.ResolveReference(ref)", "ref.ResolveReference(base)"},
		{"dereferencer/service.go", "urls = append(urls, e.URL)", `urls = append(urls, e.URL+"")`},
		{"dereferencer/service.go", "endpointURLs(selected, params)", "endpointURLs(append([]vm.Service{},selected...), params)"},
	}
	for _, tc := range cases {
		if a := c(tc.file, tc.old, tc.replacement).ServiceAudit(); len(a.Unknown) == 0 {
			t.Fatal(tc, a)
		}
	}
	// Malformed or unsupported shapes must fail closed without panicking.
	for _, mutate := range []func(*Program){
		func(p *Program) { delete(p.functions, p.Find(p.module+"/dereferencer.endpointURLs")) },
		func(p *Program) {
			f := p.Find(p.module + "/dereferencer.endpointURLs")
			p.functions[f].node.Body.List = nil
		},
		func(p *Program) {
			f := p.Find(p.module + "/dereferencer.endpointURLs")
			p.functions[f].node.Body.List[2].(*ast.IfStmt).Init = nil
		},
		func(p *Program) {
			f := p.Find(p.module + "/dereferencer.endpointURLs")
			p.functions[f].node.Body.List[2].(*ast.IfStmt).Cond = &ast.UnaryExpr{Op: token.ADD, X: ast.NewIdent("ok")}
		},
		func(p *Program) {
			f := p.Find(p.module + "/dereferencer.endpointURLs")
			p.functions[f].node.Body.List[3].(*ast.AssignStmt).Rhs = nil
		},
		func(p *Program) {
			f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).services")
			p.functions[f].node.Body.List = nil
		},
		func(p *Program) {
			f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).resource")
			shape, _ := serviceShape(p.functions[f].node)
			shape.first.Rhs = nil
		},
	} {
		p := c("", "", "")
		mutate(p)
		if a := p.ServiceAudit(); len(a.Unknown) == 0 {
			t.Fatal(a)
		}
	}
	p := c("", "", "")
	if p.serviceArgument("missing", "missing") {
		t.Fatal("missing caller")
	}
	f := p.Find(p.module + "/dereferencer.endpointURLs")
	d := p.functions[f]
	if serviceFrame(p, function{node: &ast.FuncDecl{Name: ast.NewIdent("f"), Type: &ast.FuncType{Params: &ast.FieldList{}}}}, true) != "" {
		t.Fatal("bad frame")
	}
	for _, endpoint := range []bool{false, true} {
		if serviceFrame(p, d, endpoint) == "" && endpoint {
			t.Fatal("valid frame")
		}
	}
	if _, ok := assignedCall(nil); ok {
		t.Fatal("nil assignment")
	}
}

func TestServiceFrameRejectsIncompleteCalls(t *testing.T) {
	p := serviceControls(t)("", "", "")
	for _, tc := range []struct {
		src      string
		endpoint bool
	}{
		{`func f(){var urls []string;for{};if true{};ref,err:=url.Parse(x);if err!=nil{};out:=urls;for _,u:=range urls{base,err:=url.Parse(u);if err!=nil{};out=append(out,base.ResolveReference(ref).String())};return out,nil}`, true},
		{`func f(){var urls []string;for{};if _,ok:=f();!ok{};ref,err:=url.Parse(x);if err!=nil{};out:=urls;for _,u:=range urls{base,err:=url.Parse(u);if err!=nil{};out=append(out,base.ResolveReference(ref).String())};return out,nil}`, true},
		{`func f(){a:=f();b,c:=g(x);switch{case a:return x;case b:return y};for{};return nil}`, false},
	} {
		parsed, e := parser.ParseFile(token.NewFileSet(), "control.go", "package control;"+tc.src, 0)
		if e != nil {
			t.Fatal(e)
		}
		if serviceFrame(p, function{node: parsed.Decls[0].(*ast.FuncDecl)}, tc.endpoint) != "" {
			t.Fatal("unreviewed frame accepted")
		}
	}
	f := p.Find(p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).resource")
	d := p.functions[f]
	shape, _ := serviceShape(d.node)
	if _, _, ok := parseArgument(d.unit.info, shape.first); ok {
		t.Fatal("parameter getter is not URL parser")
	}
}
