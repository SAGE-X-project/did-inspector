package sourcearith

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

func copiedExpansionControls(t *testing.T) func(string, string) *Program {
	t.Helper()
	original := expansionControls(t)("", "", "")
	source := map[string][]byte{}
	for name, b := range original.source {
		source[name] = b
	}
	for name, file := range map[string]string{"resolver/resolver.go": "testdata/expansion-copy-resolver.go.txt", "resolver/expand.go": "testdata/expansion-copy-map.go.txt"} {
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		source[name] = b
	}
	standard := importer.ForCompiler(token.NewFileSet(), "source", nil)
	return func(old, next string) *Program {
		input := map[string][]byte{}
		for name, b := range source {
			input[name] = b
		}
		if old != "" {
			s := string(input["resolver/resolver.go"])
			if !strings.Contains(s, old) {
				t.Fatal(old)
			}
			input["resolver/resolver.go"] = []byte(strings.Replace(s, old, next, 1))
		}
		p := NewProgram(t.Context(), original.module, input)
		p.standard = standard
		if _, e := p.Import(p.module + "/resolver"); e != nil {
			t.Fatal(e)
		}
		return p
	}
}

func TestExpansionCopiedOptionsBindings(t *testing.T) {
	c := copiedExpansionControls(t)
	p := c("", "")
	a := p.ExpansionAuditForCopiedOptions()
	if len(a.Unknown) != 0 || len(a.Steps) != 2 || !a.Steps[0].Correct || !a.Steps[1].Correct || a.Roles["copied_options"] != "documentOptions github.com/sage-x-project/did-go/resolution.ResolutionOptions" {
		t.Fatal(a.Unknown, a.Roles)
	}
	if len(p.ExpansionAudit().Unknown) == 0 {
		t.Fatal("old direct-options contract was weakened")
	}
	old := expansionControls(t)("", "", "")
	if len(old.ExpansionAuditForCopiedOptions().Unknown) == 0 {
		t.Fatal("unreviewed layout accepted")
	}
}

// These edits are parser/type-checker inputs only, never compiled or executed.
func TestExpansionCopiedOptionsRefusals(t *testing.T) {
	c := copiedExpansionControls(t)
	for _, tt := range [][2]string{
		{"return resolution.Result{DocumentMetadata: rr.Metadata.Clone()}", "opts.ExpandRelativeURLs = false; return resolution.Result{DocumentMetadata: rr.Metadata.Clone()}"},
		{"if e := opts.Validate(); e != nil {\n\t\treturn resolution.ErrorResult(e)\n\t}", "opts.ExpandRelativeURLs = false"},
		{"documentOptions := opts", "documentOptions := opts; opts.ExpandRelativeURLs = false"},
		{"documentOptions.Accept = \"\"", "opts.ExpandRelativeURLs = false"},
		{"documentOptions := opts", "documentOptions := resolution.ResolutionOptions{}"},
		{"return r.output(d, rr, documentOptions)", "return r.output(d, rr, opts)"},
		{"if r.intermediateDocument {", "if !r.intermediateDocument {"},
		{"resolution.Negotiate(opts.Accept, representation.CoreMediaTypes())", "resolution.Negotiate(documentOptions.Accept, representation.CoreMediaTypes())"},
		{"if _, ok := resolution.Negotiate(opts.Accept, representation.CoreMediaTypes()); !ok {", "if _, ok := resolution.Negotiate(opts.Accept, representation.CoreMediaTypes()); ok {"},
		{"documentOptions.Accept = \"\"", "documentOptions.Accept = \"application/did\""},
		{"documentOptions.Accept = \"\"", "documentOptions.ExpandRelativeURLs = true"},
		{"documentOptions.Accept = \"\"", "documentOptions.Extra[\"unit-marker\"] = true"},
		{"documentOptions.Accept = \"\"", "*documentOptions.VersionTime = *opts.VersionTime"},
		{"documentOptions.Accept = \"\"", "func() { documentOptions.Accept = \"\" }()"},
		{"rr, e := read(ctx, m, d, documentOptions)", "rr, e := read(ctx, m, d, opts)"},
		{"documentOptions := opts", "documentOptions := *(&opts)"},
		{"documentOptions := opts", "documentOptions := opts; _ = &documentOptions"},
	} {
		p := c(tt[0], tt[1])
		if len(p.ExpansionAuditForCopiedOptions().Unknown) == 0 {
			t.Fatal("unreviewed copy accepted", tt)
		}
	}
}

func replaceCopyNode[T any](target *T, next T) func() {
	old := *target
	*target = next
	return func() { *target = old }
}

// Unsupported parser shapes are analysis data too. No altered code is run.
func TestExpansionCopiedOptionsShapes(t *testing.T) {
	p := copiedExpansionControls(t)("", "")
	f := p.Find(p.module + "/resolver.(*" + p.module + "/resolver.DefaultResolver).Resolve")
	entry := p.functions[f]
	sig := f.Type().(*types.Signature)
	body := entry.node.Body
	init := body.List[5].(*ast.AssignStmt)
	local := init.Lhs[0].(*ast.Ident)
	outer := body.List[6].(*ast.IfStmt)
	inner := outer.Body.List[0].(*ast.IfStmt)
	neg := inner.Init.(*ast.AssignStmt)
	flag := neg.Lhs[1].(*ast.Ident)
	negotiate := neg.Rhs[0].(*ast.CallExpr)
	offers := negotiate.Args[1].(*ast.CallExpr)
	condition := inner.Cond.(*ast.UnaryExpr)
	accept := inner.Body.List[0].(*ast.AssignStmt)
	read := body.List[7].(*ast.AssignStmt)
	call := read.Rhs[0].(*ast.CallExpr)
	supported := body.List[3].(*ast.IfStmt)
	validate := body.List[4].(*ast.IfStmt)
	supportedInit := supported.Init.(*ast.AssignStmt)
	validateInit := validate.Init.(*ast.AssignStmt)
	supportedCall := supportedInit.Rhs[0].(*ast.CallExpr)
	validateCall := validateInit.Rhs[0].(*ast.CallExpr)
	ret := body.List[len(body.List)-1].(*ast.ReturnStmt)
	argument := ret.Results[0].(*ast.CallExpr).Args[2]
	for name, alter := range map[string]func() func(){
		"supported shape":     func() func() { return replaceCopyNode(&body.List[3], ast.Stmt(&ast.EmptyStmt{})) },
		"validate shape":      func() func() { return replaceCopyNode(&body.List[4], ast.Stmt(&ast.EmptyStmt{})) },
		"supported binding":   func() func() { return replaceCopyNode(&supported.Init, ast.Stmt(&ast.EmptyStmt{})) },
		"validate binding":    func() func() { return replaceCopyNode(&validate.Init, ast.Stmt(&ast.EmptyStmt{})) },
		"supported call":      func() func() { return replaceCopyNode(&supportedInit.Rhs[0], ast.Expr(ast.NewIdent("other"))) },
		"validate call":       func() func() { return replaceCopyNode(&validateInit.Rhs[0], ast.Expr(ast.NewIdent("other"))) },
		"supported argument":  func() func() { return replaceCopyNode(&supportedCall.Args, []ast.Expr(nil)) },
		"validate argument":   func() func() { return replaceCopyNode(&validateCall.Args, []ast.Expr{ast.NewIdent("other")}) },
		"missing body":        func() func() { return replaceCopyNode(&entry.node.Body, (*ast.BlockStmt)(nil)) },
		"wrong length":        func() func() { return replaceCopyNode(&body.List, body.List[:11]) },
		"copy declaration":    func() func() { return replaceCopyNode(&body.List[5], ast.Stmt(&ast.EmptyStmt{})) },
		"copy token":          func() func() { return replaceCopyNode(&init.Tok, token.ASSIGN) },
		"copy left shape":     func() func() { return replaceCopyNode(&init.Lhs[0], ast.Expr(&ast.ParenExpr{X: local})) },
		"missing copy object": func() func() { return replaceCopyNodeMap(entry.unit.info.Defs, local, nil) },
		"missing outer":       func() func() { return replaceCopyNode(&body.List[6], ast.Stmt(&ast.EmptyStmt{})) },
		"outer extra branch":  func() func() { return replaceCopyNode(&outer.Else, ast.Stmt(&ast.EmptyStmt{})) },
		"missing inner":       func() func() { return replaceCopyNode(&outer.Body.List[0], ast.Stmt(&ast.EmptyStmt{})) },
		"inner extra branch":  func() func() { return replaceCopyNode(&inner.Else, ast.Stmt(&ast.EmptyStmt{})) },
		"missing negotiation": func() func() { return replaceCopyNode(&inner.Init, ast.Stmt(&ast.EmptyStmt{})) },
		"negotiation arity":   func() func() { return replaceCopyNode(&neg.Lhs, neg.Lhs[:1]) },
		"blank shape": func() func() {
			return replaceCopyNode(&neg.Lhs[0], ast.Expr(&ast.BasicLit{Kind: token.INT, Value: "0"}))
		},
		"blank name":         func() func() { return replaceCopyNode(&neg.Lhs[0], ast.Expr(ast.NewIdent("other"))) },
		"flag binding":       func() func() { return replaceCopyNodeMap(entry.unit.info.Defs, flag, nil) },
		"negotiate shape":    func() func() { return replaceCopyNode(&neg.Rhs[0], ast.Expr(ast.NewIdent("other"))) },
		"negotiate arity":    func() func() { return replaceCopyNode(&negotiate.Args, negotiate.Args[:1]) },
		"offers shape":       func() func() { return replaceCopyNode(&negotiate.Args[1], ast.Expr(ast.NewIdent("other"))) },
		"offers arity":       func() func() { return replaceCopyNode(&offers.Args, []ast.Expr{ast.NewIdent("other")}) },
		"condition shape":    func() func() { return replaceCopyNode(&inner.Cond, condition.X) },
		"condition binding":  func() func() { return replaceCopyNode(&condition.X, ast.Expr(ast.NewIdent("other"))) },
		"accept shape":       func() func() { return replaceCopyNode(&inner.Body.List[0], ast.Stmt(&ast.EmptyStmt{})) },
		"accept arity":       func() func() { return replaceCopyNode(&accept.Rhs, []ast.Expr(nil)) },
		"accept nonconstant": func() func() { return replaceCopyNode(&accept.Rhs[0], ast.Expr(ast.NewIdent("other"))) },
		"accept wrong constant": func() func() {
			x := &ast.BasicLit{Kind: token.INT, Value: "0"}
			entry.unit.info.Types[x] = types.TypeAndValue{Value: constant.MakeInt64(0)}
			undo := replaceCopyNode(&accept.Rhs[0], ast.Expr(x))
			return func() { undo(); delete(entry.unit.info.Types, x) }
		},
		"read shape":      func() func() { return replaceCopyNode(&body.List[7], ast.Stmt(&ast.EmptyStmt{})) },
		"read assignment": func() func() { return replaceCopyNode(&read.Rhs, []ast.Expr(nil)) },
		"read call":       func() func() { return replaceCopyNode(&read.Rhs[0], ast.Expr(ast.NewIdent("other"))) },
		"read arity":      func() func() { return replaceCopyNode(&call.Args, call.Args[:3]) },
		"extra local use": func() func() {
			id := ast.NewIdent(local.Name)
			entry.unit.info.Uses[id] = entry.unit.info.Defs[local]
			undo := replaceCopyNode(&body.List[0], ast.Stmt(&ast.ExprStmt{X: id}))
			return func() { undo(); delete(entry.unit.info.Uses, id) }
		},
	} {
		t.Run(name, func(t *testing.T) {
			undo := alter()
			defer undo()
			if _, ok := copiedExpansionOptions(entry, sig, argument, p.module); ok {
				t.Fatal("unsupported source shape accepted")
			}
		})
	}
	if _, ok := copiedExpansionOptions(entry, sig, argument, p.module); !ok {
		t.Fatal("shape controls did not restore source")
	}
}

func replaceCopyNodeMap(m map[*ast.Ident]types.Object, key *ast.Ident, next types.Object) func() {
	old := m[key]
	m[key] = next
	return func() { m[key] = old }
}
