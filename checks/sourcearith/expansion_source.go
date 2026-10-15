package sourcearith

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
)

func expansionGuard(f *ast.FuncDecl) *ast.IfStmt {
	if f.Body == nil || len(f.Body.List) != 18 {
		return nil
	}
	g, _ := f.Body.List[4].(*ast.IfStmt)
	return g
}

// Only the independently judged option guard is masked. Reviewed traversal,
// consumer/output bindings and helper context remain explicit prerequisites.
func expansionFrame(p *Program, f function) string {
	set := token.NewFileSet()
	parsed, e := parser.ParseFile(set, "expansion.go", "package expansion\n"+sourceExpression(p, f.node), 0)
	if e != nil {
		return ""
	}
	fn := parsed.Decls[0].(*ast.FuncDecl)
	g := expansionGuard(fn)
	if g == nil {
		return ""
	}
	g.Cond = ast.NewIdent("_")
	var b bytes.Buffer
	if format.Node(&b, set, fn) != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

// ExpansionAudit distinguishes an option predicate from complete traversal.
// Typed Extra-field reads are required for method/service extension coverage;
// their absence in the reviewed closed helpers is corroborated by ordinary
// same-call consumer and resolver receipts, never inferred from an output alone.
func (p *Program) ExpansionAudit() ServiceAudit {
	output := p.module + "/resolver.(*" + p.module + "/resolver.DefaultResolver).output"
	a := ServiceAudit{Roots: []string{output, p.module + "/resolver.expand"}, Frames: map[string]string{}, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	of := p.Find(output)
	ef := p.Find(a.Roots[1])
	if of == nil || ef == nil {
		a.Unknown = append(a.Unknown, "missing expansion roots")
		return a
	}
	o := p.functions[of]
	g := expansionGuard(o.node)
	if g == nil {
		a.Unknown = append(a.Unknown, "unreviewed expansion output layout")
		return a
	}
	sig := of.Type().(*types.Signature)
	if sig.Params().Len() != 3 {
		a.Unknown = append(a.Unknown, "unbound output options")
		return a
	}
	expr := g.Cond
	positive := true
	if n, ok := expr.(*ast.UnaryExpr); ok && n.Op == token.NOT {
		positive = false
		expr = n.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || !fieldRole(o.unit.info, expr, sig.Params().At(2), "ExpandRelativeURLs") || sel.Sel.Name != "ExpandRelativeURLs" {
		a.Unknown = append(a.Unknown, "unreviewed expansion option predicate")
		return a
	}
	resolve := p.module + "/resolver.(*" + p.module + "/resolver.DefaultResolver).Resolve"
	rf := p.Find(resolve)
	if rf == nil {
		a.Unknown = append(a.Unknown, "missing Resolve entry")
		return a
	}
	entry := p.functions[rf]
	if entry.node.Body == nil || len(entry.node.Body.List) == 0 {
		a.Unknown = append(a.Unknown, "missing Resolve body")
		return a
	}
	ret, ok := entry.node.Body.List[len(entry.node.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		a.Unknown = append(a.Unknown, "unreviewed Resolve return")
		return a
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	rsig := rf.Type().(*types.Signature)
	if !ok || len(call.Args) != 3 || rsig.Params().Len() != 3 || selectionSymbol(entry.unit.info, call.Fun) != output || object(entry.unit.info, call.Args[2]) != rsig.Params().At(2) {
		a.Unknown = append(a.Unknown, "unbound Resolve options")
		return a
	}
	consumed, ok := o.node.Body.List[0].(*ast.AssignStmt)
	if !ok || len(consumed.Lhs) != 3 || len(consumed.Rhs) != 1 {
		a.Unknown = append(a.Unknown, "missing consumed document")
		return a
	}
	id, bound := consumed.Lhs[0].(*ast.Ident)
	if !bound {
		a.Unknown = append(a.Unknown, "unbound consumed local")
		return a
	}
	doc := o.unit.info.Defs[id]
	if doc == nil || len(g.Body.List) != 1 {
		a.Unknown = append(a.Unknown, "missing expansion body")
		return a
	}
	inner, ok := g.Body.List[0].(*ast.IfStmt)
	if !ok {
		a.Unknown = append(a.Unknown, "missing expansion assignment")
		return a
	}
	assign, ok := inner.Init.(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || object(o.unit.info, assign.Lhs[0]) != doc {
		a.Unknown = append(a.Unknown, "unbound expansion output")
		return a
	}
	expandCall, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(expandCall.Args) != 1 || selectionSymbol(o.unit.info, expandCall.Fun) != a.Roots[1] || object(o.unit.info, expandCall.Args[0]) != doc {
		a.Unknown = append(a.Unknown, "unbound expansion input")
		return a
	}
	a.Roles["consumed_document"] = doc.Name() + " " + types.TypeString(doc.Type(), nil)
	a.Roots = append(a.Roots, resolve)
	for _, edge := range [][]string{{resolve, output}, {output, a.Roots[1]}, {a.Roots[1], p.module + "/resolver.expandMethod"}, {a.Roots[1], p.module + "/resolver.expandValue"}, {p.module + "/resolver.expandValue", p.module + "/resolver.expandValue"}, {p.module + "/resolver.expandMethod", p.module + "/resolver.absolute"}, {a.Roots[1], p.module + "/resolver.absoluteString"}} {
		if !p.Calls(edge[0], edge[1]) {
			a.Unknown = append(a.Unknown, "missing expansion call edge")
			return a
		}
		a.CallPaths = append(a.CallPaths, edge)
	}
	// These are the actual typed struct fields, not matches of selector spelling.
	reads := map[string]bool{"Method": false, "Service": false}
	for fn, d := range p.functions {
		if fn.Pkg().Path() != p.module+"/resolver" {
			continue
		}
		ast.Inspect(d.node, func(n ast.Node) bool {
			s, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			field, ok := object(d.unit.info, s).(*types.Var)
			if !ok || !field.IsField() || field.Name() != "Extra" {
				return true
			}
			t := d.unit.info.TypeOf(s.X)
			if ptr, ok := t.(*types.Pointer); ok {
				t = ptr.Elem()
			}
			named, ok := t.(*types.Named)
			if ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == p.module+"/vm" {
				reads[named.Obj().Name()] = true
			}
			return true
		})
	}
	// All selected resolver/typed document helpers are closed reviewed context.
	// The guard is the sole supported source variation for this pinned revision.
	for fn, d := range p.functions {
		a.Frames[Symbol(fn)] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, d.node))))
	}
	frame := expansionFrame(p, o)
	if frame == "" {
		a.Unknown = append(a.Unknown, "missing expansion frame")
		return a
	}
	a.Frames[output] = frame
	a.Roles["options"] = sig.Params().At(2).Name() + " " + types.TypeString(sig.Params().At(2).Type(), nil)
	a.Roles["method_extensions"] = fmt.Sprint(reads["Method"])
	a.Roles["service_extensions"] = fmt.Sprint(reads["Service"])
	a.Steps = []StateStep{{Kind: "expansion-enabled-condition", Correct: positive, Expressions: []string{sourceExpression(p, g.Cond)}}, {Kind: "complete-extension-traversal", Correct: reads["Method"] && reads["Service"], Expressions: []string{"typed Method.Extra read: " + fmt.Sprint(reads["Method"]), "typed Service.Extra read: " + fmt.Sprint(reads["Service"])}}}
	return a
}
