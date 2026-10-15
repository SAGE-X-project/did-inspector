package sourcearith

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/constant"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
)

type selectionParts struct {
	doc, initial *ast.AssignStmt
	decl         *ast.ValueSpec
	loop         *ast.RangeStmt
	add          *ast.AssignStmt
	gate         *ast.IfStmt
	endpoint     *ast.AssignStmt
	output       *ast.ReturnStmt
}

func selectionShape(f *ast.FuncDecl) (selectionParts, bool) {
	var s selectionParts
	if f.Body == nil || len(f.Body.List) != 13 {
		return s, false
	}
	s.doc, _ = f.Body.List[0].(*ast.AssignStmt)
	d, ok := f.Body.List[3].(*ast.DeclStmt)
	s.loop, _ = f.Body.List[4].(*ast.RangeStmt)
	s.initial, _ = f.Body.List[6].(*ast.AssignStmt)
	s.gate, _ = f.Body.List[8].(*ast.IfStmt)
	s.endpoint, _ = f.Body.List[9].(*ast.AssignStmt)
	s.output, _ = f.Body.List[12].(*ast.ReturnStmt)
	if !ok || s.doc == nil || s.loop == nil || len(s.loop.Body.List) != 3 || s.initial == nil || s.gate == nil || s.endpoint == nil || s.output == nil {
		return s, false
	}
	g, ok := d.Decl.(*ast.GenDecl)
	if !ok || len(g.Specs) != 1 {
		return s, false
	}
	s.decl, _ = g.Specs[0].(*ast.ValueSpec)
	s.add, _ = s.loop.Body.List[2].(*ast.AssignStmt)
	return s, s.decl != nil && len(s.decl.Names) == 1 && s.add != nil && len(s.doc.Lhs) == 1 && len(s.doc.Rhs) == 1 && len(s.initial.Lhs) == 1 && len(s.initial.Rhs) == 1 && len(s.add.Lhs) == 1 && len(s.add.Rhs) == 1 && len(s.output.Results) == 1
}
func selectionFrame(p *Program, d function, endpoint bool) string {
	set := token.NewFileSet()
	f, e := parser.ParseFile(set, "selection.go", "package selection\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	fn := f.Decls[0].(*ast.FuncDecl)
	if endpoint {
		s, ok := endpointShape(fn)
		if !ok {
			return ""
		}
		loop, ok := fn.Body.List[1].(*ast.RangeStmt)
		if !ok {
			return ""
		}
		loop.X = ast.NewIdent("_")
		// Keep the entire inner endpoint traversal, reference and error context.
		_ = s
	} else {
		s, ok := selectionShape(fn)
		if !ok {
			return ""
		}
		s.loop.X = ast.NewIdent("_")
		c, ok := s.add.Rhs[0].(*ast.CallExpr)
		if !ok || len(c.Args) != 2 {
			return ""
		}
		c.Args[1] = ast.NewIdent("_")
		s.gate.Cond = ast.NewIdent("_")
		out, ok := s.output.Results[0].(*ast.CallExpr)
		if !ok || len(out.Args) != 1 {
			return ""
		}
		out.Args[0] = ast.NewIdent("_")
	}
	var out bytes.Buffer
	if format.Node(&out, set, fn) != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(out.Bytes()))
}
func fieldRole(info *types.Info, e ast.Expr, receiver types.Object, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	return ok && object(info, s.X) == receiver && s.Sel.Name == name && object(info, s) != nil
}

// selectionFilters binds both optional guards to the actual parameter presence
// and service fields. The fixed match helper's semantics are a reviewed premise.
func selectionFilters(d function, s selectionParts, params, doc, item types.Object, module string) bool {
	good := true
	for i, key := range []string{"service", "serviceType"} {
		a, ok := d.node.Body.List[i+1].(*ast.AssignStmt)
		if !ok {
			return false
		}
		presence, k, ok := parameterPresence(d.unit.info, a, params, module)
		if !ok || k != key {
			return false
		}
		cond, ok := s.loop.Body.List[i].(*ast.IfStmt)
		if !ok {
			return false
		}
		guard, ok := cond.Cond.(*ast.BinaryExpr)
		if !ok || guard.Op != token.LAND || object(d.unit.info, guard.X) != presence {
			return false
		}
		neg, ok := guard.Y.(*ast.UnaryExpr)
		if !ok || neg.Op != token.NOT {
			return false
		}
		c, ok := neg.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		fn, ok := object(d.unit.info, c.Fun).(*types.Func)
		if !ok {
			return false
		}
		if i == 0 {
			if len(c.Args) != 3 || Symbol(fn) != module+"/dereferencer.serviceIDMatches" || !fieldRole(d.unit.info, c.Args[0], item, "ID") || !fieldRole(d.unit.info, c.Args[1], params, "Service") {
				return false
			}
			id, ok := c.Args[2].(*ast.CallExpr)
			if !ok {
				return false
			}
			sel, ok := id.Fun.(*ast.SelectorExpr)
			good = good && ok && object(d.unit.info, sel.X) == doc && object(d.unit.info, id.Fun) != nil && selectionSymbol(d.unit.info, id.Fun) == module+"/document.(*"+module+"/document.Document).ID"
		} else {
			good = good && len(c.Args) == 2 && Symbol(fn) == "slices.Contains" && fieldRole(d.unit.info, c.Args[0], item, "Type") && fieldRole(d.unit.info, c.Args[1], params, "ServiceType")
		}
	}
	return good
}
func (p *Program) SelectionAudit() ServiceAudit {
	root := p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).services"
	end := p.module + "/dereferencer.endpointURLs"
	a := ServiceAudit{Roots: []string{root, end}, Frames: map[string]string{}, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	f, g := p.Find(root), p.Find(end)
	if f == nil || g == nil {
		a.Unknown = append(a.Unknown, "missing selection source")
		return a
	}
	d, e := p.functions[f], p.functions[g]
	s, ok := selectionShape(d.node)
	ep, ok1 := endpointShape(e.node)
	sig, esig := f.Type().(*types.Signature), g.Type().(*types.Signature)
	if !ok || !ok1 || sig.Params().Len() != 4 || esig.Params().Len() != 2 {
		a.Unknown = append(a.Unknown, "unreviewed selection layout")
		return a
	}
	info := d.unit.info
	docID, ok := s.doc.Lhs[0].(*ast.Ident)
	itemID, ok1 := s.loop.Value.(*ast.Ident)
	kindID, ok2 := s.initial.Lhs[0].(*ast.Ident)
	each, ok3 := e.node.Body.List[1].(*ast.RangeStmt)
	selected := info.Defs[s.decl.Names[0]]
	if !ok || !ok1 || !ok2 || !ok3 || selected == nil {
		a.Unknown = append(a.Unknown, "unbound selection locals")
		return a
	}
	doc, item, kind := info.Defs[docID], info.Defs[itemID], info.Defs[kindID]
	input, ok := s.loop.X.(*ast.CallExpr)
	add, ok1 := s.add.Rhs[0].(*ast.CallExpr)
	if !ok || !ok1 || doc == nil || item == nil || kind == nil || len(add.Args) != 2 {
		a.Unknown = append(a.Unknown, "unreviewed collection operands")
		return a
	}
	getter, ok := input.Fun.(*ast.SelectorExpr)
	builtin, ok1 := object(info, add.Fun).(*types.Builtin)
	if !ok || !ok1 || builtin.Name() != "append" || object(info, input.Fun) == nil {
		a.Unknown = append(a.Unknown, "unreviewed collection operations")
		return a
	}
	if bareLocal(info, getter.X) == nil || bareLocal(e.unit.info, each.X) == nil {
		a.Unknown = append(a.Unknown, "unreviewed collection receivers")
		return a
	}
	if bareLocal(info, add.Args[1]) == nil {
		zero, ok := add.Args[1].(*ast.CompositeLit)
		if !ok || len(zero.Elts) != 0 || types.TypeString(info.TypeOf(zero), nil) != p.module+"/vm.Service" {
			a.Unknown = append(a.Unknown, "unreviewed appended service")
			return a
		}
	}
	out, ok := s.output.Results[0].(*ast.CallExpr)
	if !ok || len(out.Args) != 1 || bareLocal(info, out.Args[0]) == nil || len(s.endpoint.Lhs) != 2 || len(s.endpoint.Rhs) != 1 {
		a.Unknown = append(a.Unknown, "unreviewed URI-list return")
		return a
	}
	urlID, ok := s.endpoint.Lhs[0].(*ast.Ident)
	if !ok || info.Defs[urlID] == nil || object(info, out.Fun) == nil {
		a.Unknown = append(a.Unknown, "unbound URI-list return")
		return a
	}
	uriReturn := selectionSymbol(info, out.Fun) == p.module+"/dereferencer.uriList" && object(info, out.Args[0]) == info.Defs[urlID]
	collected := fieldRole(info, s.doc.Rhs[0], sig.Params().At(1), "Document") && object(info, getter.X) == doc && selectionSymbol(info, input.Fun) == p.module+"/document.(*"+p.module+"/document.Document).Services" && object(info, s.add.Lhs[0]) == selected && object(info, add.Args[0]) == selected && object(info, add.Args[1]) == item && selectionFilters(d, s, sig.Params().At(0), doc, item, p.module)
	gate := s.gate.Cond
	positive := true
	if n, ok := gate.(*ast.UnaryExpr); ok && n.Op == token.NOT {
		positive = false
		gate = n.X
	}
	c, ok := gate.(*ast.CallExpr)
	if !ok || len(c.Args) != 1 || object(info, c.Fun) == nil || object(info, c.Args[0]) == nil {
		a.Unknown = append(a.Unknown, "unreviewed document media guard")
		return a
	}
	if selectionSymbol(info, c.Fun) != p.module+"/dereferencer.isDIDMediaType" {
		a.Unknown = append(a.Unknown, "unreviewed document media predicate")
		return a
	}
	docGuard := positive && object(info, c.Args[0]) == kind
	// Exact single media values only: finite CoreMediaTypes plus the actual
	// resolved metadata media and URI-list offer are checked with runtime receipts.
	closure := []string{"isDIDMediaType", "serviceIDMatches", "absoluteRef", "withServices", "documentResult", "uriList", "Get", "Parameters", "Services", "CoreMediaTypes", "Negotiate", "ParseAccept", "weight", "Matches", "specificity"}
	for fn, unit := range p.functions {
		for _, name := range closure {
			if fn.Name() == name {
				a.Frames[Symbol(fn)] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, unit.node))))
			}
		}
	}
	for _, edge := range [][]string{{root, end}, {root, p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).documentResult"}, {root, p.module + "/dereferencer.uriList"}} {
		if !p.Calls(edge[0], edge[1]) {
			a.Unknown = append(a.Unknown, "unbound selected branch call")
			return a
		}
		a.CallPaths = append(a.CallPaths, edge)
	}
	if !selectionNegotiation(d, s, kind, sig.Params().At(2)) {
		a.Unknown = append(a.Unknown, "unreviewed typed negotiation flow")
		return a
	}
	interrupted := false
	ast.Inspect(each.Body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.BranchStmt, *ast.ReturnStmt:
			interrupted = true
		}
		return true
	})
	if interrupted {
		a.Unknown = append(a.Unknown, "interrupted selected service traversal")
		return a
	}
	media, ok := p.selectionMedia(d)
	if !ok {
		a.Unknown = append(a.Unknown, "unreviewed finite media offers")
		return a
	}
	a.Roles["document_media_offers"] = media
	a.Frames[root] = selectionFrame(p, d, false)
	a.Frames[end] = selectionFrame(p, e, true)
	for name, obj := range map[string]types.Object{"resolved_document": doc, "service_item": item, "selected_services": selected, "media_kind": kind, "endpoint_selected": esig.Params().At(0)} {
		a.Roles[name] = obj.Name() + " " + types.TypeString(obj.Type(), nil)
	}
	a.Steps = []StateStep{{Kind: "selected-service-list", Correct: collected, Expressions: []string{sourceExpression(p, s.loop.X), sourceExpression(p, s.add)}}, {Kind: "each-selected-service", Correct: object(e.unit.info, each.X) == esig.Params().At(0) && p.serviceArgument(root, end), Expressions: []string{sourceExpression(p, each.X)}}, {Kind: "document-media-branch", Correct: docGuard, Expressions: []string{sourceExpression(p, s.gate.Cond)}}, {Kind: "uri-list-media-branch", Correct: docGuard && uriReturn, Expressions: []string{sourceExpression(p, s.output)}}}
	_ = ep
	return a
}

func (p *Program) selectionMedia(d function) (string, bool) {
	f := p.Find(p.module + "/representation.CoreMediaTypes")
	if f == nil {
		return "", false
	}
	unit := p.functions[f]
	values := []string{}
	ast.Inspect(unit.node.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range c.Elts {
			v := unit.unit.info.Types[e].Value
			if v != nil && v.Kind() == constant.String {
				values = append(values, constant.StringVal(v))
			}
		}
		return true
	})
	if len(values) != 3 || values[0] != "application/did" || values[1] != "application/did+ld+json" || values[2] != "application/did+json" {
		return "", false
	}
	hasURI := false
	ast.Inspect(d.node.Body.List[7], func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) != 2 {
			return true
		}
		fn, ok := object(d.unit.info, c.Fun).(*types.Builtin)
		v := d.unit.info.Types[c.Args[1]].Value
		if ok && fn.Name() == "append" && v != nil && v.Kind() == constant.String && constant.StringVal(v) == "text/uri-list" {
			hasURI = true
		}
		return true
	})
	return "application/did | application/did+ld+json | application/did+json | text/uri-list", hasURI
}

func selectionSymbol(info *types.Info, e ast.Expr) string {
	fn, ok := object(info, e).(*types.Func)
	if !ok {
		return ""
	}
	return Symbol(fn)
}

// selectionNegotiation ties the same Accept parameter, offer collection and
// selected kind to the nominal negotiation call. Other layouts are unreviewed.
func selectionNegotiation(d function, s selectionParts, kind, opts types.Object) bool {
	info := d.unit.info
	index, ok := s.initial.Rhs[0].(*ast.IndexExpr)
	if !ok {
		return false
	}
	call, ok := index.X.(*ast.CallExpr)
	v := info.Types[index.Index].Value
	if !ok || v == nil || v.Kind() != constant.Int || constant.Sign(v) != 0 || selectionSymbol(info, call.Fun) != "github.com/sage-x-project/did-go/representation.CoreMediaTypes" {
		return false
	}
	outer, ok := d.node.Body.List[7].(*ast.IfStmt)
	if !ok || len(outer.Body.List) != 3 {
		return false
	}
	guard, ok := outer.Cond.(*ast.BinaryExpr)
	if !ok || guard.Op != token.NEQ || !fieldRole(info, guard.X, opts, "Accept") {
		return false
	}
	empty := info.Types[guard.Y].Value
	if empty == nil || empty.Kind() != constant.String || constant.StringVal(empty) != "" {
		return false
	}
	offers, ok := outer.Body.List[0].(*ast.AssignStmt)
	inner, ok1 := outer.Body.List[2].(*ast.IfStmt)
	if !ok || !ok1 || len(offers.Lhs) != 1 {
		return false
	}
	oid, ok := offers.Lhs[0].(*ast.Ident)
	if !ok || info.Defs[oid] == nil {
		return false
	}
	assign, ok := inner.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 || object(info, assign.Lhs[0]) != kind {
		return false
	}
	negotiate, ok := assign.Rhs[0].(*ast.CallExpr)
	return ok && len(negotiate.Args) == 2 && selectionSymbol(info, negotiate.Fun) == "github.com/sage-x-project/did-go/resolution.Negotiate" && fieldRole(info, negotiate.Args[0], opts, "Accept") && object(info, negotiate.Args[1]) == info.Defs[oid]
}
