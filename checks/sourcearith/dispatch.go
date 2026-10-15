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

type dispatchParts struct {
	resolved, flow    *ast.AssignStmt
	resolve, resource *ast.CallExpr
	fallback          ast.Expr
	uri               *ast.CaseClause
	guard             *ast.IfStmt
	inherit           *ast.CallExpr
}

func dispatchShape(entry, resource, fragment *ast.FuncDecl) (dispatchParts, bool) {
	var s dispatchParts
	if entry.Body == nil || len(entry.Body.List) != 10 || resource.Body == nil || len(resource.Body.List) != 5 || fragment.Body == nil || len(fragment.Body.List) != 3 {
		return s, false
	}
	s.resolved, _ = entry.Body.List[4].(*ast.AssignStmt)
	s.flow, _ = entry.Body.List[7].(*ast.AssignStmt)
	sw, ok := resource.Body.List[2].(*ast.SwitchStmt)
	ts, ok1 := fragment.Body.List[1].(*ast.TypeSwitchStmt)
	if s.resolved == nil || s.flow == nil || len(s.resolved.Lhs) != 1 || len(s.resolved.Rhs) != 1 || len(s.flow.Lhs) != 2 || len(s.flow.Rhs) != 1 || !ok || !ok1 || len(sw.Body.List) != 2 || len(ts.Body.List) != 2 {
		return s, false
	}
	s.resolve, _ = s.resolved.Rhs[0].(*ast.CallExpr)
	s.resource, _ = s.flow.Rhs[0].(*ast.CallExpr)
	branch, ok := sw.Body.List[1].(*ast.CaseClause)
	s.uri, _ = ts.Body.List[1].(*ast.CaseClause)
	if !ok || len(branch.List) != 1 || s.uri == nil || len(s.uri.List) != 1 || len(s.uri.Body) != 2 {
		return s, false
	}
	s.fallback = branch.List[0]
	s.guard, _ = s.uri.Body[1].(*ast.IfStmt)
	if s.guard == nil || len(s.guard.Body.List) != 1 {
		return s, false
	}
	ret, ok := s.guard.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return s, false
	}
	s.inherit, _ = ret.Results[0].(*ast.CallExpr)
	return s, s.resolve != nil && len(s.resolve.Args) == 3 && s.resource != nil && len(s.resource.Args) == 5 && s.inherit != nil && len(s.inherit.Args) == 2
}

// dispatchFrames masks only the independently judged operands. Everything else
// remains a reviewed source prerequisite, never an oracle for these predicates.
func dispatchFrames(p *Program, nodes []function) map[string]string {
	set := token.NewFileSet()
	decls := []*ast.FuncDecl{}
	for _, d := range nodes {
		f, e := parser.ParseFile(set, "dispatch.go", "package dispatch\n"+sourceExpression(p, d.node), 0)
		if e != nil {
			return nil
		}
		decls = append(decls, f.Decls[0].(*ast.FuncDecl))
	}
	if len(decls) != 3 {
		return nil
	}
	s, ok := dispatchShape(decls[0], decls[1], decls[2])
	if !ok {
		return nil
	}
	s.resource.Args[3] = ast.NewIdent("_")
	sw := decls[1].Body.List[2].(*ast.SwitchStmt)
	sw.Body.List[1].(*ast.CaseClause).List[0] = ast.NewIdent("_")
	s.guard.Cond = ast.NewIdent("_")
	out := map[string]string{}
	for i, d := range decls {
		var b bytes.Buffer
		if format.Node(&b, set, d) != nil {
			return nil
		}
		out[nodes[i].node.Name.Name] = fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
	}
	return out
}

func (p *Program) DispatchAudit() ServiceAudit {
	method := func(name string) string {
		return p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer)." + name
	}
	roots := []string{method("Dereference"), method("resource"), method("fragment")}
	a := ServiceAudit{Roots: roots, Frames: map[string]string{}, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	nodes := []function{}
	sigs := []*types.Signature{}
	for _, root := range roots {
		f := p.Find(root)
		if f == nil {
			a.Unknown = append(a.Unknown, "missing dispatch root")
			return a
		}
		nodes = append(nodes, p.functions[f])
		sigs = append(sigs, f.Type().(*types.Signature))
	}
	s, ok := dispatchShape(nodes[0].node, nodes[1].node, nodes[2].node)
	if !ok || sigs[0].Params().Len() != 3 || sigs[1].Params().Len() != 5 || sigs[2].Params().Len() != 3 {
		a.Unknown = append(a.Unknown, "unreviewed dispatch layout")
		return a
	}
	e, resource, f := nodes[0], nodes[1], nodes[2]
	info := e.unit.info
	id, ok := s.resolved.Lhs[0].(*ast.Ident)
	outID, ok1 := s.flow.Lhs[0].(*ast.Ident)
	if !ok || !ok1 || info.Defs[id] == nil || info.Defs[outID] == nil {
		a.Unknown = append(a.Unknown, "unbound dispatch result")
		return a
	}
	resolved := info.Defs[id]
	output := info.Defs[outID]
	if bareLocal(info, s.resource.Args[3]) == nil {
		zero, ok := s.resource.Args[3].(*ast.CompositeLit)
		if !ok || len(zero.Elts) != 0 || types.TypeString(info.TypeOf(zero), nil) != p.module+"/resolution.Result" {
			a.Unknown = append(a.Unknown, "unreviewed result operand")
			return a
		}
	}
	resolver, ok := s.resolve.Fun.(*ast.SelectorExpr)
	if !ok || selectionSymbol(info, s.resolve.Fun) != p.module+"/resolution.("+p.module+"/resolution.Resolver).Resolve" || !fieldRole(info, resolver.X, sigs[0].Recv(), "resolver") {
		a.Unknown = append(a.Unknown, "unbound resolver dispatch")
		return a
	}
	// The resolver interface and original call, nil/error guards, document and
	// service argument roles stay bound in the reviewed entry/resource frames.
	nilGate, ok := e.node.Body.List[6].(*ast.IfStmt)
	if !ok {
		a.Unknown = append(a.Unknown, "missing document success boundary")
		return a
	}
	nilCheck, ok := nilGate.Cond.(*ast.BinaryExpr)
	if !ok {
		a.Unknown = append(a.Unknown, "unreviewed document success boundary")
		return a
	}
	received := object(info, s.resource.Args[3]) == resolved && fieldRole(info, nilCheck.X, resolved, "Document") && nilCheck.Op == token.EQL
	resourceBranch := resource.node.Body.List[2].(*ast.SwitchStmt).Body.List[1].(*ast.CaseClause)
	if len(resourceBranch.Body) != 1 {
		a.Unknown = append(a.Unknown, "missing document resource return")
		return a
	}
	documentReturn, ok := resourceBranch.Body[0].(*ast.ReturnStmt)
	if !ok || len(documentReturn.Results) != 2 {
		a.Unknown = append(a.Unknown, "unreviewed document resource return")
		return a
	}
	documentCall, ok := documentReturn.Results[0].(*ast.CallExpr)
	serviceFn := p.Find(method("services"))
	if !ok || len(documentCall.Args) != 4 || serviceFn == nil {
		a.Unknown = append(a.Unknown, "missing document resource binding")
		return a
	}
	serviceNode := p.functions[serviceFn]
	if serviceNode.node.Body == nil || len(serviceNode.node.Body.List) == 0 {
		a.Unknown = append(a.Unknown, "missing service document binding")
		return a
	}
	serviceDoc, ok := serviceNode.node.Body.List[0].(*ast.AssignStmt)
	if !ok || len(serviceDoc.Rhs) != 1 {
		a.Unknown = append(a.Unknown, "unreviewed service document binding")
		return a
	}
	received = received && fieldRole(resource.unit.info, documentCall.Args[0], sigs[1].Params().At(3), "Document") && object(resource.unit.info, documentCall.Args[1]) == sigs[1].Params().At(3) && fieldRole(serviceNode.unit.info, serviceDoc.Rhs[0], serviceFn.Type().(*types.Signature).Params().At(1), "Document")
	guard, ok := s.fallback.(*ast.BinaryExpr)
	if !ok || (guard.Op != token.LAND && guard.Op != token.LOR) {
		a.Unknown = append(a.Unknown, "unreviewed path/query predicate")
		return a
	}
	pathGuard, ok := guard.X.(*ast.BinaryExpr)
	query, ok1 := guard.Y.(*ast.CallExpr)
	if !ok || !ok1 || (pathGuard.Op != token.EQL && pathGuard.Op != token.NEQ) || len(query.Args) != 1 || selectionSymbol(resource.unit.info, query.Fun) != p.module+"/dereferencer.onlyResolutionParameters" {
		a.Unknown = append(a.Unknown, "unreviewed query predicate")
		return a
	}
	path, ok := pathGuard.X.(*ast.CallExpr)
	v := resource.unit.info.Types[pathGuard.Y].Value
	if !ok || len(path.Args) != 0 || v == nil || v.Kind() != constant.String || constant.StringVal(v) != "" || selectionSymbol(resource.unit.info, path.Fun) != p.module+"/did.("+p.module+"/did.DIDURL).Path" {
		a.Unknown = append(a.Unknown, "unreviewed path predicate")
		return a
	}
	receiver, ok := path.Fun.(*ast.SelectorExpr)
	if !ok || bareLocal(resource.unit.info, receiver.X) == nil || bareLocal(resource.unit.info, query.Args[0]) == nil {
		a.Unknown = append(a.Unknown, "unbound path/query inputs")
		return a
	}
	fallback := guard.Op == token.LAND && pathGuard.Op == token.EQL && object(resource.unit.info, receiver.X) == sigs[1].Params().At(1) && object(resource.unit.info, query.Args[0]) == sigs[1].Params().At(2)
	ts := f.node.Body.List[1].(*ast.TypeSwitchStmt)
	assign, ok := ts.Assign.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		a.Unknown = append(a.Unknown, "unreviewed endpoint dispatch")
		return a
	}
	assertion, ok := assign.Rhs[0].(*ast.TypeAssertExpr)
	if !ok || assertion.Type != nil || f.unit.info.Implicits[s.uri] == nil {
		a.Unknown = append(a.Unknown, "unbound endpoint content")
		return a
	}
	check := s.guard.Cond
	positive := true
	if n, ok := check.(*ast.UnaryExpr); ok && n.Op == token.NOT {
		positive = false
		check = n.X
	}
	has, ok := check.(*ast.CallExpr)
	if !ok || len(has.Args) != 0 || selectionSymbol(f.unit.info, has.Fun) != p.module+"/did.("+p.module+"/did.DIDURL).HasFragment" {
		a.Unknown = append(a.Unknown, "unreviewed fragment presence predicate")
		return a
	}
	hasReceiver, ok := has.Fun.(*ast.SelectorExpr)
	if !ok || bareLocal(f.unit.info, hasReceiver.X) == nil {
		a.Unknown = append(a.Unknown, "unbound fragment input")
		return a
	}
	terminal, ok := e.node.Body.List[9].(*ast.ReturnStmt)
	if !ok || len(terminal.Results) != 1 {
		a.Unknown = append(a.Unknown, "unreviewed fragment return")
		return a
	}
	last, ok := terminal.Results[0].(*ast.CallExpr)
	if !ok || len(last.Args) != 3 {
		a.Unknown = append(a.Unknown, "unreviewed fragment continuation")
		return a
	}
	uri := positive && fieldRole(f.unit.info, assertion.X, sigs[2].Params().At(1), "ContentStream") && types.TypeString(f.unit.info.TypeOf(s.uri.List[0]), nil) == "[]string" && object(f.unit.info, hasReceiver.X) == sigs[2].Params().At(0) && object(info, last.Args[1]) == output
	for _, edge := range [][]string{{roots[0], roots[1]}, {roots[1], method("services")}, {method("services"), p.module + "/dereferencer.endpointURLs"}, {method("services"), p.module + "/dereferencer.uriList"}, {roots[0], roots[2]}, {roots[2], p.module + "/dereferencer.inheritFragment"}} {
		if !p.Calls(edge[0], edge[1]) {
			a.Unknown = append(a.Unknown, "missing dispatch call edge")
			return a
		}
		a.CallPaths = append(a.CallPaths, edge)
	}
	closure := map[string]bool{"resolutionOptions": true, "onlyResolutionParameters": true, "services": true, "endpointURLs": true, "uriList": true, "inheritFragment": true, "HasFragment": true, "Fragment": true, "Path": true, "Parameters": true, "Names": true, "Get": true, "DID": true, "documentResult": true, "producible": true, "isDIDMediaType": true, "CoreMediaTypes": true}
	for fn, d := range p.functions {
		if closure[fn.Name()] {
			a.Frames[Symbol(fn)] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, d.node))))
		}
	}
	frames := dispatchFrames(p, nodes)
	if len(frames) != 3 {
		a.Unknown = append(a.Unknown, "missing dispatch frame")
		return a
	}
	for i, root := range roots {
		a.Frames[root] = frames[nodes[i].node.Name.Name]
	}
	for name, obj := range map[string]types.Object{"resolved_result": resolved, "resource_output": output, "resource_input": sigs[1].Params().At(3), "endpoint_content": f.unit.info.Implicits[s.uri]} {
		a.Roles[name] = obj.Name() + " " + types.TypeString(obj.Type(), nil)
	}
	a.Steps = []StateStep{{Kind: "resolved-document-flow", Correct: received, Expressions: []string{sourceExpression(p, s.resolved), sourceExpression(p, s.resource.Args[3])}}, {Kind: "path-query-fallback", Correct: fallback, Expressions: []string{sourceExpression(p, s.fallback)}}, {Kind: "endpoint-fragment-branch", Correct: uri, Expressions: []string{sourceExpression(p, assertion), sourceExpression(p, s.uri.List[0]), sourceExpression(p, s.guard.Cond)}}}
	return a
}
