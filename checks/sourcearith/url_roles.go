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

type urlRoleSites struct {
	loop       *ast.RangeStmt
	handler    *ast.CallExpr
	guard      *ast.BinaryExpr
	scan       *ast.AssignStmt
	extraction *ast.AssignStmt
	value      *ast.SliceExpr
}

func urlSites(resource, parse *ast.FuncDecl) (urlRoleSites, bool) {
	var s urlRoleSites
	if resource.Body == nil || len(resource.Body.List) != 5 || parse.Body == nil || len(parse.Body.List) != 4 {
		return s, false
	}
	s.loop, _ = resource.Body.List[3].(*ast.RangeStmt)
	branch, ok := parse.Body.List[1].(*ast.IfStmt)
	if s.loop == nil || len(s.loop.Body.List) != 1 || !ok || len(branch.Body.List) != 4 {
		return s, false
	}
	h, ok := s.loop.Body.List[0].(*ast.IfStmt)
	guard, ok1 := branch.Cond.(*ast.BinaryExpr)
	if !ok || !ok1 || guard.Op != token.LAND {
		return s, false
	}
	init, ok := h.Init.(*ast.AssignStmt)
	s.guard, _ = guard.Y.(*ast.BinaryExpr)
	s.scan, _ = branch.Body.List[0].(*ast.AssignStmt)
	s.extraction, _ = branch.Body.List[2].(*ast.AssignStmt)
	if !ok || len(init.Rhs) != 1 || s.guard == nil || s.scan == nil || len(s.scan.Lhs) != 2 || s.extraction == nil || len(s.extraction.Lhs) != 2 || len(s.extraction.Rhs) != 2 {
		return s, false
	}
	s.handler, _ = init.Rhs[0].(*ast.CallExpr)
	s.value, _ = s.extraction.Rhs[0].(*ast.SliceExpr)
	return s, s.handler != nil && len(s.handler.Args) == 4 && s.value != nil
}

// Mask only independently judged URL operand and fragment separator/offset.
// The remaining parser, caller, getter and helper bodies are reviewed premises.
func urlRoleFrames(p *Program, resource, parse function) map[string]string {
	set := token.NewFileSet()
	decls := []*ast.FuncDecl{}
	for _, f := range []function{resource, parse} {
		file, err := parser.ParseFile(set, "url.go", "package urlroles\n"+sourceExpression(p, f.node), 0)
		if err != nil {
			return nil
		}
		decls = append(decls, file.Decls[0].(*ast.FuncDecl))
	}
	s, ok := urlSites(decls[0], decls[1])
	if !ok {
		return nil
	}
	s.handler.Args[1] = ast.NewIdent("_")
	s.guard.Y = ast.NewIdent("_")
	s.value.Low = ast.NewIdent("_")
	frames := map[string]string{}
	for fn, f := range p.functions {
		frames[Symbol(fn)] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, f.node))))
	}
	for i, f := range []function{resource, parse} {
		var b bytes.Buffer
		if format.Node(&b, set, decls[i]) != nil {
			return nil
		}
		obj := f.unit.info.Defs[f.node.Name].(*types.Func)
		frames[Symbol(obj)] = fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
	}
	return frames
}

// A direct typed call must use the very same parameter, not a name or copy.
// For getter methods index -1 refers to the receiver expression.
func urlRoleArgument(p *Program, from *types.Func, to string, index int, role types.Object) bool {
	f, ok := p.functions[from]
	if !ok || role == nil {
		return false
	}
	found := false
	ast.Inspect(f.node, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, ok := object(f.unit.info, c.Fun).(*types.Func)
		if !ok || callee.Pkg() == nil || Symbol(callee) != to {
			return true
		}
		if index < 0 {
			if s, ok := c.Fun.(*ast.SelectorExpr); ok && object(f.unit.info, s.X) == role {
				found = true
			}
		} else if index < len(c.Args) && object(f.unit.info, c.Args[index]) == role {
			found = true
		}
		return true
	})
	return found
}

// URLRolesAudit judges two independent steps in the pinned DID integration:
// primary-resource URL adjustment and parser fragment extraction used by RP.
func (p *Program) URLRolesAudit() ServiceAudit {
	method := func(name string) string {
		return p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer)." + name
	}
	rp := p.module + "/relyingparty.(*" + p.module + "/relyingparty.RelyingParty).VerificationMethod"
	getter := p.module + "/did.(" + p.module + "/did.DIDURL).Fragment"
	names := []string{method("Dereference"), method("resource"), p.module + "/did.parseQueryFragment", rp, p.module + "/relyingparty.checkRef", p.module + "/document.SelectMethod", p.module + "/document.findMethod", getter, p.module + "/did.ParseURL", p.module + "/did.parseTail"}
	a := ServiceAudit{Roots: names, Frames: map[string]string{}, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	funcs := []*types.Func{}
	nodes := []function{}
	sigs := []*types.Signature{}
	for _, name := range names {
		f := p.Find(name)
		if f == nil {
			a.Unknown = append(a.Unknown, "missing URL role root")
			return a
		}
		funcs = append(funcs, f)
		nodes = append(nodes, p.functions[f])
		sigs = append(sigs, f.Type().(*types.Signature))
	}
	s, ok := urlSites(nodes[1].node, nodes[2].node)
	if !ok || sigs[0].Params().Len() != 3 || sigs[1].Params().Len() != 5 || sigs[2].Params().Len() != 3 || sigs[3].Params().Len() != 3 || sigs[4].Params().Len() != 1 || sigs[5].Params().Len() != 3 || sigs[6].Params().Len() != 2 {
		a.Unknown = append(a.Unknown, "unreviewed URL role shape")
		return a
	}
	rinfo, pinfo := nodes[1].unit.info, nodes[2].unit.info
	u := sigs[1].Params().At(1)
	receiver := sigs[1].Recv()
	h, ok := s.loop.Value.(*ast.Ident)
	handlers, ok1 := s.loop.X.(*ast.SelectorExpr)
	if !ok || !ok1 || !fieldRole(rinfo, handlers, receiver, "handlers") || rinfo.Defs[h] == nil || object(rinfo, s.handler.Fun) != rinfo.Defs[h] || types.TypeString(rinfo.Defs[h].Type(), nil) != p.module+"/dereferencer.ResourceHandler" {
		a.Unknown = append(a.Unknown, "unbound actual resource handler")
		return a
	}
	for pos, param := range map[int]int{0: 0, 2: 3, 3: 4} {
		if object(rinfo, s.handler.Args[pos]) != sigs[1].Params().At(param) {
			a.Unknown = append(a.Unknown, "unbound handler context/result/options")
			return a
		}
	}
	adjusted := false
	if object(rinfo, s.handler.Args[1]) != u {
		c, ok := s.handler.Args[1].(*ast.CallExpr)
		if !ok || len(c.Args) != 0 {
			a.Unknown = append(a.Unknown, "unreviewed handler URL expression")
			return a
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || object(rinfo, sel.X) != u || selectionSymbol(rinfo, c.Fun) != p.module+"/did.("+p.module+"/did.DIDURL).WithoutFragment" {
			a.Unknown = append(a.Unknown, "unbound handler URL adjustment")
			return a
		}
		adjusted = true
	}
	str, start, url := sigs[2].Params().At(0), sigs[2].Params().At(1), sigs[2].Params().At(2)
	offset, ok := s.value.Low.(*ast.BinaryExpr)
	index, ok1 := s.guard.X.(*ast.IndexExpr)
	if !ok || !ok1 || offset.Op != token.ADD || object(pinfo, offset.X) != start || object(pinfo, index.X) != str || object(pinfo, index.Index) != start || object(pinfo, s.value.X) != str || s.value.Slice3 || s.guard.Op != token.EQL {
		a.Unknown = append(a.Unknown, "unreviewed fragment slice or separator roles")
		return a
	}
	sep, off := pinfo.Types[s.guard.Y].Value, pinfo.Types[offset.Y].Value
	end, ok := s.scan.Lhs[0].(*ast.Ident)
	if sep == nil || off == nil || sep.Kind() != constant.Int || off.Kind() != constant.Int || !ok || object(pinfo, s.value.High) != pinfo.Defs[end] || !fieldRole(pinfo, s.extraction.Lhs[0], url, "fragment") || !fieldRole(pinfo, s.extraction.Lhs[1], url, "hasFragment") {
		a.Unknown = append(a.Unknown, "unbound fragment storage or literals")
		return a
	}
	hash, known := constant.Int64Val(sep)
	skip, known1 := constant.Int64Val(off)
	flag := pinfo.Types[s.extraction.Rhs[1]].Value
	if !known || !known1 || flag == nil || flag.Kind() != constant.Bool || !constant.BoolVal(flag) {
		a.Unknown = append(a.Unknown, "unreviewed fragment presence semantics")
		return a
	}
	bindings := []struct {
		from         int
		to           string
		index, param int
	}{
		{0, names[1], 1, 1}, {3, names[4], 0, 1}, {3, names[5], 1, 1}, {5, names[6], 1, 1}, {4, getter, -1, 0}, {6, getter, -1, 1},
	}
	for _, b := range bindings {
		if !urlRoleArgument(p, funcs[b.from], b.to, b.index, sigs[b.from].Params().At(b.param)) {
			a.Unknown = append(a.Unknown, "lost same-reference or input URL binding")
			return a
		}
	}
	g := nodes[7]
	if g.node.Body == nil || len(g.node.Body.List) != 1 || sigs[7].Recv() == nil {
		a.Unknown = append(a.Unknown, "missing fragment accessor")
		return a
	}
	ret, ok := g.node.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 || !fieldRole(g.unit.info, ret.Results[0], sigs[7].Recv(), "fragment") {
		a.Unknown = append(a.Unknown, "unbound fragment accessor value")
		return a
	}
	for _, edge := range [][]string{{names[0], names[1]}, {names[0], method("fragment")}, {names[8], names[9]}, {names[9], names[2]}, {names[2], p.module + "/did.scanQueryChars"}, {names[3], names[4]}, {names[3], names[5]}, {names[5], names[6]}, {names[4], getter}, {names[6], getter}} {
		if !p.Calls(edge[0], edge[1]) {
			a.Unknown = append(a.Unknown, "missing URL call edge")
			return a
		}
		a.CallPaths = append(a.CallPaths, edge)
	}
	a.Frames = urlRoleFrames(p, nodes[1], nodes[2])
	if len(a.Frames) == 0 {
		a.Unknown = append(a.Unknown, "missing reviewed URL context")
		return a
	}
	a.Roles["handler_url"] = u.Name() + " " + types.TypeString(u.Type(), nil)
	a.Roles["relying_party_reference"] = sigs[3].Params().At(1).Name() + " " + types.TypeString(sigs[3].Params().At(1).Type(), nil)
	a.Roles["parsed_fragment"] = sourceExpression(p, s.extraction.Lhs[0])
	a.Roles["source_string"] = str.Name()
	a.Roles["source_offset"] = start.Name()
	a.Steps = []StateStep{{Kind: "primary-resource-fragment-separation", Correct: adjusted, Expressions: []string{sourceExpression(p, s.handler.Args[1])}}, {Kind: "did-reference-fragment-extraction", Correct: hash == '#' && skip == 1, Expressions: []string{sourceExpression(p, s.guard), sourceExpression(p, s.value), sourceExpression(p, s.extraction.Lhs[0])}}}
	return a
}
