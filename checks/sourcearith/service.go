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

// ServiceAudit binds selected service/relative-reference conditions and parser
// operand roles, not complete matching, RFC3986 resolution or runtime tracing.
type ServiceAudit struct {
	Roots     []string          `json:"roots"`
	Frames    map[string]string `json:"frames"`
	Roles     map[string]string `json:"roles"`
	Steps     []StateStep       `json:"steps"`
	Unknown   []string          `json:"unknown"`
	CallPaths [][]string        `json:"call_paths"`
}
type serviceParts struct {
	first, second *ast.AssignStmt
	branch        *ast.CaseClause
}
type endpointParts struct {
	guard *ast.IfStmt
	ref   *ast.AssignStmt
	loop  *ast.RangeStmt
	base  *ast.AssignStmt
}

func serviceShape(f *ast.FuncDecl) (serviceParts, bool) {
	var p serviceParts
	if f.Body == nil || len(f.Body.List) != 5 {
		return p, false
	}
	p.first, _ = f.Body.List[0].(*ast.AssignStmt)
	p.second, _ = f.Body.List[1].(*ast.AssignStmt)
	s, ok := f.Body.List[2].(*ast.SwitchStmt)
	if p.first == nil || p.second == nil || !ok || len(s.Body.List) != 2 {
		return p, false
	}
	p.branch, _ = s.Body.List[0].(*ast.CaseClause)
	return p, p.branch != nil && len(p.branch.List) == 1 && len(p.branch.Body) == 1
}
func endpointShape(f *ast.FuncDecl) (endpointParts, bool) {
	var p endpointParts
	if f.Body == nil || len(f.Body.List) != 8 {
		return p, false
	}
	p.guard, _ = f.Body.List[2].(*ast.IfStmt)
	p.ref, _ = f.Body.List[3].(*ast.AssignStmt)
	p.loop, _ = f.Body.List[6].(*ast.RangeStmt)
	if p.guard == nil || p.ref == nil || p.loop == nil || len(p.loop.Body.List) != 3 {
		return p, false
	}
	p.base, _ = p.loop.Body.List[0].(*ast.AssignStmt)
	return p, p.base != nil
}
func assignedCall(s *ast.AssignStmt) (*ast.CallExpr, bool) {
	if s == nil || len(s.Lhs) != 2 || len(s.Rhs) != 1 {
		return nil, false
	}
	c, ok := s.Rhs[0].(*ast.CallExpr)
	return c, ok && len(c.Args) == 1
}
func serviceFrame(p *Program, d function, endpoint bool) string {
	set := token.NewFileSet()
	f, e := parser.ParseFile(set, "service.go", "package service\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	fn := f.Decls[0].(*ast.FuncDecl)
	if endpoint {
		s, ok := endpointShape(fn)
		if !ok {
			return ""
		}
		init, ok := s.guard.Init.(*ast.AssignStmt)
		if !ok {
			return ""
		}
		for _, a := range []*ast.AssignStmt{init, s.ref, s.base} {
			c, ok := assignedCall(a)
			if !ok {
				return ""
			}
			c.Args[0] = &ast.Ident{Name: "_"}
		}
		s.guard.Cond = &ast.Ident{Name: "_"}
	} else {
		s, ok := serviceShape(fn)
		if !ok {
			return ""
		}
		for _, a := range []*ast.AssignStmt{s.first, s.second} {
			c, ok := assignedCall(a)
			if !ok {
				return ""
			}
			c.Args[0] = &ast.Ident{Name: "_"}
		}
		s.branch.List[0] = &ast.Ident{Name: "_"}
	}
	var out bytes.Buffer
	if format.Node(&out, set, fn) != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(out.Bytes()))
}
func parameterPresence(info *types.Info, s *ast.AssignStmt, param types.Object, module string) (types.Object, string, bool) {
	c, ok := assignedCall(s)
	if !ok {
		return nil, "", false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	fn, _ := object(info, c.Fun).(*types.Func)
	id, ok1 := s.Lhs[1].(*ast.Ident)
	value := info.Types[c.Args[0]].Value
	if !ok || !ok1 || fn == nil || Symbol(fn) != module+"/did.("+module+"/did.DIDParameters).Get" || object(info, sel.X) != param || info.Defs[id] == nil || value == nil || value.Kind() != constant.String {
		return nil, "", false
	}
	return info.Defs[id], constant.StringVal(value), true
}
func parseArgument(info *types.Info, s *ast.AssignStmt) (types.Object, ast.Expr, bool) {
	c, ok := assignedCall(s)
	if !ok {
		return nil, nil, false
	}
	fn, _ := object(info, c.Fun).(*types.Func)
	id, ok := s.Lhs[0].(*ast.Ident)
	if !ok || fn == nil || Symbol(fn) != "net/url.Parse" || info.Defs[id] == nil {
		return nil, nil, false
	}
	return info.Defs[id], c.Args[0], true
}
func (p *Program) ServiceAudit() ServiceAudit {
	roots := []string{p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).resource", p.module + "/dereferencer.endpointURLs"}
	a := ServiceAudit{Roots: roots, Frames: map[string]string{}, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	f, g := p.Find(roots[0]), p.Find(roots[1])
	if f == nil || g == nil {
		a.Unknown = append(a.Unknown, "missing service source")
		return a
	}
	d, e := p.functions[f], p.functions[g]
	s, ok := serviceShape(d.node)
	ep, ok1 := endpointShape(e.node)
	sig, esig := f.Type().(*types.Signature), g.Type().(*types.Signature)
	if !ok || !ok1 || sig.Params().Len() != 5 || esig.Params().Len() != 2 {
		a.Unknown = append(a.Unknown, "unreviewed service source layout")
		return a
	}
	x, k, ok := parameterPresence(d.unit.info, s.first, sig.Params().At(2), p.module)
	y, l, ok1 := parameterPresence(d.unit.info, s.second, sig.Params().At(2), p.module)
	guard, ok2 := s.branch.List[0].(*ast.BinaryExpr)
	if !ok || !ok1 || !ok2 || (guard.Op != token.LOR && guard.Op != token.LAND) || bareLocal(d.unit.info, guard.X) == nil || bareLocal(d.unit.info, guard.Y) == nil {
		a.Unknown = append(a.Unknown, "unsupported service parameter or guard")
		return a
	}
	init, ok := ep.guard.Init.(*ast.AssignStmt)
	if !ok {
		a.Unknown = append(a.Unknown, "missing relativeRef presence assignment")
		return a
	}
	present, key, ok := parameterPresence(e.unit.info, init, esig.Params().At(1), p.module)
	neg, negated := ep.guard.Cond.(*ast.UnaryExpr)
	condition := ep.guard.Cond
	if negated {
		if neg.Op != token.NOT {
			a.Unknown = append(a.Unknown, "unsupported reference condition")
			return a
		}
		condition = neg.X
	}
	if !ok || bareLocal(e.unit.info, condition) == nil {
		a.Unknown = append(a.Unknown, "unreviewed reference condition")
		return a
	}
	ref, refArg, ok := parseArgument(e.unit.info, ep.ref)
	base, baseArg, ok1 := parseArgument(e.unit.info, ep.base)
	selector, ok2 := refArg.(*ast.SelectorExpr)
	loopID, ok3 := ep.loop.Value.(*ast.Ident)
	if !ok || !ok1 || !ok2 || !ok3 || bareLocal(e.unit.info, selector.X) == nil || object(e.unit.info, selector) == nil || bareLocal(e.unit.info, baseArg) == nil || e.unit.info.Defs[loopID] == nil {
		a.Unknown = append(a.Unknown, "unreviewed URL parser operands")
		return a
	}
	// The exact collection/filter/append/error/caller frame is an independently
	// reviewed prerequisite. Confirm the parser results feed the actual operation.
	bound := false
	ast.Inspect(ep.loop.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && len(c.Args) == 1 {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
				fn, _ := object(e.unit.info, c.Fun).(*types.Func)
				if fn != nil && Symbol(fn) == "net/url.(*net/url.URL).ResolveReference" && object(e.unit.info, sel.X) == base && object(e.unit.info, c.Args[0]) == ref {
					bound = true
				}
			}
		}
		return true
	})
	if !bound {
		a.Unknown = append(a.Unknown, "unbound base/reference operands")
		return a
	}
	// Follow the selected service's string endpoint into the collection and range
	// local. Unreviewed alternatives are errors, not inferred nonconformance.
	collection, ok := serviceCollection(e, esig.Params().At(0), ep.loop)
	if !ok {
		a.Unknown = append(a.Unknown, "unbound selected endpoint collection")
		return a
	}
	for name, obj := range collection {
		a.Roles[name] = obj.Name() + " " + types.TypeString(obj.Type(), nil)
	}
	service := p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).services"
	entry := p.module + "/dereferencer.(*" + p.module + "/dereferencer.Dereferencer).Dereference"
	for _, edge := range [][]string{{entry, roots[0]}, {roots[0], service}, {service, roots[1]}} {
		if !p.Calls(edge[0], edge[1]) {
			a.Unknown = append(a.Unknown, "unbound service caller")
			return a
		}
		a.CallPaths = append(a.CallPaths, edge)
	}
	for fn, unit := range p.functions {
		if Symbol(fn) == service || fn.Pkg().Path() == p.module+"/did" && (fn.Name() == "Get" || fn.Name() == "Parameters") {
			a.Frames[Symbol(fn)] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, unit.node))))
		}
	}
	if !p.serviceArgument(service, roots[1]) {
		a.Unknown = append(a.Unknown, "unbound selected caller argument")
		return a
	}
	serviceCorrect := ((k == "service" && l == "serviceType") || (k == "serviceType" && l == "service")) && guard.Op == token.LOR && ((object(d.unit.info, guard.X) == x && object(d.unit.info, guard.Y) == y) || (object(d.unit.info, guard.X) == y && object(d.unit.info, guard.Y) == x))
	relativeCorrect := key == "relativeRef" && negated && object(e.unit.info, condition) == present
	a.Frames[roots[0]] = serviceFrame(p, d, false)
	a.Frames[roots[1]] = serviceFrame(p, e, true)
	for name, obj := range map[string]types.Object{"first_presence": x, "second_presence": y, "relative_ref_present": present, "base": base, "reference": ref, "endpoint": e.unit.info.Defs[loopID]} {
		a.Roles[name] = obj.Name() + " " + types.TypeString(obj.Type(), nil)
	}
	a.Steps = []StateStep{{Kind: "service-parameter-branch", Correct: serviceCorrect, Expressions: []string{sourceExpression(p, s.branch.List[0])}}, {Kind: "relative-reference-branch", Correct: relativeCorrect, Expressions: []string{sourceExpression(p, ep.guard.Cond)}}, {Kind: "selected-endpoint-base", Correct: object(e.unit.info, baseArg) == e.unit.info.Defs[loopID], Expressions: []string{sourceExpression(p, baseArg)}}, {Kind: "relative-reference-value", Correct: object(e.unit.info, selector.X) == esig.Params().At(1) && selector.Sel.Name == "RelativeRef", Expressions: []string{sourceExpression(p, refArg)}}}
	return a
}

// serviceCollection verifies the typed selected -> service -> endpoint -> URL
// append -> urls -> range chain. The unchanged frame separately binds filtering.
func serviceCollection(d function, selected types.Object, loop *ast.RangeStmt) (map[string]types.Object, bool) {
	info := d.unit.info
	roles := map[string]types.Object{"selected": selected}
	ast.Inspect(d.node.Body, func(n ast.Node) bool {
		r, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		id, ok := r.Value.(*ast.Ident)
		if !ok {
			return true
		}
		if object(info, r.X) == selected {
			roles["selected_service"] = info.Defs[id]
		}
		if sel, ok := r.X.(*ast.SelectorExpr); ok && roles["selected_service"] != nil && object(info, sel.X) == roles["selected_service"] && sel.Sel.Name == "ServiceEndpoint" && object(info, sel) != nil {
			roles["service_endpoint"] = info.Defs[id]
		}
		return true
	})
	ast.Inspect(d.node.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return true
		}
		c, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || len(c.Args) != 2 {
			return true
		}
		builtin, ok := object(info, c.Fun).(*types.Builtin)
		field, ok1 := c.Args[1].(*ast.SelectorExpr)
		if ok && builtin.Name() == "append" && ok1 && roles["service_endpoint"] != nil && object(info, field.X) == roles["service_endpoint"] && field.Sel.Name == "URL" && object(info, field) != nil && object(info, a.Lhs[0]) == object(info, c.Args[0]) {
			roles["endpoint_urls"] = object(info, a.Lhs[0])
		}
		return true
	})
	return roles, len(roles) == 4 && roles["endpoint_urls"] != nil && object(info, loop.X) == roles["endpoint_urls"]
}

func (p *Program) serviceArgument(caller, target string) bool {
	f := p.Find(caller)
	if f == nil {
		return false
	}
	d := p.functions[f]
	sig := f.Type().(*types.Signature)
	var selected types.Object
	ast.Inspect(d.node.Body, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if ok && len(v.Names) == 1 && v.Names[0].Name == "selected" {
			selected = d.unit.info.Defs[v.Names[0]]
		}
		return true
	})
	bound := false
	ast.Inspect(d.node.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if ok && len(c.Args) == 2 {
			fn, ok := object(d.unit.info, c.Fun).(*types.Func)
			if ok && Symbol(fn) == target && selected != nil && object(d.unit.info, c.Args[0]) == selected && object(d.unit.info, c.Args[1]) == sig.Params().At(0) {
				bound = true
			}
		}
		return true
	})
	return bound
}
