package sourcearith

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// copiedExpansionOptions binds the reviewed Resolve layout's struct copy and
// its sole Accept fallback. Only the scalar ExpandRelativeURLs preservation is
// established: Extra and VersionTime still have their ordinary shallow-copy
// semantics. Unsupported assignments, indirect writes and escapes are unknown.
func copiedExpansionOptions(entry function, sig *types.Signature, argument ast.Expr, module string) (types.Object, bool) {
	bad := func() (types.Object, bool) { return nil, false }
	if entry.node.Body == nil || len(entry.node.Body.List) != 12 || sig.Params().Len() != 3 || sig.Recv() == nil {
		return bad()
	}
	statements := entry.node.Body.List
	info := entry.unit.info
	opts := sig.Params().At(2)
	nominal, ok := opts.Type().(*types.Named)
	if !ok || nominal.Obj().Pkg() == nil || nominal.Obj().Pkg().Path() != module+"/resolution" || nominal.Obj().Name() != "ResolutionOptions" {
		return bad()
	}
	if _, ok := nominal.Underlying().(*types.Struct); !ok {
		return bad()
	}
	init, ok := statements[5].(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 || len(init.Rhs) != 1 || object(info, init.Rhs[0]) != opts {
		return bad()
	}
	localID, ok := init.Lhs[0].(*ast.Ident)
	if !ok {
		return bad()
	}
	local := info.Defs[localID]
	if local == nil || object(info, argument) != local || !types.Identical(local.Type(), opts.Type()) {
		return bad()
	}
	outer, ok := statements[6].(*ast.IfStmt)
	if !ok || !fieldRole(info, outer.Cond, sig.Recv(), "intermediateDocument") || len(outer.Body.List) != 1 || outer.Else != nil {
		return bad()
	}
	inner, ok := outer.Body.List[0].(*ast.IfStmt)
	if !ok || len(inner.Body.List) != 1 || inner.Else != nil {
		return bad()
	}
	negotiation, ok := inner.Init.(*ast.AssignStmt)
	if !ok || negotiation.Tok != token.DEFINE || len(negotiation.Lhs) != 2 || len(negotiation.Rhs) != 1 {
		return bad()
	}
	blank, ok := negotiation.Lhs[0].(*ast.Ident)
	flag, ok1 := negotiation.Lhs[1].(*ast.Ident)
	if !ok || !ok1 || blank.Name != "_" || info.Defs[flag] == nil {
		return bad()
	}
	negotiate, ok := negotiation.Rhs[0].(*ast.CallExpr)
	if !ok || len(negotiate.Args) != 2 || selectionSymbol(info, negotiate.Fun) != module+"/resolution.Negotiate" || !fieldRole(info, negotiate.Args[0], opts, "Accept") {
		return bad()
	}
	offers, ok := negotiate.Args[1].(*ast.CallExpr)
	if !ok || len(offers.Args) != 0 || selectionSymbol(info, offers.Fun) != module+"/representation.CoreMediaTypes" {
		return bad()
	}
	condition, ok := inner.Cond.(*ast.UnaryExpr)
	if !ok || condition.Op != token.NOT || object(info, condition.X) != info.Defs[flag] {
		return bad()
	}
	accept, ok := inner.Body.List[0].(*ast.AssignStmt)
	if !ok || accept.Tok != token.ASSIGN || len(accept.Lhs) != 1 || len(accept.Rhs) != 1 || !fieldRole(info, accept.Lhs[0], local, "Accept") {
		return bad()
	}
	value := info.Types[accept.Rhs[0]].Value
	if value == nil || value.Kind() != constant.String || constant.StringVal(value) != "" {
		return bad()
	}
	read, ok := statements[7].(*ast.AssignStmt)
	if !ok || len(read.Rhs) != 1 {
		return bad()
	}
	call, ok := read.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 4 || selectionSymbol(info, call.Fun) != module+"/resolver.read" || object(info, call.Args[3]) != local {
		return bad()
	}
	// selectionSymbol already requires a *types.Func; Go function objects have signatures.
	callee := object(info, call.Fun).(*types.Func)
	readSig := callee.Type().(*types.Signature)
	if readSig.Params().Len() != 4 || !types.Identical(readSig.Params().At(3).Type(), local.Type()) {
		return bad()
	}
	sel, ok := accept.Lhs[0].(*ast.SelectorExpr)
	if !ok {
		return bad()
	}
	// Bind the original parameter's only permitted pre-copy uses too. A
	// by-value copy cannot preserve the caller's flag if opts was overwritten.
	var originalUses []ast.Node
	for i, expected := range []string{module + "/resolver.(*" + module + "/resolver.DefaultResolver).supported", module + "/resolution.(" + module + "/resolution.ResolutionOptions).Validate"} {
		guard, ok := statements[i+3].(*ast.IfStmt)
		if !ok {
			return bad()
		}
		binding, ok := guard.Init.(*ast.AssignStmt)
		if !ok || len(binding.Rhs) != 1 {
			return bad()
		}
		invoke, ok := binding.Rhs[0].(*ast.CallExpr)
		if !ok || selectionSymbol(info, invoke.Fun) != expected {
			return bad()
		}
		fn := object(info, invoke.Fun).(*types.Func)
		invoked := fn.Type().(*types.Signature)
		if i == 0 {
			if len(invoke.Args) != 1 || invoked.Params().Len() != 1 || !types.Identical(invoked.Params().At(0).Type(), opts.Type()) || object(info, invoke.Args[0]) != opts {
				return bad()
			}
			originalUses = append(originalUses, invoke.Args[0])
		} else {
			selector, ok := invoke.Fun.(*ast.SelectorExpr)
			if !ok || len(invoke.Args) != 0 || invoked.Recv() == nil || !types.Identical(invoked.Recv().Type(), opts.Type()) || object(info, selector.X) != opts {
				return bad()
			}
			originalUses = append(originalUses, selector.X)
		}
	}
	originalAccept := negotiate.Args[0].(*ast.SelectorExpr)
	originalUses = append(originalUses, init.Rhs[0], originalAccept.X)
	originalAllowed := map[ast.Node]bool{}
	for _, n := range originalUses {
		originalAllowed[n] = true
	}
	// The local's only occurrences are the copy definition, this Accept write,
	// and the two reviewed by-value call arguments. This rejects aliases,
	// closures, address escapes and even indirect writes through Extra/pointers.
	allowed := map[ast.Node]bool{localID: true, sel.X: true, call.Args[3]: true, argument: true}
	safe := true
	seen := 0
	originalSeen := 0
	ast.Inspect(entry.node.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if ok && (object(info, id) == local || info.Defs[id] == local) {
			seen++
			if !allowed[id] {
				safe = false
			}
		}
		if ok && object(info, id) == opts {
			originalSeen++
			if !originalAllowed[id] {
				safe = false
			}
		}
		return true
	})
	if !safe || seen != 4 || originalSeen != 4 {
		return bad()
	}
	return local, true
}
