package sourcearith

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// FragmentMediaAudit binds the actual document, fully qualified fragment,
// pre-authorization lookup candidate and that same candidate's final return.
// Closed reviewed helpers and plain-JSON absolute-id semantics are premises.
func (p *Program) FragmentMediaAudit() ServiceAudit {
	a := ServiceAudit{Roots: []string{}, Frames: map[string]string{}, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	names := []string{"dereferencer.verificationMethod", "document.SelectMethod", "document.findMethod", "document.allMethods"}
	nodes := []function{}
	functions := []*types.Func{}
	for _, name := range names {
		root := p.module + "/" + name
		f := p.Find(root)
		if f == nil {
			a.Unknown = append(a.Unknown, "missing method-selection helper")
			return a
		}
		d := p.functions[f]
		if d.node.Body == nil {
			a.Unknown = append(a.Unknown, "missing selection body")
			return a
		}
		a.Roots = append(a.Roots, root)
		a.Frames[root] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, d.node))))
		nodes = append(nodes, d)
		functions = append(functions, f)
	}
	for _, edge := range [][2]string{{names[0], names[1]}, {names[1], names[2]}, {names[2], names[3]}} {
		from, to := p.module+"/"+edge[0], p.module+"/"+edge[1]
		if !p.Calls(from, to) {
			a.Unknown = append(a.Unknown, "missing method-selection edge")
			return a
		}
		a.CallPaths = append(a.CallPaths, []string{from, to})
	}
	// Fixed statement layout excludes intervening mutation, alternate returns,
	// aliases and reassignments through the separately reviewed exact frames.
	h, selectFn := nodes[0], nodes[1]
	if len(h.node.Body.List) != 7 || len(selectFn.node.Body.List) != 11 {
		a.Unknown = append(a.Unknown, "unreviewed selection phase layout")
		return a
	}
	ref, ok := h.node.Body.List[2].(*ast.AssignStmt)
	selected, ok1 := h.node.Body.List[4].(*ast.AssignStmt)
	found, ok2 := selectFn.node.Body.List[4].(*ast.AssignStmt)
	if !ok || !ok1 || !ok2 || len(ref.Lhs) != 2 || len(ref.Rhs) != 1 || len(selected.Lhs) != 2 || len(selected.Rhs) != 1 || len(found.Lhs) != 2 || len(found.Rhs) != 1 {
		a.Unknown = append(a.Unknown, "unreviewed candidate assignments")
		return a
	}
	reference, ok := ref.Rhs[0].(*ast.CallExpr)
	call, ok1 := selected.Rhs[0].(*ast.CallExpr)
	lookup, ok2 := found.Rhs[0].(*ast.CallExpr)
	if !ok || !ok1 || !ok2 || len(reference.Args) != 1 || len(call.Args) != 3 || len(lookup.Args) != 2 {
		a.Unknown = append(a.Unknown, "unreviewed selection calls")
		return a
	}
	hs, ss := functions[0].Type().(*types.Signature), functions[1].Type().(*types.Signature)
	if hs.Params().Len() != 4 || ss.Params().Len() != 3 {
		a.Unknown = append(a.Unknown, "unbound selection parameters")
		return a
	}
	refID, ok := ref.Lhs[0].(*ast.Ident)
	selectedID, ok1 := selected.Lhs[0].(*ast.Ident)
	foundID, ok2 := found.Lhs[0].(*ast.Ident)
	if !ok || !ok1 || !ok2 || h.unit.info.Defs[refID] == nil || h.unit.info.Defs[selectedID] == nil || selectFn.unit.info.Defs[foundID] == nil {
		a.Unknown = append(a.Unknown, "unbound candidate storage")
		return a
	}
	// A single absolute-id fixture excludes relative-id fallback. The reviewed
	// findMethod body returns the Clone of the unique absolute-id match first.
	constructed := sourceExpression(p, reference.Args[0]) == `doc.ID().String() + "#" + frag` && urlRoleArgument(p, functions[0], p.module+"/document.(*"+p.module+"/document.Document).ID", -1, hs.Params().At(0))
	// ID's actual receiver is a pointer, as independently resolved by Go types.

	helperArgs := object(h.unit.info, call.Args[0]) == hs.Params().At(0) && object(h.unit.info, call.Args[1]) == h.unit.info.Defs[refID] && object(h.unit.info, call.Fun) == functions[1]
	lookupArgs := object(selectFn.unit.info, lookup.Args[0]) == ss.Params().At(0) && object(selectFn.unit.info, lookup.Args[1]) == ss.Params().At(1) && object(selectFn.unit.info, lookup.Fun) == functions[2]
	ret, ok := selectFn.node.Body.List[10].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 2 {
		a.Unknown = append(a.Unknown, "missing selected-candidate return")
		return a
	}
	addr, ok := ret.Results[0].(*ast.UnaryExpr)
	same := ok && addr.Op == token.AND && object(selectFn.unit.info, addr.X) == selectFn.unit.info.Defs[foundID]
	final, ok := h.node.Body.List[6].(*ast.ReturnStmt)
	if !ok || len(final.Results) != 1 {
		a.Unknown = append(a.Unknown, "missing fragment result")
		return a
	}
	result, ok := final.Results[0].(*ast.CompositeLit)
	if !ok {
		a.Unknown = append(a.Unknown, "unreviewed fragment result")
		return a
	}
	returned := false
	for _, element := range result.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		value, ok1 := kv.Value.(*ast.StarExpr)
		if ok && ok1 && key.Name == "ContentStream" && object(h.unit.info, value.X) == h.unit.info.Defs[selectedID] {
			returned = true
		}
	}
	a.Roles["helper_document"] = hs.Params().At(0).Name()
	a.Roles["helper_fragment"] = hs.Params().At(1).Name()
	a.Roles["parsed_reference"] = refID.Name
	a.Roles["candidate"] = foundID.Name
	a.Steps = []StateStep{{Kind: "same-document-full-fragment", Correct: constructed && helperArgs, Expressions: []string{sourceExpression(p, reference), sourceExpression(p, call)}}, {Kind: "same-pre-authorization-candidate", Correct: lookupArgs && same && returned, Expressions: []string{sourceExpression(p, lookup), sourceExpression(p, ret), sourceExpression(p, final)}}}
	return a
}
