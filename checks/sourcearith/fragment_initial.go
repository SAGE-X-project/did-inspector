package sourcearith

import (
	"go/ast"
	"go/types"
)

// FragmentInitialAudit identifies the selected search result's semantic zero
// state. Go result initialization is an explicit language-semantics premise;
// this is not a runtime trace or proof of complete algorithm equivalence.
type FragmentInitialAudit struct {
	Binding       FragmentAudit `json:"binding"`
	Search        string        `json:"search"`
	ResultTypes   []string      `json:"result_types"`
	ResultRoles   []string      `json:"result_roles"`
	InitialValues []string      `json:"initial_values"`
	LanguageRule  string        `json:"language_rule"`
	Unknown       []string      `json:"unknown"`
}

// FragmentInitialAudit maps the unnamed (any, bool) search results to the
// caller's found/ok locals. No copied output or final null is its oracle.
func (p *Program) FragmentInitialAudit(root string) FragmentInitialAudit {
	out := FragmentInitialAudit{Binding: p.FragmentAudit(root), Search: p.module + "/dereferencer.findFragment", ResultTypes: []string{}, ResultRoles: []string{}, InitialValues: []string{}, LanguageRule: "https://go.dev/ref/spec#Return_statements; function-entry result values have their type's zero value", Unknown: []string{}}
	if len(out.Binding.Unknown) != 0 {
		out.Unknown = append(out.Unknown, "unbound caller/search context")
		return out
	}
	f, search := p.Find(root), p.Find(out.Search)
	d := p.functions[f]
	_, found, _, _ := fragmentShape(d.node)
	call, ok := found.Rhs[0].(*ast.CallExpr)
	if !ok || object(d.unit.info, call.Fun) != search || len(call.Args) != 2 {
		out.Unknown = append(out.Unknown, "unbound search result assignment")
		return out
	}
	matcher, ok := d.node.Body.List[1].(*ast.AssignStmt)
	if !ok || len(matcher.Lhs) != 1 {
		out.Unknown = append(out.Unknown, "unreviewed matcher assignment")
		return out
	}
	match, ok := matcher.Lhs[0].(*ast.Ident)
	if !ok || d.unit.info.Defs[match] == nil {
		out.Unknown = append(out.Unknown, "missing matcher local")
		return out
	}
	caller := f.Type().(*types.Signature)
	if object(d.unit.info, call.Args[0]) != caller.Params().At(0) || object(d.unit.info, call.Args[1]) != d.unit.info.Defs[match] {
		out.Unknown = append(out.Unknown, "unbound search input/matcher roles")
		return out
	}
	sig := search.Type().(*types.Signature)
	if sig.Results().Len() != 2 || sig.Results().At(0).Name() != "" || sig.Results().At(1).Name() != "" || !types.Identical(sig.Results().At(0).Type(), types.Universe.Lookup("any").Type()) || !types.Identical(sig.Results().At(1).Type(), types.Typ[types.Bool]) {
		out.Unknown = append(out.Unknown, "unreviewed search result roles/types")
		return out
	}
	for i := 0; i < 2; i++ {
		id, ok := found.Lhs[i].(*ast.Ident)
		if !ok || d.unit.info.Defs[id] == nil {
			out.Unknown = append(out.Unknown, "missing caller result local")
			return out
		}
		out.ResultTypes = append(out.ResultTypes, types.TypeString(sig.Results().At(i).Type(), nil))
		out.ResultRoles = append(out.ResultRoles, id.Name)
	}
	out.InitialValues = []string{"nil interface (no fragment)", "false (no match)"}
	return out
}
