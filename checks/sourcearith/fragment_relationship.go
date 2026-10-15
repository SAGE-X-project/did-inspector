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

// FragmentRelationshipAudit records selected typed option and branch roles.
// It is not a runtime trace, empty-option policy or a media-type conformance proof.
type FragmentRelationshipAudit struct {
	Root    string            `json:"root"`
	Frame   string            `json:"frame"`
	Roles   map[string]string `json:"roles"`
	Steps   []StateStep       `json:"steps"`
	Unknown []string          `json:"unknown"`
}

func relationshipShape(fn *ast.FuncDecl) (*ast.AssignStmt, *ast.TypeSwitchStmt, *ast.CaseClause, *ast.CallExpr, bool) {
	if fn.Body == nil || len(fn.Body.List) != 3 {
		return nil, nil, nil, nil, false
	}
	start, ok := fn.Body.List[0].(*ast.AssignStmt)
	outer, ok1 := fn.Body.List[1].(*ast.TypeSwitchStmt)
	if !ok || !ok1 || len(start.Lhs) != 1 || len(start.Rhs) != 1 || len(outer.Body.List) != 2 {
		return nil, nil, nil, nil, false
	}
	doc, ok := outer.Body.List[0].(*ast.CaseClause)
	if !ok || len(doc.List) != 1 || len(doc.Body) != 1 {
		return nil, nil, nil, nil, false
	}
	inner, ok := doc.Body[0].(*ast.SwitchStmt)
	if !ok || inner.Tag != nil || len(inner.Body.List) != 3 {
		return nil, nil, nil, nil, false
	}
	branch, ok := inner.Body.List[1].(*ast.CaseClause)
	if !ok || len(branch.List) != 1 || len(branch.Body) != 1 {
		return nil, nil, nil, nil, false
	}
	ret, ok := branch.Body[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil, nil, nil, nil, false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 4 {
		return nil, nil, nil, nil, false
	}
	return start, outer, branch, call, true
}

func relationshipFrame(p *Program, d function) string {
	set := token.NewFileSet()
	f, e := parser.ParseFile(set, "relationship.go", "package relationship\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	start, _, branch, call, ok := relationshipShape(f.Decls[0].(*ast.FuncDecl))
	if !ok {
		return ""
	}
	start.Rhs[0] = &ast.Ident{Name: "_"}
	branch.List[0] = &ast.Ident{Name: "_"}
	call.Args[2] = &ast.Ident{Name: "_"}
	var b bytes.Buffer
	if format.Node(&b, set, f.Decls[0]) != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

func (p *Program) FragmentRelationshipAudit(root string) FragmentRelationshipAudit {
	a := FragmentRelationshipAudit{Root: root, Roles: map[string]string{}, Steps: []StateStep{}, Unknown: []string{}}
	if root != p.module+"/dereferencer.(*"+p.module+"/dereferencer.Dereferencer).fragment" {
		a.Unknown = append(a.Unknown, "unselected relationship root")
		return a
	}
	f := p.Find(root)
	if f == nil {
		a.Unknown = append(a.Unknown, "missing relationship root")
		return a
	}
	d := p.functions[f]
	start, outer, branch, call, ok := relationshipShape(d.node)
	if !ok {
		a.Unknown = append(a.Unknown, "unreviewed relationship structure")
		return a
	}
	info := d.unit.info
	sig := f.Type().(*types.Signature)
	if sig.Params().Len() != 3 {
		a.Unknown = append(a.Unknown, "unreviewed relationship parameter roles")
		return a
	}
	local, ok := start.Lhs[0].(*ast.Ident)
	field, ok1 := start.Rhs[0].(*ast.SelectorExpr)
	guard, ok2 := branch.List[0].(*ast.BinaryExpr)
	if !ok || !ok1 || !ok2 {
		a.Unknown = append(a.Unknown, "unreviewed option or guard expression")
		return a
	}
	if bareLocal(info, field.X) == nil || object(info, field) == nil || (guard.Op != token.NEQ && guard.Op != token.EQL) {
		a.Unknown = append(a.Unknown, "unsupported option receiver, field binding or comparison")
		return a
	}
	rel := info.Defs[local]
	opts := sig.Params().At(2)
	assign, ok := outer.Assign.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) != 1 || rel == nil {
		a.Unknown = append(a.Unknown, "missing relationship locals")
		return a
	}
	typed, ok := assign.Rhs[0].(*ast.TypeAssertExpr)
	if !ok || typed.Type != nil {
		a.Unknown = append(a.Unknown, "unreviewed resource type dispatch")
		return a
	}
	stream, ok := typed.X.(*ast.SelectorExpr)
	_, ok1 = assign.Lhs[0].(*ast.Ident)
	doc := outer.Body.List[0].(*ast.CaseClause)
	target, _ := object(info, call.Fun).(*types.Func)
	val := info.Types[guard.Y].Value
	if !ok || !ok1 || info.Implicits[outer.Body.List[0]] == nil || target == nil || val == nil || val.Kind() != constant.String || bareLocal(info, guard.X) == nil || bareLocal(info, call.Args[2]) == nil {
		a.Unknown = append(a.Unknown, "missing typed guard or call roles")
		return a
	}
	a.Frame = relationshipFrame(p, d)
	source := object(info, field.X) == opts && field.Sel.Name == "VerificationRelationship" && object(info, field) != nil
	document := object(info, stream.X) == sig.Params().At(1) && stream.Sel.Name == "ContentStream" && types.TypeString(info.TypeOf(doc.List[0]), nil) == "*"+p.module+"/document.Document"
	selected := document && source && guard.Op == token.NEQ && constant.StringVal(val) == "" && object(info, guard.X) == rel
	forwarded := source && object(info, call.Args[2]) == rel && Symbol(target) == p.module+"/dereferencer.verificationMethod" && object(info, call.Args[0]) == info.Implicits[doc]
	for name, obj := range map[string]types.Object{"options": opts, "relationship": rel, "content": info.Implicits[doc]} {
		a.Roles[name] = obj.Name() + " " + types.TypeString(obj.Type(), nil)
	}
	a.Steps = []StateStep{{Kind: "document-relationship-branch", Correct: selected, Expressions: []string{sourceExpression(p, typed), sourceExpression(p, doc.List[0]), sourceExpression(p, guard)}}, {Kind: "relationship-option-value", Correct: forwarded, Expressions: []string{sourceExpression(p, start.Rhs[0]), sourceExpression(p, call.Args[2])}}}
	return a
}
