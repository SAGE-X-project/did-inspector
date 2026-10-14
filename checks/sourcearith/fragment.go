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

// FragmentAudit binds a selected canonical identifier, fragment construction,
// and returned search result. It does not certify recursive search coverage.
type FragmentAudit struct {
	Root      string            `json:"root"`
	CallPaths [][]string        `json:"call_paths"`
	Frames    map[string]string `json:"frames"`
	Roles     map[string]string `json:"roles"`
	Scope     []string          `json:"scope"`
	Steps     []StateStep       `json:"steps"`
	Unknown   []string          `json:"unknown"`
}

func fragmentShape(fn *ast.FuncDecl) (*ast.AssignStmt, *ast.AssignStmt, *ast.KeyValueExpr, bool) {
	if fn.Body == nil || len(fn.Body.List) != 5 {
		return nil, nil, nil, false
	}
	start, ok := fn.Body.List[0].(*ast.AssignStmt)
	found, ok1 := fn.Body.List[2].(*ast.AssignStmt)
	result, ok2 := fn.Body.List[4].(*ast.ReturnStmt)
	if !ok || !ok1 || !ok2 || len(start.Lhs) != 2 || len(start.Rhs) != 2 || len(found.Lhs) != 2 || len(found.Rhs) != 1 || len(result.Results) != 1 {
		return nil, nil, nil, false
	}
	composite, ok := result.Results[0].(*ast.CompositeLit)
	if !ok {
		return nil, nil, nil, false
	}
	for _, elt := range composite.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, nil, nil, false
		}
		key, ok := kv.Key.(*ast.Ident)
		if ok && key.Name == "ContentStream" {
			return start, found, kv, true
		}
	}
	return nil, nil, nil, false
}

func fragmentFrame(p *Program, d function) string {
	set := token.NewFileSet()
	f, e := parser.ParseFile(set, "fragment.go", "package fragment\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	fn := f.Decls[0].(*ast.FuncDecl)
	start, _, payload, ok := fragmentShape(fn)
	if !ok {
		return ""
	}
	start.Rhs[0] = &ast.Ident{Name: "_"}
	payload.Value = &ast.Ident{Name: "_"}
	var b bytes.Buffer
	if format.Node(&b, set, fn) != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

// FragmentAudit uses typed receiver and local bindings. Exact source-context
// fingerprints are prerequisites in the profile, never a predicate oracle.
func (p *Program) FragmentAudit(root string) FragmentAudit {
	out := FragmentAudit{Root: root, Frames: map[string]string{}, Roles: map[string]string{}, Scope: []string{
		"fixed source, stable non-nil typed document, fragment-bearing document branch without verificationRelationship",
		"Document.ID and DID.String/IsZero, DIDURL.Fragment, caller routing, search callback and error-envelope source are explicit reviewed prerequisites",
		"selected identifier construction and exact returned search result; null initialization and every-map recursion remain unjudged",
		"not public authority, all media types, whole algorithm equivalence or runtime/binary attestation",
	}, Steps: []StateStep{}, Unknown: []string{}, CallPaths: [][]string{}}
	if root != p.module+"/dereferencer.resolveFragment" {
		out.Unknown = append(out.Unknown, "unselected fragment root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing fragment root")
		return out
	}
	d := p.functions[f]
	start, found, payload, ok := fragmentShape(d.node)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed fragment structure")
		return out
	}
	info := d.unit.info
	sig := f.Type().(*types.Signature)
	if sig.Params().Len() != 3 {
		out.Unknown = append(out.Unknown, "unreviewed fragment parameter roles")
		return out
	}
	doc, frag := sig.Params().At(0), sig.Params().At(1)
	fullID, ok := start.Lhs[0].(*ast.Ident)
	resultID, ok1 := found.Lhs[0].(*ast.Ident)
	if !ok || !ok1 {
		out.Unknown = append(out.Unknown, "unreviewed fragment locals")
		return out
	}
	full, result := info.Defs[fullID], info.Defs[resultID]
	if full == nil || result == nil {
		out.Unknown = append(out.Unknown, "missing fragment local bindings")
		return out
	}
	out.Frames[root] = fragmentFrame(p, d)
	// Preserve all caller/helper prerequisites, including getter implementation
	// bytes. Generic component matches do not attest a public runtime trace.
	for fn, unit := range p.functions {
		path, name := fn.Pkg().Path(), fn.Name()
		selected := path == p.module+"/dereferencer" && (name == "Dereference" || name == "fragment" || name == "findFragment" || name == "findMap" || name == "failed") || path == p.module+"/document" && name == "ID" || path == p.module+"/did" && (name == "String" || name == "IsZero" || name == "Fragment" || name == "HasFragment" || name == "Method" || name == "MSID")
		if path == p.module+"/resolution" && name == "ErrorDereferenceResult" {
			selected = true
		}
		if selected {
			out.Frames[Symbol(fn)] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, unit.node))))
		}
	}
	var entry, branch string
	for fn := range p.functions {
		if fn.Pkg().Path() == p.module+"/dereferencer" {
			if fn.Name() == "Dereference" {
				entry = Symbol(fn)
			}
			if fn.Name() == "fragment" {
				branch = Symbol(fn)
			}
		}
	}
	for _, edge := range [][]string{{entry, branch}, {branch, root}, {root, p.module + "/dereferencer.findFragment"}} {
		if !p.Calls(edge[0], edge[1]) {
			out.Unknown = append(out.Unknown, "unproven fragment symbol edge")
			return out
		}
		out.CallPaths = append(out.CallPaths, edge)
	}
	outer, ok := start.Rhs[0].(*ast.BinaryExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed full fragment construction")
		return out
	}
	inner, ok := outer.X.(*ast.BinaryExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed canonical prefix construction")
		return out
	}
	str, ok := inner.X.(*ast.CallExpr)
	if !ok || len(str.Args) != 0 {
		out.Unknown = append(out.Unknown, "unreviewed canonical string call")
		return out
	}
	strSel, ok := str.Fun.(*ast.SelectorExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed canonical string receiver")
		return out
	}
	id, ok := strSel.X.(*ast.CallExpr)
	if !ok || len(id.Args) != 0 {
		out.Unknown = append(out.Unknown, "unreviewed document identifier call")
		return out
	}
	idSel, ok := id.Fun.(*ast.SelectorExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed document identifier receiver")
		return out
	}
	stringFn, _ := object(info, str.Fun).(*types.Func)
	idFn, _ := object(info, id.Fun).(*types.Func)
	if stringFn == nil || idFn == nil {
		out.Unknown = append(out.Unknown, "missing canonical method symbols")
		return out
	}
	idSymbol, stringSymbol := Symbol(idFn), Symbol(stringFn)
	prefix := p.module + "/did.(" + p.module + "/did.DID)."
	if object(info, idSel.X) == nil || idSymbol != p.module+"/document.(*"+p.module+"/document.Document).ID" || (stringSymbol != prefix+"String" && stringSymbol != prefix+"Method" && stringSymbol != prefix+"MSID") {
		out.Unknown = append(out.Unknown, "unreviewed canonical accessor")
		return out
	}
	switch payload.Value.(type) {
	case *ast.Ident, *ast.CompositeLit:
	default:
		out.Unknown = append(out.Unknown, "unreviewed return transformation")
		return out
	}
	canonical := object(info, idSel.X) == doc && Symbol(idFn) == p.module+"/document.(*"+p.module+"/document.Document).ID" && Symbol(stringFn) == p.module+"/did.("+p.module+"/did.DID).String"
	delimiter := info.Types[inner.Y].Value
	if delimiter == nil || delimiter.Kind() != constant.String {
		out.Unknown = append(out.Unknown, "unreviewed fragment delimiter")
		return out
	}
	if bareLocal(info, outer.Y) == nil {
		out.Unknown = append(out.Unknown, "unreviewed fragment operand expression")
		return out
	}
	qualified := canonical && inner.Op == token.ADD && outer.Op == token.ADD && constant.StringVal(delimiter) == "#" && object(info, outer.Y) == frag
	for name, obj := range map[string]types.Object{"document": doc, "fragment": frag, "fully_qualified": full, "found": result} {
		out.Roles[name] = fmt.Sprintf("%s %s @%s", obj.Name(), types.TypeString(obj.Type(), nil), p.set.Position(obj.Pos()))
	}
	out.Steps = append(out.Steps, StateStep{Kind: "canonical-document-id", Correct: canonical, Expressions: []string{sourceExpression(p, id), sourceExpression(p, str)}}, StateStep{Kind: "fully-qualified-fragment", Correct: qualified, Expressions: []string{sourceExpression(p, start.Rhs[0])}}, StateStep{Kind: "return-search-result", Correct: object(info, payload.Value) == result, Expressions: []string{sourceExpression(p, found.Rhs[0]), sourceExpression(p, payload.Value)}})
	return out
}
