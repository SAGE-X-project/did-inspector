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

// StateStep is a bounded source transition, not an execution trace.
type StateStep struct {
	Kind        string   `json:"kind"`
	Expressions []string `json:"expressions"`
	Correct     bool     `json:"correct"`
}

// StateAudit keeps source context separate from each transition predicate.
type StateAudit struct {
	Root    string            `json:"root"`
	Frame   string            `json:"frame"`
	Roles   map[string]string `json:"roles"`
	Scope   []string          `json:"scope"`
	Steps   []StateStep       `json:"steps"`
	Unknown []string          `json:"unknown"`
}
type codecState struct {
	outer                  ast.Stmt
	body                   *ast.BlockStmt
	inner                  *ast.ForStmt
	carry, counter, length *ast.AssignStmt
}

func codecStateShape(fn *ast.FuncDecl, encode bool) (codecState, bool) {
	var out codecState
	if fn.Body == nil {
		return out, false
	}
	count := 0
	for _, stmt := range fn.Body.List {
		var body *ast.BlockStmt
		if encode {
			if r, ok := stmt.(*ast.RangeStmt); ok {
				body = r.Body
			}
		} else {
			if f, ok := stmt.(*ast.ForStmt); ok {
				body = f.Body
			}
		}
		if body == nil {
			continue
		}
		for i, node := range body.List {
			loop, ok := node.(*ast.ForStmt)
			if !ok || len(loop.Body.List) != 4 || i < 2 || i+1 != len(body.List)-1 {
				continue
			}
			carry, ok1 := body.List[0].(*ast.AssignStmt)
			counter, ok2 := body.List[i-1].(*ast.AssignStmt)
			length, ok3 := body.List[i+1].(*ast.AssignStmt)
			if !ok1 || !ok2 || !ok3 {
				continue
			}
			count++
			out = codecState{stmt, body, loop, carry, counter, length}
		}
	}
	return out, count == 1
}
func singleAssignment(a *ast.AssignStmt) bool { return len(a.Lhs) == 1 && len(a.Rhs) == 1 }
func definedLocal(info *types.Info, a *ast.AssignStmt) *types.Var {
	if !singleAssignment(a) || a.Tok != token.DEFINE {
		return nil
	}
	id, ok := a.Lhs[0].(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := info.Defs[id].(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
		return nil
	}
	return v
}
func intVariable(v *types.Var) bool {
	return v != nil && types.Identical(v.Type(), types.Typ[types.Int])
}
func zeroConstant(info *types.Info, e ast.Expr) bool {
	v := info.Types[e].Value
	return v != nil && v.ExactString() == "0"
}

// stateFrame removes only the checked transitions from a clone. Everything
// else, including guards, input roles and absence of control transfers, must
// match separately reviewed context before the profile can give a verdict.
func stateFrame(p *Program, data function, encode bool) string {
	set := token.NewFileSet()
	clone, e := parser.ParseFile(set, "state.go", "package state\n"+sourceExpression(p, data.node), 0)
	if e != nil {
		return ""
	}
	fn, ok := clone.Decls[0].(*ast.FuncDecl)
	if !ok {
		return ""
	}
	shape, ok := codecStateShape(fn, encode)
	if !ok || !singleAssignment(shape.carry) || !singleAssignment(shape.length) {
		return ""
	}
	shape.carry.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	shape.inner.Post = nil
	shape.inner.Body.List = shape.inner.Body.List[:3]
	if !encode {
		shape.length.Lhs = []ast.Expr{&ast.Ident{Name: "_"}}
		shape.length.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
		shape.length.Tok = token.ASSIGN
		shape.outer.(*ast.ForStmt).Post = nil
		// The alphabet store is checked independently; preserve its loop context.
		for _, stmt := range fn.Body.List {
			loop, ok := stmt.(*ast.ForStmt)
			if !ok || len(loop.Body.List) != 1 {
				continue
			}
			a, ok := loop.Body.List[0].(*ast.AssignStmt)
			if !ok || !singleAssignment(a) {
				continue
			}
			cell, ok := a.Lhs[0].(*ast.IndexExpr)
			if !ok {
				continue
			}
			if _, ok := cell.Index.(*ast.IndexExpr); !ok {
				continue
			}
			a.Lhs = []ast.Expr{&ast.Ident{Name: "_"}}
			a.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
			a.Tok = token.ASSIGN
		}
	}
	var b bytes.Buffer
	if e := format.Node(&b, set, fn); e != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

// asciiSelector binds the literal standard alphabets to the real selector
// and the selected Base calls. The proof excludes arbitrary Unicode alphabets.
func (p *Program) asciiSelector() bool {
	selector := p.Find(p.module + "/internal/multiformats.alphabetFor")
	if selector == nil {
		return false
	}
	d := p.functions[selector]
	info := d.unit.info
	if d.node.Body == nil || len(d.node.Body.List) != 2 || d.node.Type.Params == nil || len(d.node.Type.Params.List) != 1 || len(d.node.Type.Params.List[0].Names) != 1 {
		return false
	}
	sw, ok := d.node.Body.List[0].(*ast.SwitchStmt)
	if !ok || sw.Init != nil || object(info, sw.Tag) != info.Defs[d.node.Type.Params.List[0].Names[0]] || len(sw.Body.List) != 2 {
		return false
	}
	end, ok := d.node.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(end.Results) != 1 || info.Types[end.Results[0]].Value == nil || info.Types[end.Results[0]].Value.Kind() != constant.String || constant.StringVal(info.Types[end.Results[0]].Value) != "" {
		return false
	}
	want := map[string]string{"122": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "117": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"}
	for _, node := range sw.Body.List {
		c, ok := node.(*ast.CaseClause)
		if !ok || len(c.List) != 1 || len(c.Body) != 1 {
			return false
		}
		ret, ok := c.Body[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return false
		}
		tag, value := info.Types[c.List[0]].Value, info.Types[ret.Results[0]].Value
		if tag == nil || value == nil || value.Kind() != constant.String || want[tag.ExactString()] != constant.StringVal(value) {
			return false
		}
		delete(want, tag.ExactString())
	}
	if len(want) != 0 {
		return false
	}
	for _, name := range []string{"Encode", "Decode"} {
		f := p.Find(p.module + "/internal/multiformats." + name + "Multibase")
		base := p.Find(p.module + "/internal/multiformats.Base" + name)
		if f == nil || base == nil {
			return false
		}
		data := p.functions[f]
		if data.node.Body == nil {
			return false
		}
		bound := map[types.Object]bool{}
		calls := 0
		writes := map[types.Object]int{}
		escaped := false
		ast.Inspect(data.node.Body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok && singleAssignment(a) && a.Tok == token.DEFINE {
				if call, ok := a.Rhs[0].(*ast.CallExpr); ok && object(data.unit.info, call.Fun) == selector {
					if v := definedLocal(data.unit.info, a); v != nil {
						bound[v] = true
					}
				}
			}
			if a, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					var v types.Object
					if id, ok := lhs.(*ast.Ident); ok {
						v = data.unit.info.Defs[id]
						if v == nil {
							v = data.unit.info.Uses[id]
						}
					}
					if bound[v] {
						writes[v]++
					}
				}
			}
			if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND && bound[object(data.unit.info, u.X)] {
				escaped = true
			}
			if call, ok := n.(*ast.CallExpr); ok && object(data.unit.info, call.Fun) == base && len(call.Args) == 2 && bound[object(data.unit.info, call.Args[1])] {
				calls++
			}
			return true
		})
		for v := range bound {
			if writes[v] != 1 {
				escaped = true
			}
		}
		if calls != 1 || escaped {
			return false
		}
	}
	return true
}

func (p *Program) StateAudit(root string) StateAudit {
	out := StateAudit{Root: root, Roles: map[string]string{}, Scope: []string{"fixed source; normal loop completion; Go for body then Post semantics"}, Steps: []StateStep{}, Unknown: []string{}}
	encode := root == p.module+"/internal/multiformats.BaseEncode"
	if !encode && root != p.module+"/internal/multiformats.BaseDecode" {
		out.Unknown = append(out.Unknown, "unselected state root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing state root")
		return out
	}
	data := p.functions[f]
	shape, ok := codecStateShape(data.node, encode)
	if !ok || !singleAssignment(shape.carry) || !singleAssignment(shape.counter) || !singleAssignment(shape.length) {
		out.Unknown = append(out.Unknown, "unreviewed state shape")
		return out
	}
	out.Frame = stateFrame(p, data, encode)
	info := data.unit.info
	carry, counter := definedLocal(info, shape.carry), definedLocal(info, shape.counter)
	init, ok := shape.inner.Init.(*ast.AssignStmt)
	if !ok {
		out.Unknown = append(out.Unknown, "missing inner index initializer")
		return out
	}
	pos := definedLocal(info, init)
	length := bareLocal(info, shape.length.Lhs[0])
	if !intVariable(carry) || !intVariable(counter) || !intVariable(pos) || !intVariable(length) || carry == counter || carry == pos || counter == pos || counter == length || !zeroConstant(info, shape.counter.Rhs[0]) {
		out.Unknown = append(out.Unknown, "unproven local state roles")
		return out
	}
	// Tie roles to the real recurrence and its guard, not merely shared names.
	first, ok1 := shape.inner.Body.List[0].(*ast.AssignStmt)
	guard, ok2 := shape.inner.Cond.(*ast.BinaryExpr)
	if !ok1 || !singleAssignment(first) || bareLocal(info, first.Lhs[0]) != carry || !ok2 {
		out.Unknown = append(out.Unknown, "unproven recurrence state")
		return out
	}
	disj, ok := guard.X.(*ast.ParenExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed counter guard")
		return out
	}
	condition, ok := disj.X.(*ast.BinaryExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed state condition")
		return out
	}
	countTest, ok := condition.Y.(*ast.BinaryExpr)
	if !ok || bareLocal(info, countTest.X) != counter || bareLocal(info, countTest.Y) != length {
		out.Unknown = append(out.Unknown, "unbound length/counter guard")
		return out
	}
	sig := f.Type().(*types.Signature)
	if sig.Params().Len() != 2 {
		out.Unknown = append(out.Unknown, "unreviewed state parameters")
		return out
	}
	input, alphabet := sig.Params().At(0), sig.Params().At(1)
	role := func(name string, v types.Object) {
		out.Roles[name] = fmt.Sprintf("%s %s @%s", v.Name(), types.TypeString(v.Type(), nil), p.set.Position(v.Pos()))
	}
	role("carry", carry)
	role("counter", counter)
	role("buffer_offset", pos)
	role("decoded_length", length)
	role("input", input)
	role("alphabet", alphabet)
	var initCorrect bool
	var cursor *types.Var
	if encode {
		r := shape.outer.(*ast.RangeStmt)
		slice, ok := r.X.(*ast.SliceExpr)
		value, defined := r.Value.(*ast.Ident)
		call, conversion := shape.carry.Rhs[0].(*ast.CallExpr)
		if !ok || !defined || !conversion || len(call.Args) != 1 || !info.Types[call.Fun].IsType() || !types.Identical(info.TypeOf(call), types.Typ[types.Int]) {
			out.Unknown = append(out.Unknown, "unreviewed byte carry conversion")
			return out
		}
		b, ok := info.Defs[value].(*types.Var)
		if !ok || !types.Identical(b.Type(), types.Typ[types.Uint8]) || object(info, slice.X) != input {
			out.Unknown = append(out.Unknown, "unbound range byte/input")
			return out
		}
		if bareLocal(info, call.Args[0]) == nil {
			out.Unknown = append(out.Unknown, "unreviewed byte carry operand")
			return out
		}
		role("range_byte", b)
		initCorrect = object(info, call.Args[0]) == b
	} else {
		out.Scope = append(out.Scope, "distinct ASCII alphabets selected by z/u public codec paths; byte equals character")
		if !p.asciiSelector() {
			out.Unknown = append(out.Unknown, "unproven standard ASCII selector")
			return out
		}
		outer := shape.outer.(*ast.ForStmt)
		a, ok := outer.Init.(*ast.AssignStmt)
		if !ok {
			out.Unknown = append(out.Unknown, "unreviewed source cursor")
			return out
		}
		cursor = definedLocal(info, a)
		lookup, ok := shape.carry.Rhs[0].(*ast.IndexExpr)
		if !ok || !intVariable(cursor) {
			out.Unknown = append(out.Unknown, "unreviewed carry lookup")
			return out
		}
		current, ok := lookup.Index.(*ast.IndexExpr)
		values := bareLocal(info, lookup.X)
		if !ok || values == nil || bareLocal(info, current.Index) == nil || bareLocal(info, current.X) == nil {
			out.Unknown = append(out.Unknown, "unbound alphabet/current byte")
			return out
		}
		role("source_cursor", cursor)
		role("alphabet_map", values)
		array, ok := values.Type().Underlying().(*types.Array)
		if !ok || array.Len() != 256 || !types.Identical(array.Elem(), types.Typ[types.Int]) {
			out.Unknown = append(out.Unknown, "unreviewed local alphabet map")
			return out
		}
		mapCorrect, mapExprs, known := p.alphabetMap(data, values, alphabet)
		if !known {
			out.Unknown = append(out.Unknown, "unproven alphabet map storage")
			return out
		}
		out.Steps = append(out.Steps, StateStep{"alphabet-map", mapExprs, mapCorrect})
		initCorrect = object(info, current.X) == input && bareLocal(info, current.Index) == cursor
	}
	out.Steps = append(out.Steps, StateStep{"carry-initialization", []string{sourceExpression(p, shape.carry)}, initCorrect})
	bodyUpdate, ok1 := shape.inner.Body.List[3].(*ast.IncDecStmt)
	post, ok2 := shape.inner.Post.(*ast.IncDecStmt)
	if !ok1 || !ok2 || bareLocal(info, bodyUpdate.X) == nil || bareLocal(info, post.X) == nil {
		out.Unknown = append(out.Unknown, "unreviewed counter/index updates")
		return out
	}
	updateCorrect := bareLocal(info, bodyUpdate.X) == counter && bodyUpdate.Tok == token.INC && bareLocal(info, post.X) == pos && post.Tok == token.DEC
	out.Steps = append(out.Steps, StateStep{"inner-state-advance", []string{sourceExpression(p, bodyUpdate), sourceExpression(p, post)}, updateCorrect})
	if !encode {
		post, ok := shape.outer.(*ast.ForStmt).Post.(*ast.IncDecStmt)
		if !ok || bareLocal(info, post.X) == nil {
			out.Unknown = append(out.Unknown, "unreviewed source cursor update")
			return out
		}
		if bareLocal(info, shape.length.Rhs[0]) == nil {
			out.Unknown = append(out.Unknown, "unreviewed length operand")
			return out
		}
		correct := shape.length.Tok == token.ASSIGN && bareLocal(info, shape.length.Rhs[0]) == counter && bareLocal(info, post.X) == cursor && post.Tok == token.INC
		out.Steps = append(out.Steps, StateStep{"length-and-source-advance", []string{sourceExpression(p, shape.length), sourceExpression(p, post)}, correct})
	}
	return out
}

func (p *Program) alphabetMap(data function, values *types.Var, alphabet types.Object) (bool, []string, bool) {
	info := data.unit.info
	expressions := []string{}
	sentinel := false
	mapping := false
	correct := false
	for _, stmt := range data.node.Body.List {
		if r, ok := stmt.(*ast.RangeStmt); ok && object(info, r.X) == values && len(r.Body.List) == 1 {
			a, ok := r.Body.List[0].(*ast.AssignStmt)
			key, defined := r.Key.(*ast.Ident)
			if !ok || !singleAssignment(a) || !defined {
				continue
			}
			cell, indexed := a.Lhs[0].(*ast.IndexExpr)
			if indexed && bareLocal(info, cell.X) == values && object(info, cell.Index) == info.Defs[key] && info.Types[a.Rhs[0]].Value != nil && info.Types[a.Rhs[0]].Value.ExactString() == "-1" && a.Tok == token.ASSIGN {
				sentinel = true
				expressions = append(expressions, sourceExpression(p, r))
			}
		}
		loop, ok := stmt.(*ast.ForStmt)
		if !ok || len(loop.Body.List) != 1 {
			continue
		}
		a, ok := loop.Body.List[0].(*ast.AssignStmt)
		if !ok || !singleAssignment(a) {
			continue
		}
		cell, ok := a.Lhs[0].(*ast.IndexExpr)
		if !ok || bareLocal(info, cell.X) != values {
			continue
		}
		character, ok := cell.Index.(*ast.IndexExpr)
		if !ok {
			continue
		}
		init, ok1 := loop.Init.(*ast.AssignStmt)
		cond, ok2 := loop.Cond.(*ast.BinaryExpr)
		post, ok3 := loop.Post.(*ast.IncDecStmt)
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		i := definedLocal(info, init)
		if !intVariable(i) || !zeroConstant(info, init.Rhs[0]) || bareLocal(info, cond.X) != i || cond.Op != token.LSS || object(info, cond.Y) != baseObject(data) || bareLocal(info, post.X) != i || post.Tok != token.INC {
			continue
		}
		if bareLocal(info, character.X) == nil || bareLocal(info, character.Index) == nil || bareLocal(info, a.Rhs[0]) == nil {
			continue
		}
		mapping = true
		correct = a.Tok == token.ASSIGN && object(info, character.X) == alphabet && bareLocal(info, character.Index) == i && bareLocal(info, a.Rhs[0]) == i
		expressions = append(expressions, sourceExpression(p, loop))
	}
	return sentinel && correct, expressions, sentinel && mapping
}
