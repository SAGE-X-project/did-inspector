package sourcearith

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
)

// PrefixAudit checks initialization and a leading-zero scan independently.
// Logical cursors are explicit projections, not materialized source variables.
type PrefixAudit struct {
	Root       string            `json:"root"`
	Frame      string            `json:"frame"`
	Roles      map[string]string `json:"roles"`
	Projection []string          `json:"projection"`
	Scope      []string          `json:"scope"`
	Steps      []StateStep       `json:"steps"`
	Unknown    []string          `json:"unknown"`
}
type prefixShape struct {
	scan         *ast.ForStmt
	zero, length *ast.AssignStmt
	offset       ast.Expr
}

func prefixStructure(fn *ast.FuncDecl, encode bool) (prefixShape, bool) {
	out := prefixShape{}
	shape, ok := codecStateShape(fn, encode)
	if !ok || !singleAssignment(shape.length) {
		return out, false
	}
	if encode {
		r := shape.outer.(*ast.RangeStmt)
		slice, ok := r.X.(*ast.SliceExpr)
		if !ok || slice.Slice3 || slice.High != nil || slice.Max != nil {
			return out, false
		}
		out.offset = slice.Low
	} else {
		init, ok := shape.outer.(*ast.ForStmt).Init.(*ast.AssignStmt)
		if !ok || !singleAssignment(init) {
			return out, false
		}
		out.offset = init.Rhs[0]
	}
	// Fixed context later establishes the exact declaration/scan order. The
	// structural selection itself cannot authorize arbitrary intervening code.
	for i, stmt := range fn.Body.List {
		if stmt == shape.outer {
			break
		}
		loop, ok := stmt.(*ast.ForStmt)
		if !ok || loop.Init != nil || loop.Post != nil || len(loop.Body.List) != 1 || i == 0 {
			continue
		}
		init, ok := fn.Body.List[i-1].(*ast.AssignStmt)
		if !ok || !singleAssignment(init) || out.scan != nil {
			return out, false
		}
		out.zero, out.scan = init, loop
	}
	for i, stmt := range fn.Body.List {
		if stmt == shape.outer {
			if i == 0 {
				return out, false
			}
			out.length, _ = fn.Body.List[i-1].(*ast.AssignStmt)
			break
		}
	}
	return out, out.scan != nil && out.length != nil && singleAssignment(out.length)
}
func prefixFrame(p *Program, d function, encode bool) string {
	set := token.NewFileSet()
	file, e := parser.ParseFile(set, "prefix.go", "package prefix\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	fn, ok := file.Decls[0].(*ast.FuncDecl)
	if !ok {
		return ""
	}
	shape, ok := prefixStructure(fn, encode)
	if !ok {
		return ""
	}
	shape.zero.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	shape.length.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	shape.scan.Cond = &ast.Ident{Name: "_"}
	shape.scan.Body.List = []ast.Stmt{&ast.EmptyStmt{}}
	state, _ := codecStateShape(fn, encode)
	if encode {
		state.outer.(*ast.RangeStmt).X.(*ast.SliceExpr).Low = &ast.Ident{Name: "_"}
	} else {
		state.outer.(*ast.ForStmt).Init.(*ast.AssignStmt).Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	}
	var b bytes.Buffer
	if e := format.Node(&b, set, fn); e != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

// firstLengthRead proves the delayed pure initializer precedes every use of
// its actual storage object; the unchanged frame supplies the intervening path.
func firstLengthRead(p *Program, d function, init *ast.AssignStmt, length *types.Var) (string, bool) {
	first := token.NoPos
	ast.Inspect(d.node.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && d.unit.info.Uses[id] == length && (first == token.NoPos || id.Pos() < first) {
			first = id.Pos()
		}
		return true
	})
	if first == token.NoPos || first <= init.End() {
		return "", false
	}
	return p.set.Position(first).String(), true
}
func inputLoopEnd(p *Program, d function, encode bool, input types.Object) (string, bool) {
	shape, ok := codecStateShape(d.node, encode)
	if !ok {
		return "", false
	}
	if encode {
		slice, ok := shape.outer.(*ast.RangeStmt).X.(*ast.SliceExpr)
		if !ok || slice.High != nil || slice.Slice3 || object(d.unit.info, slice.X) != input {
			return "", false
		}
		return "len(" + sourceExpression(p, slice.X) + ") (implicit upper bound)", true
	}
	loop := shape.outer.(*ast.ForStmt)
	cond, ok := loop.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.LSS {
		return "", false
	}
	call, ok := cond.Y.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || object(d.unit.info, call.Args[0]) != input {
		return "", false
	}
	builtin, ok := object(d.unit.info, call.Fun).(*types.Builtin)
	if !ok || builtin.Name() != "len" {
		return "", false
	}
	return sourceExpression(p, call), true
}
func (p *Program) PrefixAudit(root string) PrefixAudit {
	out := PrefixAudit{Root: root, Roles: map[string]string{}, Projection: []string{}, Scope: []string{"fixed source, stable input, normal completion; external input mutation excluded", "logical cursor and length projection across declaration order; not a runtime trace or complete codec equivalence"}, Steps: []StateStep{}, Unknown: []string{}}
	encode := root == p.module+"/internal/multiformats.BaseEncode"
	if !encode && root != p.module+"/internal/multiformats.BaseDecode" {
		out.Unknown = append(out.Unknown, "unselected prefix root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing prefix root")
		return out
	}
	d := p.functions[f]
	shape, ok := prefixStructure(d.node, encode)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed prefix structure")
		return out
	}
	info := d.unit.info
	zero, length := definedLocal(info, shape.zero), definedLocal(info, shape.length)
	if !intVariable(zero) || !intVariable(length) || zero == length || info.Types[shape.zero.Rhs[0]].Value == nil || info.Types[shape.length.Rhs[0]].Value == nil || !integer(info.TypeOf(shape.zero.Rhs[0])) || !integer(info.TypeOf(shape.length.Rhs[0])) {
		out.Unknown = append(out.Unknown, "unreviewed prefix initialization")
		return out
	}
	sig := f.Type().(*types.Signature)
	input, alphabet := sig.Params().At(0), sig.Params().At(1)
	state, _ := codecStateShape(d.node, encode)
	first, phase := firstLengthRead(p, d, shape.length, length)
	end, endBound := inputLoopEnd(p, d, encode, input)
	if !phase || !endBound || !singleAssignment(state.length) || bareLocal(info, state.length.Lhs[0]) != length {
		out.Unknown = append(out.Unknown, "unproven delayed length storage/input end")
		return out
	}

	cond, ok := shape.scan.Cond.(*ast.BinaryExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed prefix condition")
		return out
	}
	limit, ok1 := cond.X.(*ast.BinaryExpr)
	value, ok2 := cond.Y.(*ast.BinaryExpr)
	update, ok3 := shape.scan.Body.List[0].(*ast.IncDecStmt)
	if !ok1 || !ok2 || !ok3 {
		out.Unknown = append(out.Unknown, "unreviewed prefix guard/update")
		return out
	}
	count := bareLocal(info, limit.X)
	call, ok := limit.Y.(*ast.CallExpr)
	current, okCurrent := value.X.(*ast.IndexExpr)
	if !intVariable(count) || !ok || len(call.Args) != 1 || bareLocal(info, call.Args[0]) == nil || !okCurrent || bareLocal(info, current.X) == nil || bareLocal(info, current.Index) == nil || bareLocal(info, update.X) == nil || bareLocal(info, shape.offset) == nil {
		out.Unknown = append(out.Unknown, "unreviewed prefix operands")
		return out
	}
	builtin, ok := object(info, call.Fun).(*types.Builtin)
	if !ok || builtin.Name() != "len" {
		out.Unknown = append(out.Unknown, "unproven prefix length")
		return out
	}
	symbolCorrect := false
	if encode {
		if info.Types[value.Y].Value == nil || !integer(info.TypeOf(value.Y)) {
			out.Unknown = append(out.Unknown, "unreviewed zero byte")
			return out
		}
		symbolCorrect = zeroConstant(info, value.Y)
	} else {
		out.Scope = append(out.Scope, "distinct standard ASCII alphabets selected by real z/u public codec paths; bytes equal characters")
		if !p.asciiSelector() {
			out.Unknown = append(out.Unknown, "unproven ASCII alphabet selector")
			return out
		}
		symbol, ok := value.Y.(*ast.IndexExpr)
		if !ok || bareLocal(info, symbol.X) == nil || info.Types[symbol.Index].Value == nil || !integer(info.TypeOf(symbol.Index)) {
			out.Unknown = append(out.Unknown, "unreviewed first alphabet symbol")
			return out
		}
		symbolCorrect = object(info, symbol.X) == alphabet && zeroConstant(info, symbol.Index)
	}
	out.Frame = prefixFrame(p, d, encode)
	role := func(name string, v types.Object) {
		out.Roles[name] = fmt.Sprintf("%s %s @%s", v.Name(), types.TypeString(v.Type(), nil), p.set.Position(v.Pos()))
	}
	role("input", input)
	role("alphabet", alphabet)
	role("prefix_count", zero)
	role("length", length)
	out.Roles["first_length_use"] = first
	out.Roles["input_end"] = end
	role("source_offset", bareLocal(info, shape.offset))
	initialZero := zeroConstant(info, shape.zero.Rhs[0])
	initialCorrect := initialZero && zeroConstant(info, shape.length.Rhs[0])
	countCorrect := initialZero && count == zero && object(info, call.Args[0]) == input && cond.Op == token.LAND && limit.Op == token.LSS && value.Op == token.EQL && object(info, current.X) == input && bareLocal(info, current.Index) == zero && bareLocal(info, update.X) == zero && update.Tok == token.INC && symbolCorrect && bareLocal(info, shape.offset) == zero
	out.Projection = []string{"expected relation: logical source cursor starts at zero and equals prefix_count while scanning; no separate begin/sourceOffset storage", "expected relation: logical end is len(input), supplied by the Go slice range or explicit input-loop bound", "expected relation: length is logically zero before its materialized declaration, with no earlier reads; normal declaration completion realizes that value", "expected relation: 0<=prefix_count<=len(input), every input[j] for j<prefix_count is the zero symbol (byte 0 or first alphabet character); at normal scan completion count=len(input) or input[count] is not that symbol"}
	out.Steps = []StateStep{{"initial-zero-state", []string{sourceExpression(p, shape.zero), sourceExpression(p, shape.length), "logical cursor=0; logical end=" + end, "delayed zero initializer before first storage use @" + first}, initialCorrect}, {"leading-zero-count-and-offset", []string{sourceExpression(p, shape.scan.Cond), sourceExpression(p, update), sourceExpression(p, shape.offset)}, countCorrect}}
	return out
}
