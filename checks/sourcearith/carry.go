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

// CarryStep records one typed source operation and its independently checked
// operand bindings. It is not a runtime trace or an overflow/bounds proof.
type CarryStep struct {
	Operation  Operation `json:"operation"`
	Expression string    `json:"expression"`
	Correct    bool      `json:"correct"`
}

// CarryAudit describes the three consecutive recurrence operations in one
// selected codec source loop. Other reference steps remain independent.
type CarryAudit struct {
	Root    string      `json:"root"`
	Frame   string      `json:"frame"`
	Base    string      `json:"base"`
	Carry   string      `json:"carry"`
	Buffer  string      `json:"buffer"`
	Index   string      `json:"index"`
	Steps   []CarryStep `json:"steps"`
	Unknown []string    `json:"unknown"`
}

// bareLocal excludes selectors (field symbols do not identify receivers),
// globals and unsupported aliases from this bounded storage proof.
func bareLocal(info *types.Info, e ast.Expr) *types.Var {
	id, ok := e.(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := info.Uses[id].(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
		return nil
	}
	return v
}
func roleInitializers(data function, loop *ast.ForStmt, carry, buffer *types.Var) bool {
	info := data.unit.info
	bufferFound := false
	for _, node := range data.node.Body.List {
		a, ok := node.(*ast.AssignStmt)
		if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			continue
		}
		id, ok := a.Lhs[0].(*ast.Ident)
		if !ok || info.Defs[id] != buffer {
			continue
		}
		call, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			continue
		}
		builtin, ok := object(info, call.Fun).(*types.Builtin)
		slice, typed := info.TypeOf(call).Underlying().(*types.Slice)
		bufferFound = ok && builtin.Name() == "make" && typed && integer(slice.Elem())
	}
	carryFound := false
	ast.Inspect(data.node.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, node := range block.List {
			if node != loop {
				continue
			}
			for _, prior := range block.List[:i] {
				a, ok := prior.(*ast.AssignStmt)
				if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
					continue
				}
				id, ok := a.Lhs[0].(*ast.Ident)
				if !ok || info.Defs[id] != carry {
					continue
				}
				switch rhs := a.Rhs[0].(type) {
				case *ast.CallExpr:
					carryFound = info.Types[rhs.Fun].IsType() && integer(info.TypeOf(rhs)) && len(rhs.Args) == 1
				case *ast.IndexExpr:
					_, nested := rhs.Index.(*ast.IndexExpr)
					carryFound = nested && integer(info.TypeOf(rhs))
				}
			}
		}
		return true
	})
	return carryFound && bufferFound
}
func sameObject(info *types.Info, x, y ast.Expr) bool {
	a, b := object(info, x), object(info, y)
	return a != nil && a == b
}
func constant256(info *types.Info, e ast.Expr) bool {
	v := info.Types[e].Value
	return v != nil && v.ExactString() == "256"
}
func baseObject(data function) types.Object {
	if len(data.node.Body.List) == 0 || data.node.Type.Params == nil || len(data.node.Type.Params.List) == 0 {
		return nil
	}
	a, ok := data.node.Body.List[0].(*ast.AssignStmt)
	if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
		return nil
	}
	call, ok := a.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil
	}
	b, ok := object(data.unit.info, call.Fun).(*types.Builtin)
	if !ok || b.Name() != "len" {
		return nil
	}
	var params []*ast.Ident
	for _, field := range data.node.Type.Params.List {
		params = append(params, field.Names...)
	}
	if len(params) != 2 {
		return nil
	}
	alphabet := data.unit.info.Defs[params[1]]
	if object(data.unit.info, call.Args[0]) != alphabet {
		return nil
	}
	id, ok := a.Lhs[0].(*ast.Ident)
	if !ok {
		return nil
	}
	return data.unit.info.Defs[id]
}

// recurrenceFrame retains the complete function context but removes only the
// three checked arithmetic statements in a cloned AST. A separately reviewed
// frame limits this analysis to known input/buffer/output roles and excludes
// decoys, shadowing, escapes and additional base assignments. The frame is not
// an arithmetic verdict: operand and operator controls are checked separately.
func recurrenceFrame(p *Program, data function) string {
	decl := sourceExpression(p, data.node)
	set := token.NewFileSet()
	clone, e := parser.ParseFile(set, "frame.go", "package frame\n"+decl, 0)
	if e != nil {
		return ""
	}
	count := 0
	ast.Inspect(clone, func(n ast.Node) bool {
		if loop, ok := n.(*ast.ForStmt); ok && len(loop.Body.List) == 4 {
			if _, ok := loop.Body.List[0].(*ast.AssignStmt); ok {
				count++
				loop.Body.List = append([]ast.Stmt{}, loop.Body.List[3:]...)
			}
		}
		return true
	})
	if count != 1 {
		return ""
	}
	var out bytes.Buffer
	if e := format.Node(&out, set, clone.Decls[0]); e != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(out.Bytes()))
}
func sourceExpression(p *Program, node ast.Node) string {
	var out bytes.Buffer
	_ = format.Node(&out, p.set, node)
	return out.String()
}

// CarryAudit checks local symbol identity, the alphabet-length base binding,
// current loop index, cell identity and arithmetic operation sequence. A shape
// outside this bounded analysis is unknown, never inferred from codec output.
func (p *Program) CarryAudit(root string) CarryAudit {
	out := CarryAudit{Root: root, Steps: []CarryStep{}, Unknown: []string{}}
	encode := root == p.module+"/internal/multiformats.BaseEncode"
	if !encode && root != p.module+"/internal/multiformats.BaseDecode" {
		out.Unknown = append(out.Unknown, "unselected recurrence root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing recurrence root")
		return out
	}
	data := p.functions[f]
	if data.node.Body == nil {
		out.Unknown = append(out.Unknown, "unavailable recurrence body")
		return out
	}
	out.Frame = recurrenceFrame(p, data)
	base := baseObject(data)
	if base == nil {
		out.Unknown = append(out.Unknown, "unproven alphabet-length base binding")
		return out
	}
	loops := []*ast.ForStmt{}
	ast.Inspect(data.node.Body, func(n ast.Node) bool {
		if loop, ok := n.(*ast.ForStmt); ok && len(loop.Body.List) == 4 {
			if _, ok := loop.Body.List[0].(*ast.AssignStmt); ok {
				loops = append(loops, loop)
			}
		}
		return true
	})
	if len(loops) != 1 {
		out.Unknown = append(out.Unknown, "ambiguous or unavailable recurrence loop")
		return out
	}
	loop := loops[0]
	a, ok1 := loop.Body.List[0].(*ast.AssignStmt)
	b, ok2 := loop.Body.List[1].(*ast.AssignStmt)
	c, ok3 := loop.Body.List[2].(*ast.AssignStmt)
	if !ok1 || !ok2 || !ok3 || len(a.Lhs) != 1 || len(a.Rhs) != 1 || len(b.Lhs) != 1 || len(b.Rhs) != 1 || len(c.Lhs) != 1 || len(c.Rhs) != 1 {
		out.Unknown = append(out.Unknown, "unreviewed recurrence statement shape")
		return out
	}
	mul, ok1 := a.Rhs[0].(*ast.BinaryExpr)
	cell, ok2 := b.Lhs[0].(*ast.IndexExpr)
	rem, ok3 := b.Rhs[0].(*ast.BinaryExpr)
	if !ok1 || !ok2 || !ok3 {
		out.Unknown = append(out.Unknown, "unreviewed recurrence expression shape")
		return out
	}
	read, ok := mul.Y.(*ast.IndexExpr)
	init, initOK := loop.Init.(*ast.AssignStmt)
	if !ok || !initOK || init.Tok != token.DEFINE || len(init.Lhs) != 1 || len(init.Rhs) != 1 {
		out.Unknown = append(out.Unknown, "unproven buffer or loop index binding")
		return out
	}
	index, ok := init.Lhs[0].(*ast.Ident)
	carry := bareLocal(data.unit.info, a.Lhs[0])
	buffer := bareLocal(data.unit.info, cell.X)
	var indexObj types.Object
	if ok {
		indexObj = data.unit.info.Defs[index]
	}
	if !ok || carry == nil || buffer == nil || indexObj == nil || carry == base || carry == buffer || carry == indexObj || base == indexObj || buffer.Parent() == buffer.Pkg().Scope() {
		out.Unknown = append(out.Unknown, "unproven local recurrence roles")
		return out
	}
	out.Base = base.Name()
	out.Carry = carry.Name()
	out.Buffer = buffer.Name()
	out.Index = indexObj.Name()
	info := data.unit.info
	if bareLocal(info, c.Lhs[0]) != carry || bareLocal(info, rem.X) != carry || bareLocal(info, read.X) != buffer || bareLocal(info, read.Index) != indexObj || bareLocal(info, cell.Index) != indexObj || !roleInitializers(data, loop, carry, buffer) {
		out.Unknown = append(out.Unknown, "unproven initializer/allocation or bare storage")
		return out
	}
	local := sameObject(info, a.Lhs[0], c.Lhs[0]) && sameObject(info, a.Lhs[0], rem.X)
	cellMatch := sameObject(info, read.X, cell.X) && object(info, read.Index) == indexObj && object(info, cell.Index) == indexObj
	if !local || !cellMatch {
		out.Unknown = append(out.Unknown, "unproven recurrence operand attribution")
		return out
	}
	if encode && (info.Types[mul.X].Value == nil || object(info, rem.Y) != base || object(info, c.Rhs[0]) != base) {
		out.Unknown = append(out.Unknown, "unsupported recurrence factor/divisor expression")
		return out
	}
	if !encode && (object(info, mul.X) != base || info.Types[rem.Y].Value == nil || info.Types[c.Rhs[0]].Value == nil) {
		out.Unknown = append(out.Unknown, "unsupported recurrence factor/divisor expression")
		return out
	}
	factor := constant256(info, mul.X)
	remainder := object(info, rem.Y) == base
	quotient := object(info, c.Rhs[0]) == base
	if !encode {
		factor = object(info, mul.X) == base
		remainder = constant256(info, rem.Y)
		quotient = constant256(info, c.Rhs[0])
	}
	recorder := auditor{p: p, out: Audit{Operations: []Operation{}}}
	recorder.operation(a.Pos(), a.Tok.String(), info.TypeOf(a.Lhs[0]), info.TypeOf(mul.X), info.TypeOf(read))
	recorder.operation(b.Pos(), rem.Op.String(), info.TypeOf(cell), info.TypeOf(rem.X), info.TypeOf(rem.Y))
	recorder.operation(c.Pos(), c.Tok.String(), info.TypeOf(c.Lhs[0]), info.TypeOf(c.Rhs[0]))
	correct := []bool{local && cellMatch && factor && a.Tok == token.ADD_ASSIGN && mul.Op == token.MUL, local && cellMatch && remainder && b.Tok == token.ASSIGN && rem.Op == token.REM, local && quotient && c.Tok == token.QUO_ASSIGN}
	for i, node := range []ast.Node{a, b, c} {
		out.Steps = append(out.Steps, CarryStep{Operation: recorder.out.Operations[i], Expression: sourceExpression(p, node), Correct: correct[i] && recorder.out.Operations[i].Integer})
	}
	return out
}
