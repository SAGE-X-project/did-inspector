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

// guardFrame masks only the initializer values and condition under inspection.
// The retained allocation, recurrence and updates establish reviewed context;
// the hash is a prerequisite, never a guard verdict.
func guardFrame(p *Program, d function, encode bool) string {
	set := token.NewFileSet()
	file, e := parser.ParseFile(set, "guard.go", "package guard\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	fn := file.Decls[0].(*ast.FuncDecl)
	s, ok := codecStateShape(fn, encode)
	if !ok || !singleAssignment(s.counter) {
		return ""
	}
	init, ok := s.inner.Init.(*ast.AssignStmt)
	if !ok || !singleAssignment(init) {
		return ""
	}
	s.counter.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	init.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	s.inner.Cond = &ast.Ident{Name: "_"}
	var b bytes.Buffer
	if e := format.Node(&b, set, fn); e != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

// allocatedSize binds the recurrence buffer to make([]int, size). Only normal
// allocation completion gives len(buffer)=size>=0. The size formula, resource
// availability and sufficient capacity are separate obligations.
func allocatedSize(d function, buffer *types.Var) *types.Var {
	if buffer == nil {
		return nil
	}
	for _, node := range d.node.Body.List {
		a, ok := node.(*ast.AssignStmt)
		if !ok || definedLocal(d.unit.info, a) != buffer {
			continue
		}
		call, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return nil
		}
		builtin, ok := object(d.unit.info, call.Fun).(*types.Builtin)
		slice, typed := d.unit.info.TypeOf(call).Underlying().(*types.Slice)
		if !ok || builtin.Name() != "make" || !typed || !types.Identical(slice.Elem(), types.Typ[types.Int]) {
			return nil
		}
		size := bareLocal(d.unit.info, call.Args[1])
		if !intVariable(size) {
			return nil
		}
		return size
	}
	return nil
}

// GuardAudit independently checks both inner-loop initializers and the guard.
// pos>=0 projects to pos!=-1 on the reviewed descending path only: successful
// allocation gives size>=0; pos starts at size-1 and decrements once per normal
// body completion. A negative start is -1 and is never entered.
func (p *Program) GuardAudit(root string) StateAudit {
	out := StateAudit{Root: root, Roles: map[string]string{}, Scope: []string{"fixed source, stable input, successful allocation and normal iteration completion", "expected relation: size=len(actual recurrence buffer)>=0 after make completion; initial pos=size-1>=-1 and i=0", "expected relation: on the unchanged body i++/Post pos-- path, pos>=0 is equivalent to pos!=-1; -1 stops before another decrement", "size formula, sufficient capacity, global termination, arbitrary input mutation and runtime/binary attestation are separate"}, Steps: []StateStep{}, Unknown: []string{}}
	encode := root == p.module+"/internal/multiformats.BaseEncode"
	if !encode && root != p.module+"/internal/multiformats.BaseDecode" {
		out.Unknown = append(out.Unknown, "unselected guard root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing guard root")
		return out
	}
	d := p.functions[f]
	s, ok := codecStateShape(d.node, encode)
	if !ok || !singleAssignment(s.carry) || !singleAssignment(s.counter) || !singleAssignment(s.length) {
		out.Unknown = append(out.Unknown, "unreviewed guard structure")
		return out
	}
	info := d.unit.info
	init, ok := s.inner.Init.(*ast.AssignStmt)
	if !ok || !singleAssignment(init) {
		out.Unknown = append(out.Unknown, "unreviewed guard initialization")
		return out
	}
	carry, counter, pos := definedLocal(info, s.carry), definedLocal(info, s.counter), definedLocal(info, init)
	length := bareLocal(info, s.length.Lhs[0])
	store, ok := s.inner.Body.List[1].(*ast.AssignStmt)
	if !ok || !singleAssignment(store) {
		out.Unknown = append(out.Unknown, "unreviewed guard buffer store")
		return out
	}
	cell, ok := store.Lhs[0].(*ast.IndexExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed guard buffer cell")
		return out
	}
	buffer := bareLocal(info, cell.X)
	size := allocatedSize(d, buffer)
	if !intVariable(carry) || !intVariable(counter) || !intVariable(pos) || !intVariable(length) || !intVariable(size) || carry == counter || carry == pos || counter == pos || length == counter || length == pos || size == pos || size == counter || size == carry || size == length || bareLocal(info, cell.Index) != pos {
		out.Unknown = append(out.Unknown, "unproven distinct local guard roles")
		return out
	}
	start, ok := init.Rhs[0].(*ast.BinaryExpr)
	cond, ok1 := s.inner.Cond.(*ast.BinaryExpr)
	if !ok || !ok1 {
		out.Unknown = append(out.Unknown, "unreviewed guard expression")
		return out
	}
	group, ok := cond.X.(*ast.ParenExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed guard grouping")
		return out
	}
	choice, ok := group.X.(*ast.BinaryExpr)
	bound, ok1 := cond.Y.(*ast.BinaryExpr)
	if !ok || !ok1 {
		out.Unknown = append(out.Unknown, "unreviewed guard conjunction")
		return out
	}
	nonzero, ok := choice.X.(*ast.BinaryExpr)
	prior, ok1 := choice.Y.(*ast.BinaryExpr)
	if !ok || !ok1 {
		out.Unknown = append(out.Unknown, "unreviewed guard alternatives")
		return out
	}
	post, ok := s.inner.Post.(*ast.IncDecStmt)
	inc, ok1 := s.inner.Body.List[3].(*ast.IncDecStmt)
	if !ok || !ok1 {
		out.Unknown = append(out.Unknown, "unreviewed descending path")
		return out
	}
	for _, e := range []ast.Expr{s.counter.Rhs[0], start.Y, nonzero.Y, bound.Y} {
		if info.Types[e].Value == nil || !integer(info.TypeOf(e)) {
			out.Unknown = append(out.Unknown, "unreviewed guard constant")
			return out
		}
	}
	for _, e := range []ast.Expr{start.X, nonzero.X, prior.X, prior.Y, bound.X, post.X, inc.X, s.length.Rhs[0]} {
		if !intVariable(bareLocal(info, e)) {
			out.Unknown = append(out.Unknown, "unreviewed guard operand")
			return out
		}
	}
	out.Frame = guardFrame(p, d, encode)
	for name, v := range map[string]*types.Var{"carry": carry, "counter": counter, "position": pos, "length": length, "size": size, "buffer": buffer} {
		out.Roles[name] = fmt.Sprintf("%s %s @%s", v.Name(), types.TypeString(v.Type(), nil), p.set.Position(v.Pos()))
	}
	startCorrect := (start.Op == token.SUB && info.Types[start.Y].Value.ExactString() == "1") || (start.Op == token.ADD && info.Types[start.Y].Value.ExactString() == "-1")
	boundCorrect := (bound.Op == token.GEQ && zeroConstant(info, bound.Y)) || ((bound.Op == token.NEQ || bound.Op == token.GTR) && info.Types[bound.Y].Value.ExactString() == "-1")
	correct := zeroConstant(info, s.counter.Rhs[0]) && startCorrect && bareLocal(info, start.X) == size && cond.Op == token.LAND && choice.Op == token.LOR && nonzero.Op == token.NEQ && bareLocal(info, nonzero.X) == carry && zeroConstant(info, nonzero.Y) && prior.Op == token.LSS && bareLocal(info, prior.X) == counter && bareLocal(info, prior.Y) == length && boundCorrect && bareLocal(info, bound.X) == pos && post.Tok == token.DEC && bareLocal(info, post.X) == pos && inc.Tok == token.INC && bareLocal(info, inc.X) == counter && bareLocal(info, s.length.Rhs[0]) == counter
	out.Steps = []StateStep{{"inner-initialization-and-guard", []string{sourceExpression(p, s.counter), sourceExpression(p, init), sourceExpression(p, s.inner.Cond), sourceExpression(p, inc), sourceExpression(p, post)}, correct}}
	return out
}
