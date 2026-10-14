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

// CursorAudit is a state projection from typed source, never a runtime trace.
type CursorAudit struct {
	Root       string            `json:"root"`
	Frame      string            `json:"frame"`
	Roles      map[string]string `json:"roles"`
	Projection []string          `json:"projection"`
	Scope      []string          `json:"scope"`
	Steps      []StateStep       `json:"steps"`
	Unknown    []string          `json:"unknown"`
}

func cursorFrame(p *Program, d function, encode bool) string {
	set := token.NewFileSet()
	clone, e := parser.ParseFile(set, "cursor.go", "package cursor\n"+sourceExpression(p, d.node), 0)
	if e != nil || len(clone.Decls) != 1 {
		return ""
	}
	fn, ok := clone.Decls[0].(*ast.FuncDecl)
	if !ok {
		return ""
	}
	shape, ok := codecStateShape(fn, encode)
	if !ok || !singleAssignment(shape.length) {
		return ""
	}
	if encode {
		shape.outer.(*ast.RangeStmt).X = &ast.Ident{Name: "_"}
		shape.length.Lhs = []ast.Expr{&ast.Ident{Name: "_"}}
		shape.length.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
		shape.length.Tok = token.ASSIGN
	} else {
		outer := shape.outer.(*ast.ForStmt)
		init, ok := outer.Init.(*ast.AssignStmt)
		if !ok || !singleAssignment(init) {
			return ""
		}
		init.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
		outer.Cond = &ast.Ident{Name: "_"}
		outer.Post = nil
	}
	var b bytes.Buffer
	if e := format.Node(&b, set, fn); e != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}

// prefixOffset identifies the actual input-prefix counter. It does not give
// an independent verdict for the complete leading-zero algorithm.
func prefixOffset(d function, input types.Object) *types.Var {
	info := d.unit.info
	for _, stmt := range d.node.Body.List {
		loop, ok := stmt.(*ast.ForStmt)
		if !ok || len(loop.Body.List) != 1 || loop.Init != nil || loop.Post != nil {
			continue
		}
		cond, ok := loop.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.LAND {
			continue
		}
		limit, ok := cond.X.(*ast.BinaryExpr)
		if !ok || limit.Op != token.LSS {
			continue
		}
		counter := bareLocal(info, limit.X)
		call, ok := limit.Y.(*ast.CallExpr)
		if !intVariable(counter) || !ok || len(call.Args) != 1 || object(info, call.Args[0]) != input {
			continue
		}
		builtin, ok := object(info, call.Fun).(*types.Builtin)
		if !ok || builtin.Name() != "len" {
			continue
		}
		update, ok := loop.Body.List[0].(*ast.IncDecStmt)
		if !ok || bareLocal(info, update.X) != counter || update.Tok != token.INC {
			continue
		}
		for _, prior := range d.node.Body.List {
			if prior == stmt {
				break
			}
			a, ok := prior.(*ast.AssignStmt)
			if ok && definedLocal(info, a) == counter && zeroConstant(info, a.Rhs[0]) {
				return counter
			}
		}
	}
	return nil
}
func (p *Program) CursorAudit(root string) CursorAudit {
	out := CursorAudit{Root: root, Roles: map[string]string{}, Projection: []string{}, Scope: []string{"fixed source and stable input; external concurrent mutation excluded", "normal completion; Go slice-range evaluation and iteration or Go for body/Post semantics"}, Steps: []StateStep{}, Unknown: []string{}}
	encode := root == p.module+"/internal/multiformats.BaseEncode"
	if !encode && root != p.module+"/internal/multiformats.BaseDecode" {
		out.Unknown = append(out.Unknown, "unselected cursor root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing cursor root")
		return out
	}
	d := p.functions[f]
	shape, ok := codecStateShape(d.node, encode)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed cursor shape")
		return out
	}
	// Reuse only typed role availability, not existing transition verdicts.
	state := p.StateAudit(root)
	if len(state.Unknown) != 0 {
		out.Unknown = append(out.Unknown, state.Unknown...)
		return out
	}
	out.Frame = cursorFrame(p, d, encode)
	out.Roles = state.Roles
	info := d.unit.info
	sig := f.Type().(*types.Signature)
	input := sig.Params().At(0)
	offset := prefixOffset(d, input)
	if offset == nil {
		out.Unknown = append(out.Unknown, "unproven input-prefix offset")
		return out
	}
	out.Roles["prefix_offset"] = fmt.Sprintf("%s %s @%s", offset.Name(), types.TypeString(offset.Type(), nil), p.set.Position(offset.Pos()))
	if encode {
		r := shape.outer.(*ast.RangeStmt)
		slice, ok := r.X.(*ast.SliceExpr)
		key, blank := r.Key.(*ast.Ident)
		value, defined := r.Value.(*ast.Ident)
		if !ok || !blank || key.Name != "_" || !defined || r.Tok != token.DEFINE || slice.Slice3 || slice.High != nil || slice.Max != nil || !intVariable(bareLocal(info, slice.Low)) || bareLocal(info, slice.X) == nil {
			out.Unknown = append(out.Unknown, "unreviewed slice-range projection")
			return out
		}
		b, ok := info.Defs[value].(*types.Var)
		if !ok || !types.Identical(b.Type(), types.Typ[types.Uint8]) {
			out.Unknown = append(out.Unknown, "unbound current range byte")
			return out
		}
		startCorrect := object(info, slice.X) == input && bareLocal(info, slice.Low) == offset
		start := bareLocal(info, slice.Low)
		out.Roles["range_start"] = fmt.Sprintf("%s %s @%s", start.Name(), types.TypeString(start.Type(), nil), p.set.Position(start.Pos()))
		out.Projection = []string{"slice header " + sourceExpression(p, r.X) + " is evaluated once; backing bytes are not copied", "for each k in the ranged slice, cursor=" + start.Name() + "+k and byte=data[cursor]", "normal body completion advances k to k+1; no materialized begin variable"}
		out.Steps = append(out.Steps, StateStep{"byte-range-from-prefix", []string{sourceExpression(p, r.X), sourceExpression(p, r.Value)}, startCorrect})
		counter := definedLocal(info, shape.counter)
		length := bareLocal(info, shape.length.Lhs[0])
		rhs := bareLocal(info, shape.length.Rhs[0])
		if !intVariable(counter) || !intVariable(length) || rhs == nil {
			out.Unknown = append(out.Unknown, "unreviewed length storage")
			return out
		}
		// The complete remaining body is part of the reviewed frame. It contains
		// no input writes, escapes, callbacks or control transfer between this
		// storage and normal range advancement. Caller data races are not proved.
		correct := shape.length.Tok == token.ASSIGN && rhs == counter
		out.Steps = append(out.Steps, StateStep{"length-and-virtual-source-advance", []string{sourceExpression(p, shape.length), "virtual cursor'=" + start.Name() + "+(k+1)"}, correct})
	} else {
		out.Scope = append(out.Scope, "valid ASCII standard-alphabet encoding; byte equals character")
		outer := shape.outer.(*ast.ForStmt)
		init, ok1 := outer.Init.(*ast.AssignStmt)
		cond, ok2 := outer.Cond.(*ast.BinaryExpr)
		post, ok3 := outer.Post.(*ast.IncDecStmt)
		if !ok1 || !ok2 || !ok3 || !singleAssignment(init) {
			out.Unknown = append(out.Unknown, "unreviewed explicit input cursor")
			return out
		}
		idx := definedLocal(info, init)
		call, ok := cond.Y.(*ast.CallExpr)
		if !intVariable(idx) || bareLocal(info, init.Rhs[0]) == nil || bareLocal(info, cond.X) == nil || !ok || len(call.Args) != 1 || bareLocal(info, call.Args[0]) == nil || bareLocal(info, post.X) == nil {
			out.Unknown = append(out.Unknown, "unreviewed explicit cursor operands")
			return out
		}
		builtin, ok := object(info, call.Fun).(*types.Builtin)
		if !ok || builtin.Name() != "len" {
			out.Unknown = append(out.Unknown, "unproven input length")
			return out
		}
		lookup := shape.carry.Rhs[0].(*ast.IndexExpr).Index.(*ast.IndexExpr)
		correct := bareLocal(info, init.Rhs[0]) == offset && bareLocal(info, cond.X) == idx && cond.Op == token.LSS && object(info, call.Args[0]) == input && bareLocal(info, post.X) == idx && post.Tok == token.INC && object(info, lookup.X) == input && bareLocal(info, lookup.Index) == idx
		out.Projection = []string{"expected relation: idx starts at the actual input-prefix offset", "expected relation: each normal iteration reads encoded[idx], then advances idx by one while idx<len(encoded)"}
		out.Steps = append(out.Steps, StateStep{"characters-from-prefix", []string{sourceExpression(p, init), sourceExpression(p, cond), sourceExpression(p, post), sourceExpression(p, lookup)}, correct})
	}
	return out
}
