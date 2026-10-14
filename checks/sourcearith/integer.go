package sourcearith

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
)

type Operation struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Operator string   `json:"operator"`
	Types    []string `json:"types"`
	Integer  bool     `json:"integer"`
}
type Audit struct {
	Root       string      `json:"root"`
	Functions  []string    `json:"functions"`
	Globals    []string    `json:"globals"`
	Operations []Operation `json:"operations"`
	Boundaries []string    `json:"boundaries"`
	Unknown    []string    `json:"unknown"`
}
type auditor struct {
	p          *Program
	out        Audit
	functions  map[*types.Func]bool
	globals    map[types.Object]bool
	boundaries map[string]bool
}

func integer(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsInteger != 0
}
func numeric(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsNumeric != 0
}
func arithmetic(op token.Token) bool {
	switch op {
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR:
		return true
	}
	return false
}
func comparison(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	}
	return false
}
func compound(op token.Token) bool {
	switch op {
	case token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN, token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN, token.AND_NOT_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN:
		return true
	}
	return false
}
func (a *auditor) operation(pos token.Pos, op string, ts ...types.Type) {
	at := a.p.set.Position(pos)
	v := Operation{File: at.Filename, Line: at.Line, Column: at.Column, Operator: op, Types: []string{}, Integer: true}
	for _, t := range ts {
		if t == nil {
			v.Types = append(v.Types, "missing")
			v.Integer = false
		} else {
			v.Types = append(v.Types, types.TypeString(t, nil))
			v.Integer = v.Integer && integer(t)
		}
	}
	a.out.Operations = append(a.out.Operations, v)
}
func (a *auditor) unknown(pos token.Pos, reason string) {
	at := a.p.set.Position(pos)
	a.out.Unknown = append(a.out.Unknown, fmt.Sprintf("%s:%d:%d: %s", at.Filename, at.Line, at.Column, reason))
}
func boundary(f *types.Func) bool {
	if f.Pkg() == nil {
		return false
	}
	pkg := f.Pkg().Path()
	sig := f.Type().(*types.Signature)
	if sig.Recv() == nil {
		return pkg == "fmt" && f.Name() == "Errorf" || pkg == "errors" && f.Name() == "New" || pkg == "strings" && f.Name() == "Repeat"
	}
	t := types.Unalias(sig.Recv().Type())
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || pkg != "strings" || named.Obj().Pkg().Path() != "strings" || named.Obj().Name() != "Builder" {
		return false
	}
	switch f.Name() {
	case "Grow", "WriteString", "WriteByte", "String":
		return true
	}
	return false
}
func (a *auditor) function(f *types.Func) {
	if a.functions[f] {
		return
	}
	a.functions[f] = true
	data, ok := a.p.functions[f]
	if !ok || data.node.Body == nil {
		a.unknown(f.Pos(), "unavailable function body "+Symbol(f))
		return
	}
	sig := f.Type().(*types.Signature)
	if sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 {
		a.unknown(f.Pos(), "unreviewed generic function "+Symbol(f))
		return
	}
	a.out.Functions = append(a.out.Functions, Symbol(f))
	a.walk(data.node.Body, data.unit)
}
func (a *auditor) global(obj types.Object, pos token.Pos) {
	if a.globals[obj] {
		return
	}
	a.globals[obj] = true
	data, ok := a.p.globals[obj]
	if !ok {
		a.unknown(pos, "unavailable global initializer "+obj.Name())
		return
	}
	if len(data.node.Values) == 0 {
		a.unknown(pos, "implicit global initializer "+obj.Name())
		return
	}
	if _, mutable := obj.(*types.Var); mutable {
		for _, file := range data.unit.files {
			for _, decl := range file.Decls {
				if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.VAR {
					for _, spec := range g.Specs {
						other := spec.(*ast.ValueSpec)
						if other != data.node && len(other.Values) > 0 {
							a.unknown(pos, "other package initializer may alter used global "+obj.Name())
							return
						}
					}
				}
				if f, ok := decl.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == "init" {
					a.unknown(pos, "package init may alter used global "+obj.Name())
					return
				}
			}
		}
	}
	a.out.Globals = append(a.out.Globals, obj.Pkg().Path()+"."+obj.Name())
	a.walk(data.node, data.unit)
}
func (a *auditor) call(c *ast.CallExpr, u *unit) {
	if tv, ok := u.info.Types[c.Fun]; ok && tv.IsType() {
		target, source := u.info.TypeOf(c), u.info.TypeOf(c.Args[0])
		if numeric(target) || numeric(source) {
			if numeric(target) && numeric(source) {
				a.operation(c.Pos(), "numeric-conversion", source, target)
			}
		}
		return
	}
	switch o := object(u.info, c.Fun).(type) {
	case *types.Builtin:
		switch o.Name() {
		case "len", "cap", "make", "append":
			a.boundaries["builtin."+o.Name()] = true
		default:
			a.unknown(c.Pos(), "unsupported builtin "+o.Name())
		}
	case *types.Func:
		if boundary(o) {
			if o.Pkg().Path() == "fmt" {
				for _, arg := range c.Args {
					if _, basic := types.Unalias(u.info.TypeOf(arg)).(*types.Basic); !basic {
						a.unknown(c.Pos(), "formatting may invoke an unreviewed method")
						return
					}
				}
			}
			a.boundaries[Symbol(o)] = true
		} else if _, ok := a.p.functions[o]; ok {
			a.function(o)
		} else {
			a.unknown(c.Pos(), "unreviewed external function "+Symbol(o))
		}
	default:
		a.unknown(c.Pos(), "indirect or unresolved call")
	}
}
func (a *auditor) walk(node ast.Node, u *unit) {
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		switch e := n.(type) {
		case *ast.BinaryExpr:
			x, y, z := u.info.TypeOf(e.X), u.info.TypeOf(e.Y), u.info.TypeOf(e)
			if arithmetic(e.Op) && (numeric(x) || numeric(y)) {
				a.operation(e.Pos(), e.Op.String(), x, y, z)
			} else if comparison(e.Op) && (numeric(x) || numeric(y)) {
				a.operation(e.Pos(), "compare-"+e.Op.String(), x, y)
			}
		case *ast.UnaryExpr:
			if e.Op == token.ADD || e.Op == token.SUB || e.Op == token.XOR {
				a.operation(e.Pos(), "unary-"+e.Op.String(), u.info.TypeOf(e.X), u.info.TypeOf(e))
			}
		case *ast.IncDecStmt:
			a.operation(e.Pos(), e.Tok.String(), u.info.TypeOf(e.X))
		case *ast.AssignStmt:
			if compound(e.Tok) && (numeric(u.info.TypeOf(e.Lhs[0])) || numeric(u.info.TypeOf(e.Rhs[0]))) {
				a.operation(e.Pos(), e.Tok.String(), u.info.TypeOf(e.Lhs[0]), u.info.TypeOf(e.Rhs[0]))
			}
		case *ast.CallExpr:
			a.call(e, u)
		case *ast.Ident:
			obj := u.info.Uses[e]
			switch obj.(type) {
			case *types.Var, *types.Const:
				if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
					a.global(obj, e.Pos())
				}
			}
		}
		return true
	})
}

// IntegerAudit includes statically reached helpers, used package initializers
// and argument expressions. Unknown calls/initializers cannot produce PASS.
// Integer types do not establish overflow safety, bounds or output equivalence.
func (p *Program) IntegerAudit(root string) Audit {
	a := auditor{p: p, out: Audit{Root: root, Functions: []string{}, Globals: []string{}, Operations: []Operation{}, Boundaries: []string{}, Unknown: []string{}}, functions: map[*types.Func]bool{}, globals: map[types.Object]bool{}, boundaries: map[string]bool{}}
	f := p.Find(root)
	if f == nil {
		a.out.Unknown = append(a.out.Unknown, "missing root "+root)
	} else {
		a.function(f)
	}
	for s := range a.boundaries {
		a.out.Boundaries = append(a.out.Boundaries, s)
	}
	sort.Strings(a.out.Functions)
	sort.Strings(a.out.Globals)
	sort.Strings(a.out.Boundaries)
	sort.Strings(a.out.Unknown)
	sort.Slice(a.out.Operations, func(i, j int) bool {
		x, y := a.out.Operations[i], a.out.Operations[j]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		return x.Column < y.Column
	})
	return a.out
}
