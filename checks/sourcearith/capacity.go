package sourcearith

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
)

// CapacityAudit is a fixed-source allocation proof for the selected u/64
// component, not the public z Multikey actor or whole codec equivalence.
type CapacityAudit struct {
	Frames      map[string]string `json:"frames"`
	Expressions []string          `json:"expressions"`
	Steps       []StateStep       `json:"steps"`
	Unknown     []string          `json:"unknown"`
}

// capacityShape selects only the two previously reviewed allocation phases.
func capacityShape(f *ast.FuncDecl, encode bool) (*ast.AssignStmt, *ast.AssignStmt, bool) {
	i := 7
	if encode {
		i = 4
	}
	if f.Body == nil || len(f.Body.List) <= i+1 {
		return nil, nil, false
	}
	size, ok := f.Body.List[i].(*ast.AssignStmt)
	store, ok1 := f.Body.List[i+1].(*ast.AssignStmt)
	return size, store, ok && ok1 && singleAssignment(size) && singleAssignment(store)
}

func (p *Program) CapacityAudit() CapacityAudit {
	a := CapacityAudit{Frames: map[string]string{}, Expressions: []string{}, Steps: []StateStep{}, Unknown: []string{}}
	prefix := p.module + "/internal/multiformats."
	if !p.asciiSelector() {
		a.Unknown = append(a.Unknown, "unbound unique u/64 ASCII alphabet and Base argument")
		return a
	}
	for _, name := range []string{"BaseEncode", "BaseDecode", "expansion", "ceilLog2", "floorLog2", "alphabetFor", "EncodeMultibase", "DecodeMultibase"} {
		fn := p.Find(prefix + name)
		if fn == nil {
			a.Unknown = append(a.Unknown, "missing capacity function: "+name)
			return a
		}
		d := p.functions[fn]
		text := sourceExpression(p, d.node)
		clone, err := parser.ParseFile(token.NewFileSet(), "capacity.go", "package capacity\n"+text, 0)
		if err != nil {
			a.Unknown = append(a.Unknown, "invalid capacity frame")
			return a
		}
		f := clone.Decls[0].(*ast.FuncDecl)
		if name == "BaseEncode" || name == "BaseDecode" {
			size, _, ok := capacityShape(f, name == "BaseEncode")
			if !ok {
				a.Unknown = append(a.Unknown, "unreviewed capacity shape")
				return a
			}
			size.Rhs[0] = ast.NewIdent("_")
		}
		if name == "expansion" {
			if f.Body == nil || len(f.Body.List) != 1 {
				a.Unknown = append(a.Unknown, "unreviewed expansion body")
				return a
			}
			ret, ok := f.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				a.Unknown = append(a.Unknown, "unreviewed expansion return")
				return a
			}
			ret.Results[0] = ast.NewIdent("_")
		}
		a.Frames[name] = fmt.Sprintf("%x", sha256.Sum256([]byte(sourceExpression(p, f))))
	}
	helper := p.functions[p.Find(prefix+"expansion")]
	sig := p.Find(prefix + "expansion").Type().(*types.Signature)
	// Exact expression comparison is restricted by typed parameter/helper binding
	// and a separately reviewed surrounding frame. Unknown alternatives are ERROR.
	if sig.Params().Len() != 3 {
		a.Unknown = append(a.Unknown, "unbound expansion parameters")
		return a
	}
	ret := helper.node.Body.List[0].(*ast.ReturnStmt)
	expression := sourceExpression(p, ret.Results[0])
	a.Expressions = append(a.Expressions, expression)
	formula := expression == "n*ceilLog2(from)/floorLog2(to) + 1"
	for _, edge := range [][2]string{{"expansion", "ceilLog2"}, {"expansion", "floorLog2"}, {"EncodeMultibase", "BaseEncode"}, {"DecodeMultibase", "BaseDecode"}, {"EncodeMultibase", "alphabetFor"}, {"DecodeMultibase", "alphabetFor"}} {
		if !p.Calls(prefix+edge[0], prefix+edge[1]) {
			a.Unknown = append(a.Unknown, "unbound capacity call path")
			return a
		}
	}
	for _, name := range []string{"BaseEncode", "BaseDecode"} {
		d := p.functions[p.Find(prefix+name)]
		encode := name == "BaseEncode"
		size, store, ok := capacityShape(d.node, encode)
		if !ok {
			a.Unknown = append(a.Unknown, "unreviewed typed capacity shape")
			return a
		}
		info := d.unit.info
		sizeLocal := definedLocal(info, size)
		storage := definedLocal(info, store)
		call, ok := size.Rhs[0].(*ast.CallExpr)
		allocation, ok1 := store.Rhs[0].(*ast.CallExpr)
		if !ok || !ok1 || len(call.Args) != 3 || len(allocation.Args) != 2 || !intVariable(sizeLocal) || storage == nil {
			a.Unknown = append(a.Unknown, "unbound allocation roles")
			return a
		}
		builtin, ok := object(info, allocation.Fun).(*types.Builtin)
		slice, ok1 := info.TypeOf(allocation).Underlying().(*types.Slice)
		if !ok || builtin.Name() != "make" || !ok1 || !integer(slice.Elem()) || object(info, allocation.Args[1]) != sizeLocal {
			a.Unknown = append(a.Unknown, "unbound zero-initialized allocation")
			return a
		}
		want := "expansion(len(encoded)-zeroes, base, 256)"
		if encode {
			want = "expansion(len(data)-zeroes, 256, base)"
		}
		expr := sourceExpression(p, call)
		a.Expressions = append(a.Expressions, expr, sourceExpression(p, store))
		target, _ := object(info, call.Fun).(*types.Func)
		a.Steps = append(a.Steps, StateStep{Kind: name + "-u64-capacity", Correct: formula && target == p.Find(prefix+"expansion") && expr == want, Expressions: []string{expression, expr, sourceExpression(p, store)}})
	}
	return a
}
