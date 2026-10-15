package sourcearith

import (
	"context"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"runtime"
	"sort"
	"strings"
)

type unit struct {
	pkg   *types.Package
	info  *types.Info
	files []*ast.File
}
type function struct {
	node *ast.FuncDecl
	unit *unit
}
type initializer struct {
	node *ast.ValueSpec
	unit *unit
}

// Program holds independent standard Go parser/type-checker results.
type Program struct {
	ctx       context.Context
	module    string
	set       *token.FileSet
	source    map[string][]byte
	standard  types.Importer
	units     map[string]*unit
	loading   map[string]bool
	functions map[*types.Func]function
	globals   map[types.Object]initializer
}

func NewProgram(ctx context.Context, module string, source map[string][]byte) *Program {
	set := token.NewFileSet()
	return &Program{ctx: ctx, module: module, set: set, source: source, standard: importer.ForCompiler(set, "source", nil), units: map[string]*unit{}, loading: map[string]bool{}, functions: map[*types.Func]function{}, globals: map[types.Object]initializer{}}
}
func (p *Program) Import(name string) (*types.Package, error) {
	if e := p.ctx.Err(); e != nil {
		return nil, e
	}
	if u := p.units[name]; u != nil {
		return u.pkg, nil
	}
	if !strings.HasPrefix(name, p.module+"/") {
		return p.standard.Import(name)
	}
	if p.loading[name] {
		return nil, fmt.Errorf("source import cycle %s", name)
	}
	p.loading[name] = true
	defer delete(p.loading, name)
	dir := strings.TrimPrefix(name, p.module+"/")
	names := []string{}
	for file := range p.source {
		if path.Dir(file) == dir {
			names = append(names, file)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("missing source package %s", name)
	}
	files := []*ast.File{}
	for _, file := range names {
		f, e := parser.ParseFile(p.set, file, p.source[file], 0)
		if e != nil {
			return nil, e
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}, Implicits: map[ast.Node]types.Object{}}
	cfg := types.Config{Importer: p, GoVersion: "go1.26", Sizes: types.SizesFor("gc", runtime.GOARCH)}
	pkg, e := cfg.Check(name, p.set, files, info)
	if e != nil {
		return nil, e
	}
	if e = p.ctx.Err(); e != nil {
		return nil, e
	}
	u := &unit{pkg, info, files}
	p.units[name] = u
	for _, f := range files {
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if obj, ok := info.Defs[decl.Name].(*types.Func); ok {
					p.functions[obj] = function{decl, u}
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok {
						for _, name := range value.Names {
							if obj := info.Defs[name]; obj != nil {
								p.globals[obj] = initializer{value, u}
							}
						}
					}
				}
			}
		}
	}
	return pkg, nil
}
func Symbol(f *types.Func) string {
	name := f.Pkg().Path() + "." + f.Name()
	sig := f.Type().(*types.Signature)
	if sig.Recv() != nil {
		name = f.Pkg().Path() + ".(" + types.TypeString(sig.Recv().Type(), nil) + ")." + f.Name()
	}
	return name
}
func object(info *types.Info, expression ast.Expr) types.Object {
	switch e := expression.(type) {
	case *ast.Ident:
		return info.Uses[e]
	case *ast.SelectorExpr:
		return info.Uses[e.Sel]
	case *ast.ParenExpr:
		return object(info, e.X)
	}
	return nil
}
func (p *Program) Find(symbol string) *types.Func {
	for f := range p.functions {
		if Symbol(f) == symbol {
			return f
		}
	}
	return nil
}

// Calls proves a direct statically resolved symbol edge, including import aliases.
// A string-matched or indirect function call is not a proven edge.
func (p *Program) Calls(from, to string) bool {
	f := p.Find(from)
	target := p.Find(to)
	if f == nil || target == nil {
		return false
	}
	data := p.functions[f]
	found := false
	ast.Inspect(data.node.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && object(data.unit.info, c.Fun) == target {
			found = true
		}
		return true
	})
	return found
}
