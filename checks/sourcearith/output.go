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

// OutputAudit projects selected output operations, not complete codec behavior.
type OutputAudit struct {
	Root       string            `json:"root"`
	Frame      string            `json:"frame"`
	Roles      map[string]string `json:"roles"`
	Scope      []string          `json:"scope"`
	Projection []string          `json:"projection"`
	Steps      []StateStep       `json:"steps"`
	Unknown    []string          `json:"unknown"`
}
type outputShape struct {
	position     *ast.AssignStmt
	scan, suffix *ast.ForStmt
	prefix       *ast.ExprStmt
	allocation   *ast.AssignStmt
	result       *ast.ReturnStmt
}

func outputStructure(fn *ast.FuncDecl, encode bool) (outputShape, bool) {
	var s outputShape
	if fn.Body == nil || len(fn.Body.List) < 7 {
		return s, false
	}
	list := fn.Body.List
	n := len(list)
	s.result, _ = list[n-1].(*ast.ReturnStmt)
	s.suffix, _ = list[n-2].(*ast.ForStmt)
	if encode {
		s.prefix, _ = list[n-3].(*ast.ExprStmt)
		s.scan, _ = list[n-6].(*ast.ForStmt)
		s.position, _ = list[n-7].(*ast.AssignStmt)
	} else {
		s.allocation, _ = list[n-3].(*ast.AssignStmt)
		s.scan, _ = list[n-4].(*ast.ForStmt)
		s.position, _ = list[n-5].(*ast.AssignStmt)
	}
	return s, s.result != nil && len(s.result.Results) == 2 && s.suffix != nil && s.suffix.Body != nil && len(s.suffix.Body.List) == 1 && s.position != nil && singleAssignment(s.position) && s.scan != nil && s.scan.Body != nil && len(s.scan.Body.List) == 1 && (encode && s.prefix != nil || !encode && s.allocation != nil && singleAssignment(s.allocation))
}

// outputFrame retains previous phases and removes only the inspected output
// operations. Decode's suffix is retained as a prerequisite for final length;
// the disputed destination offset clause is not judged here.
func outputFrame(p *Program, d function, encode bool) string {
	set := token.NewFileSet()
	file, e := parser.ParseFile(set, "output.go", "package output\n"+sourceExpression(p, d.node), 0)
	if e != nil {
		return ""
	}
	fn := file.Decls[0].(*ast.FuncDecl)
	s, ok := outputStructure(fn, encode)
	if !ok {
		return ""
	}
	if encode {
		s.prefix.X = &ast.Ident{Name: "_"}
		s.suffix.Cond = &ast.Ident{Name: "_"}
		s.suffix.Post = nil
		s.suffix.Body.List = []ast.Stmt{&ast.EmptyStmt{}}
		s.result.Results[0] = &ast.Ident{Name: "_"}
	} else {
		s.position.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
		s.scan.Cond = &ast.Ident{Name: "_"}
		s.scan.Body.List = []ast.Stmt{&ast.EmptyStmt{}}
		s.allocation.Rhs = []ast.Expr{&ast.Ident{Name: "_"}}
	}
	var b bytes.Buffer
	if e := format.Node(&b, set, fn); e != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}
func builderReceiver(d function, call *ast.CallExpr) (*types.Var, *types.Func) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}
	receiver := bareLocal(d.unit.info, sel.X)
	f, ok := object(d.unit.info, call.Fun).(*types.Func)
	if receiver == nil || !ok || !boundary(f) || f.Type().(*types.Signature).Recv() == nil {
		return nil, nil
	}
	named, ok := types.Unalias(receiver.Type()).(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "strings" || named.Obj().Name() != "Builder" {
		return nil, nil
	}
	return receiver, f
}

// outputLengthDomain proves the preceding local counter bound from source
// facts, without consulting a previous audit verdict. Reviewed context excludes
// extra writes/control transfers between these actual statements.
func outputLengthDomain(d function, state codecState, size, length *types.Var) bool {
	info := d.unit.info
	init, ok := state.inner.Init.(*ast.AssignStmt)
	if !ok || !singleAssignment(init) {
		return false
	}
	position := definedLocal(info, init)
	counter := definedLocal(info, state.counter)
	start, ok := init.Rhs[0].(*ast.BinaryExpr)
	cond, ok1 := state.inner.Cond.(*ast.BinaryExpr)
	if !ok || !ok1 || !intVariable(position) || !intVariable(counter) || position == counter || position == size || counter == length || !zeroConstant(info, state.counter.Rhs[0]) {
		return false
	}
	bound, ok := cond.Y.(*ast.BinaryExpr)
	post, ok1 := state.inner.Post.(*ast.IncDecStmt)
	inc, ok2 := state.inner.Body.List[3].(*ast.IncDecStmt)
	if !ok || !ok1 || !ok2 || start.Op != token.SUB || bareLocal(info, start.X) != size || info.Types[start.Y].Value == nil || info.Types[start.Y].Value.ExactString() != "1" || cond.Op != token.LAND || bound.Op != token.GEQ || bareLocal(info, bound.X) != position || !zeroConstant(info, bound.Y) || post.Tok != token.DEC || bareLocal(info, post.X) != position || inc.Tok != token.INC || bareLocal(info, inc.X) != counter || bareLocal(info, state.length.Rhs[0]) != counter {
		return false
	}
	for _, node := range d.node.Body.List {
		a, ok := node.(*ast.AssignStmt)
		if ok && definedLocal(info, a) == length {
			return zeroConstant(info, a.Rhs[0])
		}
	}
	return false
}
func (p *Program) OutputAudit(root string) OutputAudit {
	out := OutputAudit{Root: root, Roles: map[string]string{}, Scope: []string{"fixed source, standard ASCII z/u alphabets, stable input, normal completion", "reviewed preceding phases and standard Go make/append and strings.Builder/Repeat semantics are explicit boundaries", "not complete codec equivalence, capacity formula, global termination or runtime/binary attestation"}, Projection: []string{}, Steps: []StateStep{}, Unknown: []string{}}
	encode := root == p.module+"/internal/multiformats.BaseEncode"
	if !encode && root != p.module+"/internal/multiformats.BaseDecode" {
		out.Unknown = append(out.Unknown, "unselected output root")
		return out
	}
	f := p.Find(root)
	if f == nil {
		out.Unknown = append(out.Unknown, "missing output root")
		return out
	}
	d := p.functions[f]
	s, ok := outputStructure(d.node, encode)
	state, ok1 := codecStateShape(d.node, encode)
	if !ok || !ok1 || !singleAssignment(state.length) {
		out.Unknown = append(out.Unknown, "unreviewed output structure")
		return out
	}
	info := d.unit.info
	pos := definedLocal(info, s.position)
	length := bareLocal(info, state.length.Lhs[0])
	store, ok := state.inner.Body.List[1].(*ast.AssignStmt)
	if !ok || !singleAssignment(store) {
		out.Unknown = append(out.Unknown, "unproven output buffer store")
		return out
	}
	cell, ok := store.Lhs[0].(*ast.IndexExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unproven output buffer cell")
		return out
	}
	buffer := bareLocal(info, cell.X)
	size := allocatedSize(d, buffer)
	input := f.Type().(*types.Signature).Params().At(0)
	alphabet := f.Type().(*types.Signature).Params().At(1)
	zero := prefixOffset(d, input)
	if !intVariable(pos) || !intVariable(length) || !intVariable(size) || !intVariable(zero) || pos == size || pos == length || pos == zero || !p.asciiSelector() {
		out.Unknown = append(out.Unknown, "unproven output roles/ASCII selector")
		return out
	}
	if !outputLengthDomain(d, state, size, length) {
		out.Unknown = append(out.Unknown, "unproven preceding length bound")
		return out
	}
	out.Frame = outputFrame(p, d, encode)
	for name, v := range map[string]types.Object{"position": pos, "length": length, "size": size, "zeroes": zero, "buffer": buffer, "alphabet": alphabet} {
		out.Roles[name] = fmt.Sprintf("%s %s @%s", v.Name(), types.TypeString(v.Type(), nil), p.set.Position(v.Pos()))
	}
	if encode {
		p.encodeOutput(d, s, pos, size, zero, buffer, alphabet, &out)
	} else {
		p.decodeOutput(d, s, pos, size, length, zero, buffer, &out)
	}
	return out
}
func (p *Program) encodeOutput(d function, s outputShape, pos, size, zero, buffer *types.Var, alphabet types.Object, out *OutputAudit) {
	info := d.unit.info
	prefix, ok := s.prefix.X.(*ast.CallExpr)
	if !ok || len(prefix.Args) != 1 {
		out.Unknown = append(out.Unknown, "unreviewed prefix builder call")
		return
	}
	builder, method := builderReceiver(d, prefix)
	repeat, ok := prefix.Args[0].(*ast.CallExpr)
	if builder == nil || !ok || len(repeat.Args) != 2 {
		out.Unknown = append(out.Unknown, "unproven prefix builder/repeat")
		return
	}
	repeatFn, ok := object(info, repeat.Fun).(*types.Func)
	slice, ok1 := repeat.Args[0].(*ast.SliceExpr)
	if !ok || repeatFn.Pkg() == nil || repeatFn.Pkg().Path() != "strings" || repeatFn.Name() != "Repeat" || repeatFn.Type().(*types.Signature).Recv() != nil || !ok1 || slice.Slice3 || slice.Low != nil || info.Types[slice.High].Value == nil || !integer(info.TypeOf(slice.High)) || bareLocal(info, slice.X) == nil || bareLocal(info, repeat.Args[1]) == nil {
		out.Unknown = append(out.Unknown, "unreviewed ASCII repeat operands")
		return
	}
	out.Roles["builder"] = fmt.Sprintf("%s %s @%s", builder.Name(), types.TypeString(builder.Type(), nil), p.set.Position(builder.Pos()))
	firstCorrect := method.Name() == "WriteString" && object(info, slice.X) == alphabet && info.Types[slice.High].Value.ExactString() == "1" && bareLocal(info, repeat.Args[1]) == zero
	cond, ok := s.suffix.Cond.(*ast.BinaryExpr)
	post, ok1 := s.suffix.Post.(*ast.IncDecStmt)
	stmt, ok2 := s.suffix.Body.List[0].(*ast.ExprStmt)
	if !ok || !ok1 || !ok2 || s.suffix.Init != nil {
		out.Unknown = append(out.Unknown, "unreviewed suffix loop")
		return
	}
	write, ok := stmt.X.(*ast.CallExpr)
	if !ok || len(write.Args) != 1 {
		out.Unknown = append(out.Unknown, "unreviewed suffix write")
		return
	}
	receiver, writeFn := builderReceiver(d, write)
	symbol, ok := write.Args[0].(*ast.IndexExpr)
	if receiver == nil || !ok {
		out.Unknown = append(out.Unknown, "unproven suffix builder/character")
		return
	}
	value, ok := symbol.Index.(*ast.IndexExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed suffix cell")
		return
	}
	for _, e := range []ast.Expr{cond.X, cond.Y, post.X, symbol.X, value.X, value.Index} {
		if bareLocal(info, e) == nil {
			out.Unknown = append(out.Unknown, "unreviewed suffix operands")
			return
		}
	}
	suffixCorrect := receiver == builder && writeFn.Name() == "WriteByte" && (cond.Op == token.LSS || cond.Op == token.NEQ) && bareLocal(info, cond.X) == pos && bareLocal(info, cond.Y) == size && post.Tok == token.INC && bareLocal(info, post.X) == pos && object(info, symbol.X) == alphabet && bareLocal(info, value.X) == buffer && bareLocal(info, value.Index) == pos
	result, ok := s.result.Results[0].(*ast.CallExpr)
	if !ok || len(result.Args) != 0 {
		out.Unknown = append(out.Unknown, "unreviewed builder return")
		return
	}
	resultBuilder, resultFn := builderReceiver(d, result)
	if resultBuilder == nil {
		out.Unknown = append(out.Unknown, "unproven builder return")
		return
	}
	returnCorrect := resultBuilder == builder && resultFn.Name() == "String"
	out.Projection = []string{"expected relation: zero-value Builder is initially empty; Repeat of alphabet[:1] supplies exactly zeroes copies of the first ASCII alphabet character", "expected relation: after each normal suffix body the same Builder contains its old bytes followed by alphabet[buffer[pos]], then pos advances once", "expected relation: reviewed prior phases bound the actual post-skip position in [0,size], where <size and !=size agree; Go body-to-Post order advances it once, and the same Builder.String returns the assembled encoding"}
	out.Steps = []StateStep{{"output-leading-symbols", []string{sourceExpression(p, prefix)}, firstCorrect}, {"output-suffix-symbols", []string{sourceExpression(p, cond), sourceExpression(p, write), sourceExpression(p, post)}, suffixCorrect}, {"output-return", []string{sourceExpression(p, result)}, returnCorrect}}
}
func (p *Program) decodeOutput(d function, s outputShape, pos, size, length, zero, buffer *types.Var, out *OutputAudit) {
	info := d.unit.info
	start, ok := s.position.Rhs[0].(*ast.BinaryExpr)
	cond, ok1 := s.scan.Cond.(*ast.BinaryExpr)
	post, ok2 := s.scan.Body.List[0].(*ast.IncDecStmt)
	if !ok || !ok1 || !ok2 || s.scan.Init != nil || s.scan.Post != nil {
		out.Unknown = append(out.Unknown, "unreviewed decoded zero scan")
		return
	}
	limit, ok := cond.X.(*ast.BinaryExpr)
	value, ok1 := cond.Y.(*ast.BinaryExpr)
	if !ok || !ok1 {
		out.Unknown = append(out.Unknown, "unreviewed decoded scan guard")
		return
	}
	cell, ok := value.X.(*ast.IndexExpr)
	if !ok || info.Types[value.Y].Value == nil || !integer(info.TypeOf(value.Y)) {
		out.Unknown = append(out.Unknown, "unreviewed decoded scan symbol")
		return
	}
	for _, e := range []ast.Expr{start.X, start.Y, limit.X, limit.Y, cell.X, cell.Index, post.X} {
		if bareLocal(info, e) == nil {
			out.Unknown = append(out.Unknown, "unreviewed decoded scan operands")
			return
		}
	}
	scanCorrect := start.Op == token.SUB && bareLocal(info, start.X) == size && bareLocal(info, start.Y) == length && cond.Op == token.LAND && (limit.Op == token.LSS || limit.Op == token.NEQ) && bareLocal(info, limit.X) == pos && bareLocal(info, limit.Y) == size && value.Op == token.EQL && bareLocal(info, cell.X) == buffer && bareLocal(info, cell.Index) == pos && zeroConstant(info, value.Y) && post.Tok == token.INC && bareLocal(info, post.X) == pos
	allocation, ok := s.allocation.Rhs[0].(*ast.CallExpr)
	output := definedLocal(info, s.allocation)
	if !ok || len(allocation.Args) != 3 || output == nil {
		out.Unknown = append(out.Unknown, "unreviewed decoded allocation")
		return
	}
	makeFn, ok := object(info, allocation.Fun).(*types.Builtin)
	outputType, ok1 := output.Type().Underlying().(*types.Slice)
	capacity, ok2 := allocation.Args[2].(*ast.BinaryExpr)
	if !ok || makeFn.Name() != "make" || !ok1 || !types.Identical(outputType.Elem(), types.Typ[types.Uint8]) || !ok2 {
		out.Unknown = append(out.Unknown, "unproven decoded allocation type/capacity")
		return
	}
	sum, ok := capacity.X.(*ast.BinaryExpr)
	if !ok {
		out.Unknown = append(out.Unknown, "unreviewed decoded capacity sum")
		return
	}
	for _, e := range []ast.Expr{allocation.Args[1], sum.X, sum.Y, capacity.Y} {
		if bareLocal(info, e) == nil {
			out.Unknown = append(out.Unknown, "unreviewed decoded capacity operands")
			return
		}
	}
	// The suffix/return remain in the reviewed frame, and typed checks below
	// independently bind final-length growth; cap alone is never the size proof.
	guard, ok := s.suffix.Cond.(*ast.BinaryExpr)
	advance, ok1 := s.suffix.Post.(*ast.IncDecStmt)
	appendStore, ok2 := s.suffix.Body.List[0].(*ast.AssignStmt)
	if !ok || !ok1 || !ok2 || !singleAssignment(appendStore) || s.suffix.Init != nil {
		out.Unknown = append(out.Unknown, "unreviewed decoded length-growth loop")
		return
	}
	appendCall, ok := appendStore.Rhs[0].(*ast.CallExpr)
	if !ok || len(appendCall.Args) != 2 {
		out.Unknown = append(out.Unknown, "unreviewed decoded append")
		return
	}
	appendFn, ok := object(info, appendCall.Fun).(*types.Builtin)
	convert, ok1 := appendCall.Args[1].(*ast.CallExpr)
	if !ok || appendFn.Name() != "append" || !ok1 || len(convert.Args) != 1 || !info.Types[convert.Fun].IsType() || !types.Identical(info.TypeOf(convert), types.Typ[types.Uint8]) {
		out.Unknown = append(out.Unknown, "unproven decoded append/conversion")
		return
	}
	sourceCell, ok := convert.Args[0].(*ast.IndexExpr)
	if !ok || bareLocal(info, sourceCell.X) != buffer || bareLocal(info, sourceCell.Index) != pos || bareLocal(info, appendStore.Lhs[0]) != output || bareLocal(info, appendCall.Args[0]) != output || appendStore.Tok != token.ASSIGN || guard.Op != token.LSS || bareLocal(info, guard.X) != pos || bareLocal(info, guard.Y) != size || advance.Tok != token.INC || bareLocal(info, advance.X) != pos || bareLocal(info, s.result.Results[0]) != output {
		out.Unknown = append(out.Unknown, "unproven decoded final-length binding")
		return
	}
	// Reservation is a source-context prerequisite, not a normative size verdict.
	// A different capacity may be equally conforming and is left unsupported.
	if sum.Op != token.ADD || capacity.Op != token.SUB || bareLocal(info, sum.X) != zero || bareLocal(info, sum.Y) != size || bareLocal(info, capacity.Y) != pos {
		out.Unknown = append(out.Unknown, "unreviewed equivalent capacity policy")
		return
	}
	allocationCorrect := bareLocal(info, allocation.Args[1]) == zero
	out.Roles["output"] = fmt.Sprintf("%s %s @%s", output.Name(), types.TypeString(output.Type(), nil), p.set.Position(output.Pos()))
	out.Projection = []string{"expected relation: reviewed earlier bounded inner loops establish 0<=length<=size; scan starts at size-length and advances across zero cells to p in [0,size], where <size and !=size agree", "expected relation: len(out)=zeroes and cap(out)=zeroes+size-p after successful make; Go zeroes the prefix and backing allocation", "expected relation: each normal suffix append grows length once, giving final len(out)=zeroes+(size-p); intermediate slice length is not the reference preallocated length", "the disputed reference destination offset in decode.16 is not interpreted or judged by this final-size/prefix relation"}
	out.Steps = []StateStep{{"decoded-leading-zero-scan", []string{sourceExpression(p, s.position), sourceExpression(p, s.scan.Cond), sourceExpression(p, post)}, scanCorrect}, {"decoded-final-size-and-zero-prefix", []string{sourceExpression(p, s.allocation), sourceExpression(p, s.suffix.Cond), sourceExpression(p, appendStore), sourceExpression(p, s.suffix.Post), sourceExpression(p, s.result)}, allocationCorrect}}
}
