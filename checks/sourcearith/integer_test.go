package sourcearith

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

func checked(t *testing.T, source string) *Program {
	t.Helper()
	p := NewProgram(t.Context(), "test", map[string][]byte{"alg/alg.go": []byte(source)})
	if _, e := p.Import("test/alg"); e != nil {
		t.Fatal(e)
	}
	return p
}
func allInteger(a Audit) bool {
	if len(a.Unknown) > 0 || len(a.Operations) == 0 {
		return false
	}
	for _, o := range a.Operations {
		if !o.Integer {
			return false
		}
	}
	return true
}
func TestIntegerClosuresAndFloatConversions(t *testing.T) {
	for _, source := range []string{
		`package alg;var scale=helper(2);func helper(n int)int{return n*2};func Root(n int)int {n+=scale;n++;n--;n=-n;n=+n;n=^n;n=(n<<1)^(n>>1);if n>=1&&n!=2{n=n/2%3};return helper(n)}`,
		`package alg;func Root(n int)int {p:=&n;s:="a";s+="b";_ =s;return *p+1}`,
		`package alg;const scale=2+3;func Root(n int)int {return n*scale}`,
	} {
		a := checked(t, source).IntegerAudit("test/alg.Root")
		if !allInteger(a) {
			t.Fatal(a)
		}
	}
	for _, source := range []string{
		`package alg;func Root(n int)int{return int(float64(n)/2.0)}`,
		`package alg;var scale=int(float64(8)/2.0);func Root(n int)int{return n*scale}`,
		`package alg;func helper(n int)int{return int(-float64(n)+1.5)};func Root(n int)int{return helper(n)}`,
		`package alg;func Root(n int)int{f:=float64(n);f++;f+=1.0;if f>2.0{f=-f};return int(f)}`,
	} {
		a := checked(t, source).IntegerAudit("test/alg.Root")
		if allInteger(a) {
			t.Fatal("float calculation accepted", a)
		}
		found := false
		for _, op := range a.Operations {
			found = found || !op.Integer
		}
		if !found {
			t.Fatal("noninteger witness missing")
		}
	}
}
func TestUnknownCallsAndInitializersCannotPass(t *testing.T) {
	for _, source := range []string{
		`package alg;func Root(n int)int{f:=func(n int)int{return n+1};return f(n)}`,
		`package alg;func helper(n int)int{return n+1};func Root(n int)int{f:=helper;return f(n)}`,
		`package alg;var unknown func(int)int;func Root(n int)int{return unknown(n)}`,
		`package alg;const(a=2;b);func Root(n int)int{return n+b}`,
		`package alg;func Root(n int)int{clear([]int{});return n+1}`,
		`package alg;func Root(n int)int{return func()int{return n+1}()}`,
		`package alg;func external(n int)int;func Root(n int)int{return external(n)}`,
	} {
		a := checked(t, source).IntegerAudit("test/alg.Root")
		if len(a.Unknown) == 0 || allInteger(a) {
			t.Fatal(source, a)
		}
	}
	p := checked(t, `package alg;func Root(n int)int{return n+1}`)
	a := p.IntegerAudit("test/alg.Missing")
	if len(a.Unknown) != 1 {
		t.Fatal(a)
	}
	// A reference to a global from an unobserved package cannot hide an initializer.
	u := p.units["test/alg"]
	foreign := types.NewVar(token.NoPos, types.NewPackage("other", "other"), "number", types.Typ[types.Int])
	a2 := auditor{p: p, globals: map[types.Object]bool{}, out: Audit{Unknown: []string{}}}
	a2.global(foreign, u.files[0].Pos())
	if len(a2.out.Unknown) != 1 {
		t.Fatal(a2.out)
	}
}
func TestTypedAliasCallEdgesAndBoundarySymbols(t *testing.T) {
	p := NewProgram(t.Context(), "test", map[string][]byte{"low/a.go": []byte(`package low;func Base(n int)int{return n+1}`), "alg/a.go": []byte(`package alg;import alias "test/low";func Root(n int)int{return alias.Base(n)}`)})
	if _, e := p.Import("test/alg"); e != nil {
		t.Fatal(e)
	}
	if !p.Calls("test/alg.Root", "test/low.Base") || p.Calls("test/alg.Root", "test/alg.Missing") {
		t.Fatal("typed edge")
	}
	if !allInteger(p.IntegerAudit("test/alg.Root")) {
		t.Fatal("helper")
	}
	// Reviewed boundaries are real standard package/type/method symbols.
	p = checked(t, `package alg;import("strings";"errors";"fmt");var err=errors.New("text");func Root(n int)int{var b strings.Builder;b.Grow(n+1);b.WriteByte(byte(n));b.WriteString(strings.Repeat("x",n));_ =b.String();_ =err;_ =fmt.Errorf("%d",n);return n+1}`)
	a := p.IntegerAudit("test/alg.Root")
	if !allInteger(a) || len(a.Boundaries) != 7 {
		t.Fatal(a)
	}
	p = checked(t, `package alg;import "math";func Root(n int)int{return int(math.Sqrt(float64(n)))}`)
	if len(p.IntegerAudit("test/alg.Root").Unknown) == 0 {
		t.Fatal("unreviewed external math")
	}
	p = checked(t, `package alg;type Builder struct{};func(*Builder)Grow(n int)int{return int(float64(n)/2)};func Root(n int)int{var b Builder;return b.Grow(n)}`)
	if allInteger(p.IntegerAudit("test/alg.Root")) {
		t.Fatal("fake builder bypass")
	}
	var basic ast.Expr = &ast.BasicLit{Kind: token.INT, Value: "1"}
	if object(&types.Info{Uses: map[*ast.Ident]types.Object{}}, basic) != nil {
		t.Fatal("unknown call expression")
	}
	p = checked(t, `package alg;func Helper(n int)int{return n+1};func Root(n int)int{return (Helper)(n)}`)
	if !p.Calls("test/alg.Root", "test/alg.Helper") {
		t.Fatal("parenthesized call")
	}
}
func TestTypeCheckingFailuresAndCancellation(t *testing.T) {
	for _, source := range []map[string][]byte{{}, {"alg/a.go": []byte(`package`)}, {"alg/a.go": []byte(`package alg;func Root()int{return "wrong"}`)}, {"alg/a.go": []byte(`package alg;import "test/low";var _=low.V`), "low/a.go": []byte(`package low;import "test/alg";var V=alg.V`)}} {
		p := NewProgram(t.Context(), "test", source)
		if _, e := p.Import("test/alg"); e == nil {
			t.Fatal("invalid source accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := NewProgram(ctx, "test", nil).Import("test/alg"); e == nil {
		t.Fatal("cancelled")
	}
	p := checked(t, `package alg;func Root(n int)int{return n+1}`)
	if _, e := p.Import("test/alg"); e != nil {
		t.Fatal(e)
	}
	if integer(nil) || numeric(nil) || integer(types.Typ[types.String]) || numeric(types.NewSlice(types.Typ[types.Int])) {
		t.Fatal("type predicate")
	}
	for _, tok := range []token.Token{token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR} {
		if !arithmetic(tok) {
			t.Fatal(tok)
		}
	}
	for _, tok := range []token.Token{token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ} {
		if !comparison(tok) {
			t.Fatal(tok)
		}
	}
	for _, tok := range []token.Token{token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN, token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN, token.AND_NOT_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN} {
		if !compound(tok) {
			t.Fatal(tok)
		}
	}
	if arithmetic(token.ASSIGN) || comparison(token.ADD) || compound(token.ASSIGN) {
		t.Fatal("operator class")
	}
	a := auditor{p: p, out: Audit{Operations: []Operation{}}}
	a.operation(p.units["test/alg"].files[0].Pos(), "unit", nil)
	if a.out.Operations[0].Integer || !strings.Contains(a.out.Operations[0].Types[0], "missing") {
		t.Fatal(a.out)
	}
}

func TestAdditionalBoundaryAndOperatorControls(t *testing.T) {
	for _, source := range []string{
		`package alg;import "strings";func Root(n int)int{var r strings.Reader;_ =r.Len();return n+1}`,
		`package alg;import "strings";func Root(n int)int{var b strings.Builder;_ =b.Cap();return n+1}`,
	} {
		a := checked(t, source).IntegerAudit("test/alg.Root")
		if len(a.Unknown) == 0 {
			t.Fatal("unreviewed method accepted")
		}
	}
	a := checked(t, `package alg;func Root(n int)int{_ =string(n);n*=2;n-=1;n/=2;n%=3;n&=4;n|=8;n^=2;n&^=1;n<<=1;n>>=1;return n+1}`).IntegerAudit("test/alg.Root")
	if !allInteger(a) {
		t.Fatal(a)
	}
	signature := types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	if boundary(types.NewFunc(token.NoPos, nil, "Unknown", signature)) {
		t.Fatal("missing package accepted")
	}
}

func TestOperationOrderAcrossFilesAndLines(t *testing.T) {
	p := NewProgram(t.Context(), "test", map[string][]byte{
		"alg/a.go": []byte("package alg\nfunc Root(n int)int {\n n++\n return helper(n)+1\n}\n"),
		"alg/z.go": []byte("package alg\nfunc helper(n int)int {\n n*=2\n return n/2\n}\n"),
	})
	if _, e := p.Import("test/alg"); e != nil {
		t.Fatal(e)
	}
	a := p.IntegerAudit("test/alg.Root")
	if !allInteger(a) || len(a.Functions) != 2 {
		t.Fatal(a)
	}
	for i := 1; i < len(a.Operations); i++ {
		x, y := a.Operations[i-1], a.Operations[i]
		if x.File > y.File || x.File == y.File && x.Line > y.Line {
			t.Fatal("unstable source operation order")
		}
	}
}

func TestImplicitCallbacksAndMutablePackageInitialization(t *testing.T) {
	for _, source := range []string{
		`package alg;var scale=2;func init(){scale=int(float64(8)/2)};func Root(n int)int{return n*scale}`,
		`package alg;import "fmt";type data int;func(data)String()string{_ =int(float64(8)/2);return "text"};func Root(n int)int{_ =fmt.Errorf("%v",data(n));return n+1}`,
		`package alg;import("fmt";"errors");func Root(n int)int{_ =fmt.Errorf("%v",errors.New("text"));return n+1}`,
	} {
		a := checked(t, source).IntegerAudit("test/alg.Root")
		if len(a.Unknown) == 0 || allInteger(a) {
			t.Fatal("implicit execution path ignored", a)
		}
	}
	a := checked(t, `package alg;const scale=2;func init(){};func Root(n int)int{return n*scale}`).IntegerAudit("test/alg.Root")
	if !allInteger(a) {
		t.Fatal("immutable constant confused with mutable global")
	}
}

func TestGenericAndOtherInitializationRemainUnknown(t *testing.T) {
	for _, source := range []string{
		`package alg;func helper[T ~int|~float64](n T)T{return n*n};func Root(n int)int{return helper(n)+1}`,
		`package alg;type Box[T ~int]struct{};func(Box[T])Help(n T)T{return n*n};func Root(n int)int{var b Box[int];return b.Help(n)+1}`,
		`package alg;var scale=2;var unused=configure();func configure()int{scale=int(float64(8)/2);return 0};func Root(n int)int{return n*scale}`,
		`package alg;var scale=2;var _=configure();func configure()int{scale=4;return 0};func Root(n int)int{return n*scale}`,
		`package alg;var(scale=2;unused=4);func Root(n int)int{return n*scale}`,
	} {
		a := checked(t, source).IntegerAudit("test/alg.Root")
		if len(a.Unknown) == 0 || allInteger(a) {
			t.Fatal("unreviewed execution accepted", a)
		}
	}
	// Unrelated initialization is not proof of noninteger algorithm arithmetic.
	a := checked(t, `package alg;var scale=2;var unused=int(float64(8)/2);func Root(n int)int{return n*scale}`).IntegerAudit("test/alg.Root")
	for _, op := range a.Operations {
		if !op.Integer {
			t.Fatal("unrelated float attributed to root", a)
		}
	}
	// An uninitialized unrelated variable has no initialization effects.
	a = checked(t, `package alg;var scale=2;var unused int;func Root(n int)int{return n*scale}`).IntegerAudit("test/alg.Root")
	if !allInteger(a) {
		t.Fatal(a)
	}
}
