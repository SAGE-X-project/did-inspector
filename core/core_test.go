package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/core/coretest"
)

func TestAggregate(t *testing.T) {
	cases := []struct {
		in   []core.Verdict
		want core.Verdict
	}{
		{nil, core.NotRun},
		{[]core.Verdict{core.Pass}, core.Pass},
		{[]core.Verdict{core.Pass, core.NotSupported}, core.NotSupported},
		{[]core.Verdict{core.NotSupported, core.Error, core.Pass}, core.Error},
		{[]core.Verdict{core.Error, core.Fail, core.NotSupported}, core.Fail},
		{[]core.Verdict{core.Fail, core.Pass}, core.Fail},
		{[]core.Verdict{core.NotApplicable}, core.NotApplicable},
		{[]core.Verdict{core.NotApplicable, core.Pass}, core.Pass},
		{[]core.Verdict{core.Pass, "BOGUS"}, core.Error},
		{[]core.Verdict{core.NotRun}, core.Error},
	}
	for _, c := range cases {
		if got := core.Aggregate(c.in); got != c.want {
			t.Errorf("Aggregate(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestVerdictPredicates(t *testing.T) {
	if len(core.Verdicts()) != 6 {
		t.Fatal("unexpected verdict set")
	}
	for _, v := range core.Verdicts() {
		if !v.Valid() {
			t.Errorf("%s invalid", v)
		}
		if v.IsObservation() == (v == core.NotRun) {
			t.Errorf("%s IsObservation = %v", v, v.IsObservation())
		}
	}
	if core.Verdict("X").Valid() {
		t.Error("unknown verdict valid")
	}
}

func TestCapabilities(t *testing.T) {
	caps := core.Capabilities()
	if len(caps) != 9 {
		t.Fatalf("got %d capabilities", len(caps))
	}
	caps[0] = "mutated"
	if core.Capabilities()[0] != core.CapDIDParser {
		t.Fatal("Capabilities exposes its backing array")
	}
	for _, c := range core.Capabilities() {
		if !c.Valid() {
			t.Errorf("%s invalid", c)
		}
		if !core.Implements(coretest.New(), c) {
			t.Errorf("fixture does not implement %s", c)
		}
		if core.Implements(coretest.Bare{}, c) {
			t.Errorf("bare subject implements %s", c)
		}
	}
	if core.Capability("x").Valid() || core.Implements(coretest.New(), "x") {
		t.Error("unknown capability accepted")
	}
	e := &core.CapabilityError{Profile: "p", Capability: core.CapResolver, Unsupported: true}
	if !strings.Contains(e.Error(), "does not support resolver under profile p") {
		t.Errorf("error = %s", e)
	}
}

func noop(context.Context, core.Subject) []core.Observation { return nil }

func TestCaseValidate(t *testing.T) {
	good := core.Case{ID: "a", Profile: "p", Statements: []string{"k#s.1"}, Needs: []core.Capability{core.CapResolver}, Run: noop}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := core.Case{ID: " ", Statements: []string{"", "k#s.1", "k#s.1"}, Needs: []core.Capability{"teleport"}}
	err := bad.Validate()
	if err == nil {
		t.Fatal("bad case accepted")
	}
	for _, part := range []string{"empty id", "empty profile", "empty statement id", "named twice", "unknown capability", "no Run"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q lacks %q", err, part)
		}
	}
	if err := (core.Case{ID: "x", Profile: "p", Run: noop}).Validate(); err == nil || !strings.Contains(err.Error(), "names no statement") {
		t.Errorf("err = %v", err)
	}
}

func TestProfileValidate(t *testing.T) {
	c := core.Case{ID: "a", Profile: "p", Statements: []string{"k#s.1"}, Run: noop}
	cases := []struct {
		p    core.Profile
		part string
	}{
		{core.Profile{Name: "p", SpecKeys: []string{"k"}, Cases: []core.Case{c}}, ""},
		{core.Profile{SpecKeys: []string{"k"}}, "empty name"},
		{core.Profile{Name: "p"}, "no spec keys"},
		{core.Profile{Name: "p", SpecKeys: []string{"k"}, Cases: []core.Case{{ID: "a"}}}, "case \"a\""},
		{core.Profile{Name: "q", SpecKeys: []string{"k"}, Cases: []core.Case{c}}, "belongs to profile p"},
		{core.Profile{Name: "p", SpecKeys: []string{"k"}, Cases: []core.Case{c, c}}, "duplicate case id"},
		{core.Profile{Name: "p", SpecKeys: []string{"other"}, Cases: []core.Case{c}}, "not in a spec"},
		{core.Profile{Name: "p", SpecKeys: []string{"k"}, Cases: []core.Case{{ID: "b", Profile: "p", Statements: []string{"nokey"}, Run: noop}}}, "not in a spec"},
	}
	for _, tc := range cases {
		err := tc.p.Validate()
		if tc.part == "" {
			if err != nil {
				t.Errorf("valid profile rejected: %v", err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.part) {
			t.Errorf("profile %+v: err = %v, want %q", tc.p, err, tc.part)
		}
	}
}

func TestParseJSONKeepsOrderAndDuplicates(t *testing.T) {
	src := `{"b":1,"a":[true,false,null,"s",-1.50e3],"b":{"z":{}, "y":[]}}`
	v, err := core.ParseJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != core.KindObject || len(v.Object) != 3 || v.Object[0].Name != "b" || v.Object[2].Name != "b" {
		t.Fatalf("v = %+v", v)
	}
	a, ok := v.Get("a")
	if !ok || len(a.Array) != 5 || a.Array[4].Number != "-1.50e3" || a.Array[3].Str != "s" || !a.Array[0].Bool {
		t.Fatalf("a = %+v", a)
	}
	if first, _ := v.Get("b"); first.Number != "1" {
		t.Fatalf("Get returned %+v, want the first member", first)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"b":1,"a":[true,false,null,"s",-1.50e3],"b":{"z":{},"y":[]}}` {
		t.Fatalf("round trip = %s", out)
	}
	if _, ok := v.Get("missing"); ok {
		t.Fatal("missing member found")
	}
}

func TestParseJSONErrors(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"truncated": `{"a":`,
		"trailing":  `{} {}`,
		"syntax":    `{"a" 1}`,
		"badarray":  `[1,]`,
		"utf8":      "\"\xff\"",
		"unclosed":  `[1`,
	}
	for name, src := range cases {
		if _, err := core.ParseJSON([]byte(src)); err == nil {
			t.Errorf("%s: parsed %q", name, src)
		}
	}
	if _, err := core.ParseJSON([]byte("\"\xff\"")); !errors.Is(err, core.ErrInvalidUTF8) {
		t.Errorf("utf8 error = %v", err)
	}
	if _, err := core.ParseJSON(nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("empty input error = %v", err)
	}
	deep := strings.Repeat("[", 10002) + strings.Repeat("]", 10002)
	if _, err := core.ParseJSON([]byte(deep)); err == nil || !strings.Contains(err.Error(), "too deep") {
		t.Errorf("deep nesting error = %v", err)
	}
}

func TestValueMarshal(t *testing.T) {
	v := core.Object(
		core.M("n", core.Null()),
		core.M("t", core.Bool(true)),
		core.M("f", core.Bool(false)),
		core.M("num", core.Number("0.5")),
		core.M("s", core.String("<a&b> \"q\"")),
		core.M("arr", core.Array(core.Number("1"), core.String("x"))),
	)
	out, err := v.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"n":null,"t":true,"f":false,"num":0.5,"s":"<a&b> \"q\"","arr":[1,"x"]}`
	if string(out) != want {
		t.Fatalf("got %s", out)
	}
	for _, bad := range []core.Value{
		core.Number(""), core.Number("true"), core.Number("1x"), {Kind: 99},
		core.Array(core.Number("")), core.Object(core.M("a", core.Number("x"))),
	} {
		if _, err := bad.MarshalJSON(); err == nil {
			t.Errorf("marshalled invalid value %+v", bad)
		}
	}
	var back core.Value
	if err := json.Unmarshal(out, &back); err != nil || len(back.Object) != 6 {
		t.Fatalf("unmarshal: %+v %v", back, err)
	}
	if err := back.UnmarshalJSON([]byte("{")); err == nil {
		t.Fatal("broken JSON unmarshalled")
	}
}

func TestKindString(t *testing.T) {
	if core.KindObject.String() != "object" || core.KindNull.String() != "null" || core.Kind(42).String() != "kind(42)" {
		t.Fatal("unexpected kind names")
	}
}

func TestDocumentJSON(t *testing.T) {
	d, err := core.ParseDocumentJSON([]byte(`{"id":"did:example:1","id":"did:example:2","x":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Len() != 3 || strings.Join(d.Names(), ",") != "id,id,x" {
		t.Fatalf("names = %v", d.Names())
	}
	if id, _ := d.Get("id"); id.Str != "did:example:1" {
		t.Fatalf("Get = %+v", id)
	}
	if _, err := core.ParseDocumentJSON([]byte(`[]`)); err == nil || !strings.Contains(err.Error(), "array, not an object") {
		t.Fatalf("array accepted as document: %v", err)
	}
	if _, err := core.ParseDocumentJSON([]byte(`{`)); err == nil {
		t.Fatal("broken document accepted")
	}
	empty, err := core.DocumentJSON{}.MarshalJSON()
	if err != nil || string(empty) != "{}" {
		t.Fatalf("empty document = %s %v", empty, err)
	}
	type wrapper struct {
		Doc core.DocumentJSON `json:"doc"`
	}
	var w wrapper
	if err := json.Unmarshal([]byte(`{"doc":{"b":1,"a":2}}`), &w); err != nil {
		t.Fatal(err)
	}
	if strings.Join(w.Doc.Names(), ",") != "b,a" {
		t.Fatalf("names = %v", w.Doc.Names())
	}
	if err := json.Unmarshal([]byte(`{"doc":[1]}`), &w); err == nil {
		t.Fatal("array unmarshalled into a document")
	}
	out, err := json.Marshal(wrapper{Doc: core.NewDocument(core.M("z", core.String("1")), core.M("a", core.String("2")))})
	if err != nil || string(out) != `{"doc":{"z":"1","a":"2"}}` {
		t.Fatalf("marshal = %s %v", out, err)
	}
}
