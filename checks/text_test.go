package checks

import (
	"errors"
	"reflect"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func mustValue(t *testing.T, s string) core.Value {
	t.Helper()
	v, err := core.ParseJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEqualJSON(t *testing.T) {
	cases := []struct {
		a, b string
		eq   bool
		at   string
	}{
		{`{"a":1,"b":[true,null,"x"]}`, `{"b":[true,null,"x"],"a":1}`, true, ""},
		{`1.5`, `1.50`, true, ""},
		{`1`, `1.0`, false, ""},
		{`1`, `2`, false, ""},
		{`[1,2]`, `[2,1]`, false, "/0"},
		{`[1]`, `[1,2]`, false, ""},
		{`{"a":{"b/c":1}}`, `{"a":{"b/c":2}}`, false, "/a/b~1c"},
		{`{"a":1}`, `{"b":1}`, false, "/a"},
		{`{"a":1}`, `{"a":1,"b":2}`, false, ""},
		{`{"a":1,"a":2}`, `{"a":1,"a":2}`, true, ""},
		{`"x"`, `1`, false, ""},
		{`true`, `false`, false, ""},
		{`null`, `null`, true, ""},
		{`"s"`, `"s"`, true, ""},
	}
	for _, c := range cases {
		eq, at := EqualJSON(mustValue(t, c.a), mustValue(t, c.b))
		if eq != c.eq || at != c.at {
			t.Errorf("EqualJSON(%s, %s) = %v %q, want %v %q", c.a, c.b, eq, at, c.eq, c.at)
		}
	}
	if equalNumber("x", "1") {
		t.Error("bad literal compared equal")
	}
}

func TestContainsJSONAndCompact(t *testing.T) {
	got, _ := core.DocumentFromValue(mustValue(t, `{"a":1,"b":"x","c":[]}`))
	want, _ := core.DocumentFromValue(mustValue(t, `{"b":"x","a":1}`))
	if ok, name := ContainsJSON(got, want); !ok || name != "" {
		t.Errorf("ContainsJSON = %v %q", ok, name)
	}
	other, _ := core.DocumentFromValue(mustValue(t, `{"a":2}`))
	if ok, name := ContainsJSON(got, other); ok || name != "a" {
		t.Errorf("ContainsJSON differing = %v %q", ok, name)
	}
	missing, _ := core.DocumentFromValue(mustValue(t, `{"z":2}`))
	if ok, name := ContainsJSON(got, missing); ok || name != "z" {
		t.Errorf("ContainsJSON missing = %v %q", ok, name)
	}
	if Compact(mustValue(t, ` { "a" : 1 } `)) != `{"a":1}` {
		t.Error("Compact")
	}
	if s := Compact(core.Number("x")); s[0] != '<' {
		t.Errorf("Compact of a bad number = %s", s)
	}
}

func TestTextPredicates(t *testing.T) {
	if !IsASCII("abc~") || IsASCII("ab\u00e9") {
		t.Error("IsASCII")
	}
	for _, s := range []string{"invalidDid", "notFound", "a-b_c.d", "X1"} {
		if !IsKeyword(s) {
			t.Errorf("IsKeyword(%q) = false", s)
		}
	}
	for _, s := range []string{"", "not found", "a/b", "\u00e9"} {
		if IsKeyword(s) {
			t.Errorf("IsKeyword(%q) = true", s)
		}
	}
	for _, s := range []string{"application/did", "application/did+ld+json", "text/plain; charset=utf-8", `a/b;x="q\"t"`, "a/b ;", "a/b; ;c=d"} {
		if !IsMediaType(s) {
			t.Errorf("IsMediaType(%q) = false", s)
		}
	}
	for _, s := range []string{"", "application", "/did", "application/", "a/b c", "a/b;c", "a/b;c=", `a/b;c="x`, "a/b;=d", "a/b;c=\"\x01\"", "a/b\u00e9"} {
		if IsMediaType(s) {
			t.Errorf("IsMediaType(%q) = true", s)
		}
	}
	if MediaTypeEssence(" Application/DID ; charset=utf-8") != "application/did" {
		t.Error("MediaTypeEssence")
	}
}

func TestIsAbsoluteURI(t *testing.T) {
	for _, s := range []string{"https://example.com/a?b#c", "did:example:123#key-1", "urn:uuid:1", "a+b.c-d:x", "https://w3id.org/security#INVALID_VERIFICATION_METHOD"} {
		if !IsAbsoluteURI(s) {
			t.Errorf("IsAbsoluteURI(%q) = false", s)
		}
	}
	for _, s := range []string{"", "NOT_FOUND", ":x", "1a:x", "a_b:x", "https://ex ample.com", "a:b#c#d", "a:%zz", "a:\u00e9"} {
		if IsAbsoluteURI(s) {
			t.Errorf("IsAbsoluteURI(%q) = true", s)
		}
	}
}

func TestParseURIList(t *testing.T) {
	got, err := ParseURIList([]byte("# comment\r\nhttps://a.example/x\r\nhttps://b.example/y\n\n"))
	if err != nil || !reflect.DeepEqual(got, []string{"https://a.example/x", "https://b.example/y"}) {
		t.Fatalf("ParseURIList = %v %v", got, err)
	}
	if got, err := ParseURIList(nil); err != nil || got != nil {
		t.Errorf("empty = %v %v", got, err)
	}
	if _, err := ParseURIList([]byte("not a uri\r\n")); !errors.Is(err, ErrURIList) {
		t.Errorf("err = %v", err)
	}
}
