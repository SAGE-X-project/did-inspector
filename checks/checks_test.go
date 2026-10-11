package checks

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func TestParseDIDValid(t *testing.T) {
	cases := []struct {
		in, method, msid string
	}{
		{"did:example:123456789abcdefghi", "example", "123456789abcdefghi"},
		{"did:web:example.com", "web", "example.com"},
		{"did:a1:B-._x", "a1", "B-._x"},
		{"did:m:a:b:c", "m", "a:b:c"},
		{"did:m::x", "m", "::x"[1:]},
		{"did:m:::x", "m", "::x"},
		{"did:m:%20%aF", "m", "%20%aF"},
		{"did:0:1", "0", "1"},
		// "did:" is a quoted ABNF string, so it is case-insensitive.
		{"DID:example:1", "example", "1"},
		{"Did:example:1", "example", "1"},
	}
	for _, c := range cases {
		got, err := ParseDID(c.in)
		if err != nil {
			t.Errorf("ParseDID(%q): %v", c.in, err)
			continue
		}
		want := core.DIDParts{DID: c.in, Method: c.method, MethodSpecificID: c.msid}
		if got != want {
			t.Errorf("ParseDID(%q) = %+v, want %+v", c.in, got, want)
		}
		if !IsDID(c.in) {
			t.Errorf("IsDID(%q) = false", c.in)
		}
	}
}

func TestParseDIDInvalid(t *testing.T) {
	cases := []struct {
		in, rule string
		offset   int
	}{
		{"", "did", 0},
		{"di", "did", 0},
		{"urn:example:1", "did", 0},
		{"did:", "method-name", 4},
		{"did::1", "method-name", 4},
		{"did:Example:1", "method-name", 4},
		{"did:ex-ample:1", "did", 6},
		{"did:example", "did", 11},
		{"did:example:", "method-specific-id", 12},
		{"did:example:1:", "method-specific-id", 13},
		{"did:example:%2", "pct-encoded", 12},
		{"did:example:%G0", "pct-encoded", 12},
		{"did:example:a b", "did", 13},
		{"did:example:a/b", "did", 13},
		{"did:example:a?b", "did", 13},
		{"did:example:a#b", "did", 13},
		{"did:example:é", "method-specific-id", 12},
	}
	for _, c := range cases {
		_, err := ParseDID(c.in)
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("ParseDID(%q) err = %v, want a SyntaxError", c.in, err)
			continue
		}
		if se.Rule != c.rule || se.Offset != c.offset || se.Input != c.in {
			t.Errorf("ParseDID(%q) = %+v, want rule %s offset %d", c.in, se, c.rule, c.offset)
		}
		if !strings.Contains(se.Error(), c.rule) {
			t.Errorf("error text %q lacks the rule", se.Error())
		}
		if IsDID(c.in) {
			t.Errorf("IsDID(%q) = true", c.in)
		}
	}
}

func TestParseDIDURLValid(t *testing.T) {
	cases := []struct {
		in                    string
		did, path, query, frg string
		hasQ, hasF            bool
	}{
		{"did:example:123", "did:example:123", "", "", "", false, false},
		{"did:example:123/path/to;x=1/", "did:example:123", "/path/to;x=1/", "", "", false, false},
		{"did:example:123?service=agent&relativeRef=/a%20b", "did:example:123", "", "service=agent&relativeRef=/a%20b", "", true, false},
		{"did:example:123#key-1", "did:example:123", "", "", "key-1", false, true},
		{"did:example:123/p?q=/?#f/?:@!$&'()*+,;=", "did:example:123", "/p", "q=/?", "f/?:@!$&'()*+,;=", true, true},
		{"did:example:123?", "did:example:123", "", "", "", true, false},
		{"did:example:123#", "did:example:123", "", "", "", false, true},
		{"did:example:123//", "did:example:123", "//", "", "", false, false},
		{"did:example:123/~user@host:8", "did:example:123", "/~user@host:8", "", "", false, false},
	}
	for _, c := range cases {
		got, err := ParseDIDURL(c.in)
		if err != nil {
			t.Errorf("ParseDIDURL(%q): %v", c.in, err)
			continue
		}
		if got.DIDURL != c.in || got.DID.DID != c.did || got.Path != c.path || got.Query != c.query ||
			got.Fragment != c.frg || got.HasQuery != c.hasQ || got.HasFragment != c.hasF {
			t.Errorf("ParseDIDURL(%q) = %+v", c.in, got)
		}
		if !IsDIDURL(c.in) {
			t.Errorf("IsDIDURL(%q) = false", c.in)
		}
	}
}

func TestParseDIDURLInvalid(t *testing.T) {
	cases := []struct {
		in, rule string
		offset   int
	}{
		{"did:example", "did", 11},
		{"did:example:123:/path", "method-specific-id", 15},
		{"did:example:123/a b", "path-abempty", 17},
		{"did:example:123/a%zz", "path-abempty", 17},
		{"did:example:123/a[", "path-abempty", 17},
		{"did:example:123?a b", "query", 17},
		{"did:example:123?a#b c", "fragment", 19},
		{"did:example:123#a#b", "fragment", 17},
		{"did:example:123?%", "query", 16},
		{"did:example:123/é", "path-abempty", 16},
	}
	for _, c := range cases {
		_, err := ParseDIDURL(c.in)
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("ParseDIDURL(%q) err = %v", c.in, err)
			continue
		}
		if se.Rule != c.rule || se.Offset != c.offset || se.Input != c.in {
			t.Errorf("ParseDIDURL(%q) = %+v, want rule %s offset %d", c.in, se, c.rule, c.offset)
		}
		if IsDIDURL(c.in) {
			t.Errorf("IsDIDURL(%q) = true", c.in)
		}
	}
}

func TestURIRules(t *testing.T) {
	if !IsPathAbempty("") || !IsPathAbempty("/a/b%2F") || IsPathAbempty("a/b") || IsPathAbempty("/a b") {
		t.Error("IsPathAbempty")
	}
	if !IsQuery("a=1&b=/?") || IsQuery("a#b") || IsQuery("%") {
		t.Error("IsQuery")
	}
	if !IsFragment("key-1") || IsFragment("a b") {
		t.Error("IsFragment")
	}
	_, err := checkRule("a\x01", isPChar, "segment")
	if err == nil || !strings.Contains(err.Reason, "0x01") {
		t.Errorf("control character reason = %v", err)
	}
}

func TestDuplicateMembers(t *testing.T) {
	src := `{"a":1,"b":[{"x":1,"x":2,"x":3}],"a":2,"c/~":{"y":1,"y":2},"b":0}`
	got, err := DuplicateMembersInBytes([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []Duplicate{
		{Pointer: "", Name: "a", Count: 2},
		{Pointer: "", Name: "b", Count: 2},
		{Pointer: "/b/0", Name: "x", Count: 3},
		{Pointer: "/c~1~0", Name: "y", Count: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if d, _ := DuplicateMembersInBytes([]byte(`{"a":{"b":1},"c":[1,"x"]}`)); d != nil {
		t.Fatalf("no duplicates expected, got %+v", d)
	}
	if _, err := DuplicateMembersInBytes([]byte(`{`)); err == nil {
		t.Fatal("broken JSON accepted")
	}
}

func TestCheckDatetimeValid(t *testing.T) {
	for _, s := range []string{
		"2020-12-20T19:17:47Z",
		"0000-02-29T00:00:00Z",
		"2000-02-29T23:59:59Z",
		"-0004-02-29T00:00:00Z",
		"12345-01-01T00:00:00Z",
		"1999-12-31T00:00:00Z",
	} {
		if err := CheckDatetime(s); err != nil {
			t.Errorf("CheckDatetime(%q): %v", s, err)
		}
	}
}

func TestCheckDatetimeInvalid(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"2020-12-20T19:17:47", ErrDatetimeNotUTC},
		{"2020-12-20T19:17:47+00:00", ErrDatetimeNotUTC},
		{"2020-12-20T19:17:47-05:00", ErrDatetimeNotUTC},
		{"2020-12-20T19:17:47.5Z", ErrDatetimeFraction},
		{"2020-12-20T24:00:00Z", ErrDatetimeEndOfDay},
		{"2020-12-20T24:00:01Z", ErrDatetimeSyntax},
		{"2020-12-20T24:00:00.0Z", ErrDatetimeSyntax},
		{"2020-12-20T25:00:00Z", ErrDatetimeSyntax},
		{"2020-12-20T19:60:00Z", ErrDatetimeSyntax},
		{"2020-12-20T19:00:60Z", ErrDatetimeSyntax},
		{"2020-13-20T19:00:00Z", ErrDatetimeSyntax},
		{"2020-00-20T19:00:00Z", ErrDatetimeSyntax},
		{"2020-02-30T19:00:00Z", ErrDatetimeSyntax},
		{"1900-02-29T00:00:00Z", ErrDatetimeSyntax},
		{"2021-04-31T00:00:00Z", ErrDatetimeSyntax},
		{"2021-04-00T00:00:00Z", ErrDatetimeSyntax},
		{"20-12-20T19:17:47Z", ErrDatetimeSyntax},
		{"02020-12-20T19:17:47Z", ErrDatetimeSyntax},
		{"2020-12-20 19:17:47Z", ErrDatetimeSyntax},
		{"2020-12-20T19:17Z", ErrDatetimeSyntax},
		{"2020-1a-20T19:17:47Z", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47.Z", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47+15:00", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47+14:01", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47+01:60", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47+0100", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47+aa:00", ErrDatetimeSyntax},
		{"2020-12-20T19:17:47z", ErrDatetimeSyntax},
		{"99999999999999999999-01-01T00:00:00Z", ErrDatetimeSyntax},
		{"", ErrDatetimeSyntax},
	}
	for _, c := range cases {
		err := CheckDatetime(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("CheckDatetime(%q) = %v, want %v", c.in, err, c.want)
		}
	}
	if err := CheckDatetime("2020-12-20T19:17:47+14:00"); !errors.Is(err, ErrDatetimeNotUTC) {
		t.Errorf("+14:00 = %v", err)
	}
}
