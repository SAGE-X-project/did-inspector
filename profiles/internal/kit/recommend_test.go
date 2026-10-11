package kit

import (
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func TestUndefinedTermCases(t *testing.T) {
	cases := UndefinedTermCases(UndefinedTermConfig{Profile: "p", Version: "1", MediaType: "application/did", Context: "https://c", Producer: "k#p", Consumer: "k#c"})
	if len(cases) != 2 || cases[0].Statements[0] != "k#p" || cases[1].Statements[0] != "k#c" {
		t.Fatalf("cases = %+v", cases)
	}
	verdict := func(c core.Case, f *fake) core.Verdict { return c.Run(ctx, f)[0].Verdict }
	if v := verdict(cases[0], &fake{}); v != core.Pass {
		t.Errorf("declined production: %s", v)
	}
	if v := verdict(cases[0], &fake{produced: []byte(`{"id":"did:example:1"}`)}); v != core.Pass {
		t.Errorf("dropped term: %s", v)
	}
	if v := verdict(cases[0], &fake{produced: []byte(`{"inspectorUndefinedTerm":1}`)}); v != core.Fail {
		t.Errorf("kept term: %s", v)
	}
	if v := verdict(cases[0], &fake{produced: []byte(`[]`)}); v != core.Fail {
		t.Errorf("non-object: %s", v)
	}
	// The fake consumer keeps every member.
	if v := verdict(cases[1], &fake{consumeOK: true}); v != core.Fail {
		t.Errorf("consumer kept the term: %s", v)
	}
	if v := verdict(cases[1], &fake{}); v != core.Fail {
		t.Errorf("consumer rejected the document: %s", v)
	}
	d := UndefinedTermDocument("https://c")
	if _, ok := d.Get(UndefinedTerm); !ok {
		t.Fatal("document lacks the term")
	}
}

func TestErrorRules(t *testing.T) {
	outcome := func(md string) Outcome { return Outcome{Metadata: doc(t, md)} }
	obj := ErrorObjectRule("s")
	for md, want := range map[string][2]bool{
		`{}`:                            {false, false},
		`{"error":"notFound"}`:          {true, false},
		`{"error":{"type":"x"}}`:        {true, true},
		`{"error":{"title":"no type"}}`: {true, false},
	} {
		applies, ok, _, _ := obj.Check(outcome(md))
		if applies != want[0] || ok != want[1] {
			t.Errorf("object rule %s = %v %v", md, applies, ok)
		}
	}
	title := ErrorMemberRule("s", "title", nil)
	feature := ErrorMemberRule("s", "detail", func(code string) bool { return code == "F" })
	for _, c := range []struct {
		rule        Invariant
		md          string
		applies, ok bool
	}{
		{title, `{"error":{"type":"x","title":"T"}}`, true, true},
		{title, `{"error":{"type":"x","title":""}}`, true, false},
		{title, `{"error":"x"}`, false, false},
		{feature, `{"error":{"type":"F"}}`, true, false},
		{feature, `{"error":{"type":"F","detail":"d"}}`, true, true},
		{feature, `{"error":{"type":"G"}}`, false, false},
	} {
		applies, ok, _, _ := c.rule.Check(outcome(c.md))
		if applies != c.applies || ok != c.ok {
			t.Errorf("member rule %s = %v %v", c.md, applies, ok)
		}
	}
}
