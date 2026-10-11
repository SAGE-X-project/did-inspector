package extract

import (
	"reflect"
	"strings"
	"testing"
)

func mustExtract(t *testing.T, src string) []Statement {
	t.Helper()
	sts, err := Extract("k", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return sts
}

func kw(word string) string {
	return `<em class="rfc2119">` + word + `</em>`
}

func TestExtractRequirements(t *testing.T) {
	src := `<html><head><title>MUST not count</title></head><body>
<section id="a"><h2>A</h2>
<p>First sentence has no keyword. A value ` + kw("MUST") + ` be a string, e.g. a DID. Another ` + kw("MAY") + ` appear &amp; more.</p>
<pre>code ` + kw("MUST") + ` be skipped</pre>
<p>Plain text.</p>
</section>
<p>Outside ` + kw("SHOULD") + ` be numbered.</p>
</body></html>`
	got := mustExtract(t, src)
	want := []Statement{
		{ID: "k#a.1", Section: "a", Kind: KindRequirement, Keywords: []string{"MUST"}, Level: LevelRequirement, Text: "A value MUST be a string, e.g. a DID."},
		{ID: "k#a.2", Section: "a", Kind: KindRequirement, Keywords: []string{"MAY"}, Level: LevelRequirement, Text: "Another MAY appear & more."},
		{ID: "k#_.1", Section: "_", Kind: KindRequirement, Keywords: []string{"SHOULD"}, Level: LevelRecommendation, Text: "Outside SHOULD be numbered."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestExtractStepsAndParents(t *testing.T) {
	src := `<section id="alg"><ol class="algorithm">
<li>Step one ` + kw("MUST") + ` run:
  <ol><li>Sub a</li><li><p>Sub b</p> text</li></ol>
</li>
<li></li>
<li>Step three<div class="note"><p>A note ` + kw("MAY") + ` say.</p></div></li>
</ol></section>`
	got := mustExtract(t, src)
	if len(got) != 5 {
		t.Fatalf("got %d statements: %#v", len(got), got)
	}
	checks := []struct {
		id, kind, text, parent string
		informative            bool
	}{
		{"k#alg.1", KindStep, "Step one MUST run:", "", false},
		{"k#alg.2", KindStep, "Sub a", "k#alg.1", false},
		{"k#alg.3", KindStep, "Sub b text", "k#alg.1", false},
		{"k#alg.4", KindStep, "Step three", "", false},
		{"k#alg.5", KindRequirement, "A note MAY say.", "", true},
	}
	for i, c := range checks {
		st := got[i]
		if st.ID != c.id || st.Kind != c.kind || st.Text != c.text || st.Parent != c.parent || st.Informative != c.informative {
			t.Errorf("statement %d = %#v, want %+v", i, st, c)
		}
	}
	if got[4].InformativeReason != "class note" {
		t.Errorf("reason = %q", got[4].InformativeReason)
	}
}

func TestExtractStepParentSkipsEmptyStep(t *testing.T) {
	src := `<section id="s"><ol class="algorithm"><li><ol><li>Inner</li></ol></li></ol></section>`
	got := mustExtract(t, src)
	if len(got) != 1 || got[0].Parent != "" || got[0].ID != "k#s.1" {
		t.Fatalf("got %#v", got)
	}
}

func TestExtractTerms(t *testing.T) {
	src := `<section id="t"><dl>
<dt><code>id</code></dt><dd><p>The id ` + kw("MUST") + ` exist.</p></dd>
<dt>other</dt><dd>Other ` + kw("SHOULD") + ` be.</dd>
</dl>
<table><tr><th>Name</th><th>Rule</th></tr>
<tr><td>service</td><td>Value ` + kw("MUST") + ` be ASCII.</td></tr></table>
<dd>Orphan ` + kw("MAY") + ` be.</dd>
<td>Orphan cell ` + kw("MAY") + ` be.</td>
</section>`
	got := mustExtract(t, src)
	terms := []string{"id", "other", "service", "", ""}
	if len(got) != len(terms) {
		t.Fatalf("got %d statements: %#v", len(got), got)
	}
	for i, term := range terms {
		if got[i].Term != term {
			t.Errorf("statement %d term = %q, want %q", i, got[i].Term, term)
		}
	}
}

func TestExtractInformative(t *testing.T) {
	src := `<section id="intro" class="informative">
<p>Intro ` + kw("MUST") + ` be informative.</p>
<section id="conformance"><p>The key words ` + kw("MUST") + ` are read.</p>
<div class="example"><p>Example ` + kw("MUST") + ` stay informative.</p></div></section>
</section>
<section id="plain"><p><em>This section is non-normative.</em></p><p>So ` + kw("SHOULD") + ` this.</p>
<section class="notoc"><p>Nested ` + kw("MAY") + ` inherit.</p></section></section>
<section id="outer"><section><p>This section is non-normative.</p><p>Anon ` + kw("MAY") + ` be.</p></section></section>
<section id="norm"><div class="issue"><p>Issue ` + kw("MUST") + ` x.</p></div><div class="advisement">Adv ` + kw("MUST") + ` y.</div></section>`
	got := mustExtract(t, src)
	want := []struct {
		id     string
		reason string
	}{
		{"k#intro.1", "class informative"},
		{"k#conformance.1", ""},
		{"k#conformance.2", "class example"},
		{"k#plain.1", "non-normative section plain"},
		{"k#plain.2", "non-normative section plain"},
		{"k#outer.1", "non-normative section"},
		{"k#norm.1", "class issue"},
		{"k#norm.2", "class advisement"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d statements: %#v", len(got), got)
	}
	for i, w := range want {
		if got[i].ID != w.id || got[i].InformativeReason != w.reason || got[i].Informative != (w.reason != "") {
			t.Errorf("statement %d = %s %q, want %s %q", i, got[i].ID, got[i].InformativeReason, w.id, w.reason)
		}
	}
}

func TestExtractToleratesBrokenMarkup(t *testing.T) {
	src := `<section id="x"><p>Unclosed ` + kw("MUST") + ` works</span></p><p>Second ` + kw("MAY") + ` too`
	got := mustExtract(t, src)
	if len(got) != 2 || got[1].Text != "Second MAY too" {
		t.Fatalf("got %#v", got)
	}
}

func TestExtractVoidAndSelfClosing(t *testing.T) {
	src := `<section id="v"><p>Line<br>break ` + kw("MUST") + `<img src="a.png"/> hold.</p></section>`
	got := mustExtract(t, src)
	if len(got) != 1 || got[0].Text != "Linebreak MUST hold." {
		t.Fatalf("got %#v", got)
	}
}

func TestExtractEmptyKey(t *testing.T) {
	if _, err := Extract("", []byte("<p></p>")); err == nil {
		t.Fatal("empty key accepted")
	}
}

func TestSplitSentences(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"One. Two.", []string{"One.", "Two."}},
		{"See e.g. This stays. Next.", []string{"See e.g. This stays.", "Next."}},
		{"He said \"stop.\" Then left.", []string{"He said \"stop.\"", "Then left."}},
		{"Version 1.1 is here. 2 more.", []string{"Version 1.1 is here.", "2 more."}},
		{"lower. case continues.", []string{"lower. case continues."}},
		{"Ends with dot.", []string{"Ends with dot."}},
		{"Trailing dot. ", []string{"Trailing dot."}},
		{"Ask? Yes! Done.", []string{"Ask?", "Yes!", "Done."}},
		{"Dot.x no split.", []string{"Dot.x no split."}},
		{"", nil},
	}
	for _, c := range cases {
		got := splitSentences(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitSentences(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestKeywordsOf(t *testing.T) {
	in := "a " + string(kwOpen) + "MUST" + string(kwClose) + " b " + string(kwOpen) + "MUST" + string(kwClose) + " " + string(kwOpen) + "MAY" + string(kwClose)
	kws, plain := keywordsOf(in)
	if !reflect.DeepEqual(kws, []string{"MUST", "MAY"}) || plain != "a MUST b MUST MAY" {
		t.Fatalf("got %q %q", kws, plain)
	}
	kws, plain = keywordsOf("x " + string(kwOpen) + "MUST")
	if kws != nil || plain != "x MUST" {
		t.Fatalf("unterminated marker: got %q %q", kws, plain)
	}
	kws, _ = keywordsOf(string(kwOpen) + " " + string(kwClose))
	if kws != nil {
		t.Fatalf("blank keyword recorded: %q", kws)
	}
}

func collect(src string) []token {
	tz := newTokenizer(src)
	var out []token
	for {
		tok, ok := tz.next()
		if !ok {
			return out
		}
		out = append(out, tok)
	}
}

func TestTokenizer(t *testing.T) {
	src := `<!DOCTYPE html><?xml x?><!-- c --><DIV Class="a b" data-x=unq hidden id='q'>t&lt;x</div>` +
		`<script>if (a<b) {}</script><br/>< lone<p/ =bad x="&amp;">`
	toks := collect(src)
	types := []tokenType{doctypeToken, doctypeToken, commentToken, startTagToken, textToken, endTagToken,
		startTagToken, endTagToken, selfClosingTagToken, textToken, textToken, startTagToken}
	if len(toks) != len(types) {
		t.Fatalf("got %d tokens: %#v", len(toks), toks)
	}
	for i, ty := range types {
		if toks[i].typ != ty {
			t.Errorf("token %d type = %d, want %d (%#v)", i, toks[i].typ, ty, toks[i])
		}
	}
	div := toks[3]
	if div.name != "div" || div.attrs["class"] != "a b" || div.attrs["data-x"] != "unq" || div.attrs["id"] != "q" {
		t.Errorf("div attrs = %#v", div.attrs)
	}
	if _, ok := div.attrs["hidden"]; !ok {
		t.Error("boolean attribute missing")
	}
	if toks[4].data != "t<x" {
		t.Errorf("text = %q", toks[4].data)
	}
	if toks[7].name != "script" {
		t.Errorf("script end = %#v", toks[7])
	}
	if toks[11].attrs["x"] != "&" {
		t.Errorf("p attrs = %#v", toks[11].attrs)
	}
}

func TestTokenizerUnterminated(t *testing.T) {
	cases := []string{
		"<!-- open",
		"<!doctype",
		"</p",
		`<p class="open`,
		"<p class='open",
		"<p a=",
		"<p a",
		"<script>never closed",
		"<p class=a class=b>",
	}
	for _, src := range cases {
		toks := collect(src)
		if len(toks) == 0 {
			t.Errorf("%q: no tokens", src)
		}
	}
	toks := collect("<p class=a class=b>")
	if toks[0].attrs["class"] != "a" {
		t.Errorf("duplicate attribute overrode the first: %#v", toks[0].attrs)
	}
	toks = collect("<script>a</scriptx>b</SCRIPT >c")
	if len(toks) != 3 || toks[1].typ != endTagToken || toks[2].data != "c" {
		t.Errorf("script end tag delimiter: %#v", toks)
	}
	toks = collect("<script>x")
	if len(toks) != 2 || toks[1].typ != endTagToken {
		t.Errorf("unterminated script: %#v", toks)
	}
}

func TestCollapseSpace(t *testing.T) {
	if got := collapseSpace("  a \n\t b  "); got != "a b" {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(nonNormativeSentence, "non-normative") {
		t.Fatal("unexpected marker sentence")
	}
}

func TestLevelOf(t *testing.T) {
	for _, tc := range []struct {
		kws  []string
		want string
	}{
		{nil, LevelRequirement},
		{[]string{"MUST"}, LevelRequirement},
		{[]string{"MAY"}, LevelRequirement},
		{[]string{"SHOULD"}, LevelRecommendation},
		{[]string{"SHOULD NOT"}, LevelRecommendation},
		{[]string{"RECOMMENDED"}, LevelRecommendation},
		{[]string{"NOT RECOMMENDED"}, LevelRecommendation},
		{[]string{"OPTIONAL", "SHOULD"}, LevelRecommendation},
		{[]string{"MUST", "SHOULD"}, LevelRequirement},
		{[]string{"SHOULD", "SHALL NOT"}, LevelRequirement},
	} {
		if got := LevelOf(tc.kws); got != tc.want {
			t.Errorf("LevelOf(%q) = %s, want %s", tc.kws, got, tc.want)
		}
	}
}
