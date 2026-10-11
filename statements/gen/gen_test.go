package gen

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/statements/extract"
)

const sample = `<section id="s"><p>Values <em class="rfc2119">MUST</em> be strings.</p></section>`

func sampleSource(data []byte) Source {
	return Source{Key: "t", Title: "T", URL: "https://example.test/", File: "t.html", SHA256: SHA256Hex(data)}
}

func writeSources(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, SourcesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, SourcesDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourcesAndLookup(t *testing.T) {
	srcs := Sources()
	if len(srcs) != 4 {
		t.Fatalf("got %d sources", len(srcs))
	}
	srcs[0].Key = "mutated"
	if Sources()[0].Key != KeyCore10 {
		t.Fatal("Sources exposes its backing array")
	}
	for _, k := range []string{KeyCore10, KeyDID11, KeyCID10, KeyRes10} {
		s, ok := SourceByKey(k)
		if !ok || s.Key != k || len(s.SHA256) != 64 || !strings.HasPrefix(s.URL, "https://www.w3.org/TR/") {
			t.Errorf("SourceByKey(%s) = %+v, %v", k, s, ok)
		}
	}
	if _, ok := SourceByKey("none"); ok {
		t.Error("unknown key found")
	}
}

func TestBuildAndVerify(t *testing.T) {
	data := []byte(sample)
	src := sampleSource(data)
	doc, err := Build(src, data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.SHA256 != src.SHA256 || doc.Source != "sources/t.html" || doc.Extractor != ExtractorVersion || len(doc.Statements) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
	_, err = Build(src, []byte(sample+" "))
	var mismatch *HashMismatchError
	if !errors.As(err, &mismatch) || !strings.Contains(err.Error(), "does not match pinned") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Build(Source{SHA256: SHA256Hex(data)}, data); err == nil {
		t.Fatal("Build accepted an empty key")
	}
}

func TestEncodeDoesNotEscapeHTML(t *testing.T) {
	out, err := Encode(Document{Key: "k", Statements: []extract.Statement{{Text: "a <b> & c"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "a <b> & c") || !strings.HasSuffix(string(out), "}\n") {
		t.Fatalf("out = %s", out)
	}
}

func TestRender(t *testing.T) {
	dir := t.TempDir()
	data := []byte(sample)
	writeSources(t, dir, map[string][]byte{"t.html": data})
	doc, out, err := Render(dir, sampleSource(data))
	if err != nil || len(doc.Statements) != 1 || len(out) == 0 {
		t.Fatalf("Render = %+v, %d bytes, %v", doc, len(out), err)
	}
	if _, _, err := Render(dir, Source{Key: "x", File: "missing.html"}); err == nil {
		t.Fatal("Render read a missing file")
	}
	bad := sampleSource(data)
	bad.SHA256 = strings.Repeat("0", 64)
	if _, _, err := Render(dir, bad); err == nil {
		t.Fatal("Render accepted a hash mismatch")
	}
}

func copyPinnedSources(t *testing.T, dir string) {
	t.Helper()
	files := map[string][]byte{}
	for _, s := range Sources() {
		data, err := os.ReadFile(filepath.Join("..", SourcesDir, s.File))
		if err != nil {
			t.Fatal(err)
		}
		files[s.File] = data
	}
	writeSources(t, dir, files)
}

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	copyPinnedSources(t, dir)
	docs, err := Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != len(Sources()) {
		t.Fatalf("got %d docs", len(docs))
	}
	for _, s := range Sources() {
		got, err := os.ReadFile(filepath.Join(dir, FileName(s.Key)))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join("..", FileName(s.Key)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s differs from the committed file", s.Key)
		}
	}
}

func TestGenerateErrors(t *testing.T) {
	if _, err := Generate(t.TempDir()); err == nil {
		t.Error("Generate succeeded without sources")
	}
	dir := t.TempDir()
	copyPinnedSources(t, dir)
	// A directory in place of the output file makes the write fail.
	if err := os.Mkdir(filepath.Join(dir, FileName(KeyCore10)), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir); err == nil {
		t.Error("Generate succeeded with an unwritable output")
	}
}

func TestInitialDecision(t *testing.T) {
	cases := []struct {
		st    extract.Statement
		scope string
		part  string
	}{
		{extract.Statement{Informative: true, InformativeReason: "class note", Keywords: []string{"MUST"}}, ScopeNotCheckable, "informative"},
		{extract.Statement{Text: "The key words MUST and MAY in this document are to be interpreted as described", Keywords: []string{"MUST"}}, ScopeNotCheckable, "RFC 2119"},
		{extract.Statement{Section: "security-requirements", Text: "Attacks MUST be discussed.", Keywords: []string{"MUST"}}, ScopeNotCheckable, "method specifications"},
		{extract.Statement{Text: "A DID method specification MUST define it.", Keywords: []string{"MUST"}}, ScopeNotCheckable, "method specifications"},
		{extract.Statement{Text: "A DID method MAY define formats.", Keywords: []string{"MAY"}}, ScopeNotCheckable, "method specifications"},
		{extract.Statement{Text: "When defining values, specification authors MAY add headers.", Keywords: []string{"MAY"}}, ScopeNotCheckable, "specification authors"},
		{extract.Statement{Text: "Types SHOULD be registered in the registries.", Keywords: []string{"SHOULD"}}, ScopeNotCheckable, "registries"},
		{extract.Statement{Text: "A representation MUST define rules.", Keywords: []string{"MUST"}}, ScopeNotCheckable, "representation"},
		{extract.Statement{Text: "A conforming consumer MAY accept options.", Keywords: []string{"MAY"}}, ScopeNotCheckable, "permission to the implementation"},
		{extract.Statement{Text: "The controller property is OPTIONAL.", Keywords: []string{"OPTIONAL"}}, ScopePending, "permission on data content"},
		{extract.Statement{Kind: extract.KindStep, Text: "Return the result."}, ScopePending, "algorithm step"},
		{extract.Statement{Kind: extract.KindRequirement, Text: "The value MUST be a string.", Keywords: []string{"MUST"}}, ScopePending, "requirement"},
		{extract.Statement{Kind: extract.KindRequirement, Text: "This input is REQUIRED, but the structure MAY be empty.", Keywords: []string{"REQUIRED", "MAY"}}, ScopePending, "requirement"},
	}
	for _, c := range cases {
		d := InitialDecision(c.st)
		if d.Scope != c.scope || !strings.Contains(d.Reason, c.part) {
			t.Errorf("InitialDecision(%q) = %+v, want %s containing %q", c.st.Text, d, c.scope, c.part)
		}
		if err := d.Validate(); err != nil {
			t.Errorf("invalid decision %+v: %v", d, err)
		}
	}
}

func TestDecisionValidate(t *testing.T) {
	if err := (Decision{Scope: "maybe", Reason: "r"}).Validate(); err == nil {
		t.Error("unknown scope accepted")
	}
	if err := (Decision{Scope: ScopePending, Reason: " "}).Validate(); err == nil {
		t.Error("blank reason accepted")
	}
	if err := (Decision{Scope: ScopeChecked, Reason: "case x"}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestMergeScope(t *testing.T) {
	docs := []Document{{Statements: []extract.Statement{
		{ID: "k#a.1", Kind: extract.KindRequirement, Text: "X MUST y.", Keywords: []string{"MUST"}},
		{ID: "k#a.2", Kind: extract.KindStep, Text: "Do."},
	}}}
	kept := Decision{Scope: ScopeChecked, Reason: "case c"}
	entries, err := MergeScope(docs, map[string]Decision{"k#a.1": kept}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Decision != kept || entries[1].Decision.Scope != ScopePending {
		t.Fatalf("entries = %+v", entries)
	}
	stale := map[string]Decision{"k#gone.2": kept, "k#gone.1": kept}
	_, err = MergeScope(docs, stale, false)
	var se *StaleScopeError
	if !errors.As(err, &se) || len(se.IDs) != 2 || se.IDs[0] != "k#gone.1" || !strings.Contains(se.Error(), "no longer exist") {
		t.Fatalf("err = %v", err)
	}
	entries, err = MergeScope(docs, stale, true)
	if err != nil || len(entries) != 2 {
		t.Fatalf("prune: %v %+v", err, entries)
	}
}

func TestEncodeDecodeScope(t *testing.T) {
	entries := []ScopeEntry{
		{ID: "k#a.2", Decision: Decision{ScopePending, "r <2>"}},
		{ID: "k#a.10", Decision: Decision{ScopeNotCheckable, "r1"}},
	}
	data, err := EncodeScope(entries)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"k#a.2\": {\"scope\":\"pending\",\"reason\":\"r <2>\"},\n  \"k#a.10\": {\"scope\":\"not-checkable\",\"reason\":\"r1\"}\n}\n"
	if string(data) != want {
		t.Fatalf("got %q", data)
	}
	m, err := DecodeScope(data)
	if err != nil || len(m) != 2 || m["k#a.10"].Scope != ScopeNotCheckable {
		t.Fatalf("decode = %v %v", m, err)
	}
	if _, err := EncodeScope([]ScopeEntry{{ID: "x", Decision: Decision{Scope: "bad", Reason: "r"}}}); err == nil {
		t.Fatal("invalid decision encoded")
	}
	if _, err := DecodeScope([]byte("[")); err == nil {
		t.Fatal("broken scope decoded")
	}
}

func TestReadScope(t *testing.T) {
	dir := t.TempDir()
	m, err := ReadScope(filepath.Join(dir, ScopeFile))
	if err != nil || len(m) != 0 {
		t.Fatalf("missing file: %v %v", m, err)
	}
	path := filepath.Join(dir, ScopeFile)
	if err := os.WriteFile(path, []byte(`{"a":{"scope":"pending","reason":"r"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err = ReadScope(path)
	if err != nil || m["a"].Scope != ScopePending {
		t.Fatalf("read: %v %v", m, err)
	}
	if _, err := ReadScope(dir); err == nil {
		t.Fatal("reading a directory succeeded")
	}
}
