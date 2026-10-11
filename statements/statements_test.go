package statements

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sage-x-project/did-inspector/statements/extract"
	"github.com/sage-x-project/did-inspector/statements/gen"
)

// TestSourcesMatchPins fails when a pinned publication's bytes change.
func TestSourcesMatchPins(t *testing.T) {
	for _, src := range Sources() {
		data, err := os.ReadFile(filepath.Join(gen.SourcesDir, src.File))
		if err != nil {
			t.Fatalf("%s: %v", src.Key, err)
		}
		if err := gen.VerifySource(src, data); err != nil {
			t.Errorf("%s: %v", src.Key, err)
		}
	}
}

// TestStatementFilesUpToDate re-runs the extractor on the pinned sources and
// fails when the committed statement files differ from its output.
func TestStatementFilesUpToDate(t *testing.T) {
	for _, src := range Sources() {
		_, want, err := gen.Render(".", src)
		if err != nil {
			t.Fatalf("%s: %v", src.Key, err)
		}
		got, err := os.ReadFile(gen.FileName(src.Key))
		if err != nil {
			t.Fatalf("%s: %v", src.Key, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run go generate ./statements", gen.FileName(src.Key))
		}
		embedded, err := embedded.ReadFile(gen.FileName(src.Key))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded, want) {
			t.Errorf("embedded %s differs from the extractor output", gen.FileName(src.Key))
		}
	}
}

func TestDocumentsCarryPinnedHashes(t *testing.T) {
	docs, err := LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != len(Sources()) {
		t.Fatalf("got %d documents, want %d", len(docs), len(Sources()))
	}
	for i, d := range docs {
		src := Sources()[i]
		if d.Key != src.Key || d.SHA256 != src.SHA256 || d.URL != src.URL {
			t.Errorf("document %s does not carry the pin of %s", d.Key, src.Key)
		}
		if len(d.Statements) == 0 {
			t.Errorf("%s: no statements", d.Key)
		}
		seen := map[string]bool{}
		for _, st := range d.Statements {
			if !strings.HasPrefix(st.ID, d.Key+"#") {
				t.Errorf("%s: id %s lacks the spec key", d.Key, st.ID)
			}
			if seen[st.ID] {
				t.Errorf("%s: duplicate id %s", d.Key, st.ID)
			}
			seen[st.ID] = true
			if st.Parent != "" && !seen[st.Parent] {
				t.Errorf("%s: parent %s of %s is not an earlier statement", d.Key, st.Parent, st.ID)
			}
		}
	}
}

func TestScopeCoversEveryStatement(t *testing.T) {
	docs, err := LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := Scope()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, d := range docs {
		for _, st := range d.Statements {
			ids[st.ID] = true
			dec, ok := scope[st.ID]
			if !ok {
				t.Errorf("no scope decision for %s", st.ID)
				continue
			}
			if err := dec.Validate(); err != nil {
				t.Errorf("%s: %v", st.ID, err)
			}
			if dec.Level != st.Level || st.Level != extract.LevelOf(st.Keywords) {
				t.Errorf("%s: scope level %q, statement level %q", st.ID, dec.Level, st.Level)
			}
			if st.Informative && dec.Scope != ScopeNotCheckable {
				t.Errorf("%s is informative but scoped %s", st.ID, dec.Scope)
			}
		}
	}
	for id := range scope {
		if !ids[id] {
			t.Errorf("scope decision for unknown statement %s", id)
		}
	}
}

func TestScopeFileIsCanonical(t *testing.T) {
	docs, err := LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := Scope()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := gen.MergeScope(docs, scope, false)
	if err != nil {
		t.Fatal(err)
	}
	want, err := gen.EncodeScope(entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := embedded.ReadFile(gen.ScopeFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("scope.json is not in canonical order and form; run go generate ./statements")
	}
}

func TestCountByScope(t *testing.T) {
	counts, err := CountByScope()
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != len(Sources()) {
		t.Fatalf("got %d count rows", len(counts))
	}
	for _, c := range counts {
		if c.Undecided != 0 {
			t.Errorf("%s: %d undecided statements", c.Key, c.Undecided)
		}
		if c.Checked+c.NotCheckable+c.Pending != c.Total {
			t.Errorf("%s: counts do not add up: %+v", c.Key, c)
		}
	}
}

func TestCountByLevel(t *testing.T) {
	all, err := CountByScope()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := CountByLevel()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(all)*len(Levels()) {
		t.Fatalf("got %d rows", len(rows))
	}
	for i, a := range all {
		req, rec := rows[2*i], rows[2*i+1]
		if req.Key != a.Key || rec.Key != a.Key || req.Level != LevelRequirement || rec.Level != LevelRecommendation {
			t.Fatalf("rows %+v %+v for %s", req, rec, a.Key)
		}
		if req.Total+rec.Total != a.Total || req.Checked+rec.Checked != a.Checked || req.Pending+rec.Pending != a.Pending ||
			req.NotCheckable+rec.NotCheckable != a.NotCheckable {
			t.Errorf("%s: level rows %+v %+v do not add up to %+v", a.Key, req, rec, a)
		}
	}
}

func TestLoadUnknownKey(t *testing.T) {
	if _, err := Load("nope"); err == nil {
		t.Fatal("Load accepted an unknown key")
	}
}

func withFiles(t *testing.T, m fstest.MapFS) {
	t.Helper()
	old := files
	files = m
	t.Cleanup(func() { files = old })
}

func TestReadErrors(t *testing.T) {
	withFiles(t, fstest.MapFS{})
	if _, err := LoadAll(); err == nil {
		t.Error("LoadAll succeeded without files")
	}
	if _, err := Scope(); err == nil {
		t.Error("Scope succeeded without files")
	}
	if _, err := CountByScope(); err == nil {
		t.Error("CountByScope succeeded without files")
	}
}

func TestDecodeErrors(t *testing.T) {
	m := fstest.MapFS{gen.ScopeFile: {Data: []byte("[")}}
	for _, s := range Sources() {
		m[gen.FileName(s.Key)] = &fstest.MapFile{Data: []byte("{}")}
	}
	m[gen.FileName(KeyCore10)] = &fstest.MapFile{Data: []byte("{")}
	withFiles(t, m)
	if _, err := Load(KeyCore10); err == nil {
		t.Error("Load decoded a broken file")
	}
	if _, err := Scope(); err == nil {
		t.Error("Scope decoded a broken file")
	}
	m[gen.FileName(KeyCore10)] = &fstest.MapFile{Data: []byte("{}")}
	if _, err := CountByScope(); err == nil {
		t.Error("CountByScope decoded a broken scope")
	}
}

func TestCountUndecided(t *testing.T) {
	m := fstest.MapFS{gen.ScopeFile: {Data: []byte(`{"core10#a.2":{"scope":"checked","reason":"r"}}`)}}
	for _, s := range Sources() {
		m[gen.FileName(s.Key)] = &fstest.MapFile{Data: []byte(`{"key":"` + s.Key + `"}`)}
	}
	m[gen.FileName(KeyCore10)] = &fstest.MapFile{Data: []byte(`{"key":"core10","statements":[{"id":"core10#a.1"},{"id":"core10#a.2"}]}`)}
	withFiles(t, m)
	counts, err := CountByScope()
	if err != nil {
		t.Fatal(err)
	}
	if counts[0].Undecided != 1 || counts[0].Checked != 1 || counts[0].Total != 2 {
		t.Fatalf("got %+v", counts[0])
	}
}
