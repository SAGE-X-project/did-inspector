package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/statements/gen"
)

func copyTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, gen.SourcesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, s := range gen.Sources() {
		data, err := os.ReadFile(filepath.Join("..", "..", "statements", gen.SourcesDir, s.File))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, gen.SourcesDir, s.File), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRunGeneratesFilesAndKeepsScope(t *testing.T) {
	dir := copyTree(t)
	scope, err := os.ReadFile(filepath.Join("..", "..", "statements", gen.ScopeFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, gen.ScopeFile), scope, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, gen.ScopeFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, scope) {
		t.Error("regeneration changed an up-to-date scope.json")
	}
	if !strings.Contains(out.String(), "core10:") || !strings.Contains(out.String(), "scope.json:") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunStaleScope(t *testing.T) {
	dir := copyTree(t)
	stale := []byte(`{"core10#gone.1":{"scope":"pending","reason":"r"}}`)
	if err := os.WriteFile(filepath.Join(dir, gen.ScopeFile), stale, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"-dir", dir}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "no longer exist") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if code := run([]string{"-dir", dir, "-prune"}, &out, &errOut); code != 0 {
		t.Fatalf("prune exit %d: %s", code, errOut.String())
	}
}

func TestRunErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-bogus"}, &out, &errOut); code != 2 {
		t.Errorf("bad flag exit %d", code)
	}
	if code := run([]string{"-dir", t.TempDir()}, &out, &errOut); code != 1 {
		t.Errorf("missing sources exit %d", code)
	}
	dir := copyTree(t)
	if err := os.WriteFile(filepath.Join(dir, gen.ScopeFile), []byte("["), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-dir", dir}, &out, &errOut); code != 1 {
		t.Errorf("broken scope exit %d", code)
	}
	dir = copyTree(t)
	if err := os.Mkdir(filepath.Join(dir, gen.ScopeFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-dir", dir}, &out, &errOut); code != 1 {
		t.Errorf("unreadable scope exit %d", code)
	}
}

func TestRunScopeWriteAndValidationErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := copyTree(t)
	invalid := []byte(`{"core10#did-syntax.1":{"scope":"maybe","reason":"r"}}`)
	if err := os.WriteFile(filepath.Join(dir, gen.ScopeFile), invalid, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-dir", dir}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "unknown scope") {
		t.Errorf("invalid decision exit %d: %s", code, errOut.String())
	}
	if os.Geteuid() == 0 {
		t.Skip("file permissions do not stop root")
	}
	dir = copyTree(t)
	path := filepath.Join(dir, gen.ScopeFile)
	if err := os.WriteFile(path, []byte(`{}`), 0o444); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-dir", dir}, &out, &errOut); code != 1 {
		t.Errorf("read-only scope exit %d", code)
	}
}
