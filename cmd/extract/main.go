// Command extract regenerates the statement files from the pinned
// publications and adds an initial scope decision for every new statement.
//
// Usage:
//
//	go run ./cmd/extract [-dir statements] [-prune]
//
// It verifies the SHA-256 of each pinned source, writes <dir>/<key>.json for
// each spec key, and updates <dir>/scope.json: existing decisions are kept,
// new statements get the initial decision, and decisions for statements that
// no longer exist are an error unless -prune is given.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sage-x-project/did-inspector/statements/gen"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "statements", "statements directory holding sources/")
	prune := fs.Bool("prune", false, "drop scope decisions for statements that no longer exist")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := generate(*dir, *prune, stdout); err != nil {
		_, _ = fmt.Fprintln(stderr, "extract:", err)
		return 1
	}
	return 0
}

func generate(dir string, prune bool, stdout io.Writer) error {
	docs, err := gen.Generate(dir)
	if err != nil {
		return err
	}
	scopePath := filepath.Join(dir, gen.ScopeFile)
	existing, err := gen.ReadScope(scopePath)
	if err != nil {
		return err
	}
	entries, err := gen.MergeScope(docs, existing, prune)
	if err != nil {
		return err
	}
	data, err := gen.EncodeScope(entries)
	if err != nil {
		return err
	}
	if err := os.WriteFile(scopePath, data, 0o644); err != nil {
		return err
	}
	var b strings.Builder
	for _, d := range docs {
		fmt.Fprintf(&b, "%s: %d statements\n", d.Key, len(d.Statements))
	}
	fmt.Fprintf(&b, "%s: %d decisions\n", gen.ScopeFile, len(entries))
	_, err = io.WriteString(stdout, b.String())
	return err
}
