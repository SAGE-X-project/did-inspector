// Package statements holds the normative statements the inspector extracted
// from the pinned W3C publications, together with the SHA-256 pins of those
// publications and the inspector's scope decision for every statement.
//
// The statement files are generated from the bytes in sources/ by
// `go generate ./statements` and embedded here. scope.json is maintained by
// hand; the generator only adds an initial decision for new statements.
package statements

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"

	"github.com/sage-x-project/did-inspector/statements/extract"
	"github.com/sage-x-project/did-inspector/statements/gen"
)

//go:generate go run ../cmd/extract -dir .

//go:embed core10.json did11-cr20260305.json cid10.json res10-crd20261001.json scope.json
var embedded embed.FS

// files is the file system the package reads; tests replace it.
var files fs.FS = embedded

// Statement is one extracted statement.
type Statement = extract.Statement

// Document is the content of one statement file.
type Document = gen.Document

// Source is one pinned publication.
type Source = gen.Source

// Decision is the scope decision for one statement.
type Decision = gen.Decision

// Scope values.
const (
	ScopeChecked      = gen.ScopeChecked
	ScopeNotCheckable = gen.ScopeNotCheckable
	ScopePending      = gen.ScopePending
)

// Statement levels.
const (
	LevelRequirement    = extract.LevelRequirement
	LevelRecommendation = extract.LevelRecommendation
)

// Levels returns the statement levels in report order.
func Levels() []string {
	return []string{LevelRequirement, LevelRecommendation}
}

// Spec keys of the pinned publications.
const (
	KeyCore10 = gen.KeyCore10
	KeyDID11  = gen.KeyDID11
	KeyCID10  = gen.KeyCID10
	KeyRes10  = gen.KeyRes10
)

// Sources returns the pinned publications in a fixed order.
func Sources() []Source {
	return gen.Sources()
}

// Load returns the embedded statement document for a spec key.
func Load(key string) (Document, error) {
	if _, ok := gen.SourceByKey(key); !ok {
		return Document{}, fmt.Errorf("statements: unknown spec key %q", key)
	}
	return decodeDocument(gen.FileName(key))
}

// LoadAll returns the embedded statement documents in source order.
func LoadAll() ([]Document, error) {
	var docs []Document
	for _, s := range gen.Sources() {
		d, err := Load(s.Key)
		if err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	return docs, nil
}

// Scope returns the embedded scope decisions keyed by statement id.
func Scope() (map[string]Decision, error) {
	data, err := fs.ReadFile(files, gen.ScopeFile)
	if err != nil {
		return nil, err
	}
	return gen.DecodeScope(data)
}

// Counts is the number of statements of one spec key, or of one level of
// one spec key, per scope.
type Counts struct {
	Key string `json:"key"`
	// Level is empty for the statements of every level.
	Level        string `json:"level,omitempty"`
	Total        int    `json:"total"`
	Checked      int    `json:"checked"`
	NotCheckable int    `json:"not_checkable"`
	Pending      int    `json:"pending"`
	Undecided    int    `json:"undecided"`
}

// CountByScope returns, per spec key in source order, the number of
// statements in each scope. Undecided counts statements without a decision,
// which a consistent tree never has.
func CountByScope() ([]Counts, error) {
	return count([]string{""}, func(Statement) string { return "" })
}

// CountByLevel returns, per spec key in source order and per level in the
// order of Levels, the number of statements in each scope.
func CountByLevel() ([]Counts, error) {
	return count(Levels(), func(st Statement) string { return extract.LevelOf(st.Keywords) })
}

// count tallies the statements of each spec key into one row per entry of
// rows; rowOf names the row of a statement.
func count(rows []string, rowOf func(Statement) string) ([]Counts, error) {
	docs, err := LoadAll()
	if err != nil {
		return nil, err
	}
	scope, err := Scope()
	if err != nil {
		return nil, err
	}
	var out []Counts
	for _, d := range docs {
		byRow := make(map[string]*Counts, len(rows))
		for _, l := range rows {
			out = append(out, Counts{Key: d.Key, Level: l})
		}
		for i := len(out) - len(rows); i < len(out); i++ {
			byRow[out[i].Level] = &out[i]
		}
		for _, st := range d.Statements {
			if c, ok := byRow[rowOf(st)]; ok {
				c.add(scope[st.ID].Scope)
			}
		}
	}
	return out, nil
}

func (c *Counts) add(scope string) {
	c.Total++
	switch scope {
	case ScopeChecked:
		c.Checked++
	case ScopeNotCheckable:
		c.NotCheckable++
	case ScopePending:
		c.Pending++
	default:
		c.Undecided++
	}
}

func decodeDocument(name string) (Document, error) {
	data, err := fs.ReadFile(files, name)
	if err != nil {
		return Document{}, err
	}
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return Document{}, fmt.Errorf("statements: decode %s: %w", name, err)
	}
	return d, nil
}
