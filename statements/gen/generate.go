package gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sage-x-project/did-inspector/statements/extract"
)

// ExtractorVersion names the extraction method recorded in every statement
// file. Change it when a change to the extractor changes its output.
const ExtractorVersion = "did-inspector-extract/2"

// SourcesDir is the directory, relative to the statements directory, that
// holds the pinned publications.
const SourcesDir = "sources"

// Document is the content of one statement file, statements/<key>.json.
type Document struct {
	Key        string              `json:"key"`
	Title      string              `json:"title"`
	URL        string              `json:"url"`
	Source     string              `json:"source"`
	SHA256     string              `json:"sha256"`
	Extractor  string              `json:"extractor"`
	Statements []extract.Statement `json:"statements"`
}

// HashMismatchError reports a source whose bytes do not match the pin.
type HashMismatchError struct {
	File   string
	Pinned string
	Actual string
}

func (e *HashMismatchError) Error() string {
	return fmt.Sprintf("source %s: SHA-256 %s does not match pinned %s", e.File, e.Actual, e.Pinned)
}

// SHA256Hex returns the hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// VerifySource checks data against the pin of src.
func VerifySource(src Source, data []byte) error {
	if got := SHA256Hex(data); got != src.SHA256 {
		return &HashMismatchError{File: src.File, Pinned: src.SHA256, Actual: got}
	}
	return nil
}

// Build verifies data against the pin of src and extracts its statements.
func Build(src Source, data []byte) (Document, error) {
	if err := VerifySource(src, data); err != nil {
		return Document{}, err
	}
	sts, err := extract.Extract(src.Key, data)
	if err != nil {
		return Document{}, fmt.Errorf("extract %s: %w", src.Key, err)
	}
	return Document{
		Key:        src.Key,
		Title:      src.Title,
		URL:        src.URL,
		Source:     SourcesDir + "/" + src.File,
		SHA256:     src.SHA256,
		Extractor:  ExtractorVersion,
		Statements: sts,
	}, nil
}

// Encode renders a document as indented JSON with a trailing newline.
func Encode(doc Document) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// FileName returns the statement file name for a spec key.
func FileName(key string) string {
	return key + ".json"
}

// Render reads the pinned source of src from dir/sources and returns the
// encoded statement document.
func Render(dir string, src Source) (Document, []byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, SourcesDir, src.File))
	if err != nil {
		return Document{}, nil, err
	}
	doc, err := Build(src, data)
	if err != nil {
		return Document{}, nil, err
	}
	out, err := Encode(doc)
	if err != nil {
		return Document{}, nil, err
	}
	return doc, out, nil
}

// Generate writes dir/<key>.json for every pinned source and returns the
// generated documents in source order.
func Generate(dir string) ([]Document, error) {
	var docs []Document
	for _, src := range Sources() {
		doc, out, err := Render(dir, src)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, FileName(src.Key)), out, 0o644); err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	return docs, nil
}
