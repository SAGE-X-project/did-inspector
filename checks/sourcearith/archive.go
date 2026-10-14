// Package sourcearith inspects fixed source data, not executable subject code.
package sourcearith

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// ArchiveFiles verifies module ZIP names and calculates Go's h1 content digest.
// Returned bytes are data only; no copied subject implementation is executed.
func ArchiveFiles(data []byte, prefix string) (map[string][]byte, string, error) {
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return nil, "", e
	}
	files := map[string][]byte{}
	total := int64(0)
	for _, f := range z.File {
		if !strings.HasPrefix(f.Name, prefix+"/") || path.Clean(f.Name) != f.Name || strings.ContainsAny(f.Name, "\n\r\\") || f.FileInfo().IsDir() || !f.Mode().IsRegular() || len(files) >= 10000 {
			return nil, "", fmt.Errorf("invalid module ZIP entry %q", f.Name)
		}
		name := strings.TrimPrefix(f.Name, prefix+"/")
		if _, dup := files[name]; dup {
			return nil, "", fmt.Errorf("duplicate module ZIP entry")
		}
		reader, e := f.Open()
		if e != nil {
			return nil, "", e
		}
		b, e := io.ReadAll(io.LimitReader(reader, 16<<20))
		closeErr := reader.Close()
		total += int64(len(b))
		if e != nil || closeErr != nil || len(b) >= 16<<20 || total > 64<<20 {
			return nil, "", fmt.Errorf("invalid or oversized module ZIP content")
		}
		files[name] = b
	}
	if len(files) == 0 {
		return nil, "", fmt.Errorf("empty module ZIP")
	}
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		digest := sha256.Sum256(files[name])
		_, _ = fmt.Fprintf(h, "%x  %s/%s\n", digest, prefix, name)
	}
	return files, "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// SourceFiles returns the complete production Go files in selected packages.
func SourceFiles(files map[string][]byte, dirs []string) map[string][]byte {
	out := map[string][]byte{}
	for name, b := range files {
		for _, dir := range dirs {
			if path.Dir(name) == dir && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
				out[name] = b
			}
		}
	}
	return out
}
