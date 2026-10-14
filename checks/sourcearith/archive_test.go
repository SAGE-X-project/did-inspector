package sourcearith

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

func archive(t *testing.T, names []string, contents []string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for i, name := range names {
		f, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = f.Write([]byte(contents[i]))
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestArchiveHashAndCompleteSourceSelection(t *testing.T) {
	data := archive(t, []string{"m@v1/alg/z.go", "m@v1/alg/a.go", "m@v1/alg/a_test.go", "m@v1/README"}, []string{"z", "a", "test", "readme"})
	files, sum, e := ArchiveFiles(data, "m@v1")
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	for _, name := range []string{"README", "alg/a.go", "alg/a_test.go", "alg/z.go"} {
		d := sha256.Sum256(files[name])
		_, _ = fmt.Fprintf(h, "%x  m@v1/%s\n", d, name)
	}
	if sum != "h1:"+base64.StdEncoding.EncodeToString(h.Sum(nil)) {
		t.Fatal(sum)
	}
	selected := SourceFiles(files, []string{"alg"})
	if len(selected) != 2 || string(selected["alg/a.go"]) != "a" {
		t.Fatal(selected)
	}
}
func TestInvalidModuleArchives(t *testing.T) {
	var empty bytes.Buffer
	w := zip.NewWriter(&empty)
	_ = w.Close()
	for _, data := range [][]byte{nil, empty.Bytes(), archive(t, []string{"wrong/a.go"}, []string{"x"}), archive(t, []string{"m@v1/a.go", "m@v1/a.go"}, []string{"a", "b"}), archive(t, []string{"m@v1/../a.go"}, []string{"x"}), archive(t, []string{"m@v1/dir/"}, []string{""}), archive(t, []string{"m@v1/a\nb.go"}, []string{"x"})} {
		if _, _, e := ArchiveFiles(data, "m@v1"); e == nil {
			t.Fatal("invalid ZIP accepted")
		}
	}
	// Ordinary incomplete/corrupted local artifact; no untrusted endpoint.
	data := archive(t, []string{"m@v1/a.go"}, []string{"content"})
	z, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	offset, _ := z.File[0].DataOffset()
	data[int(offset)] ^= 0xff
	if _, _, e := ArchiveFiles(data, "m@v1"); e == nil {
		t.Fatal("corrupt content accepted")
	}
}
