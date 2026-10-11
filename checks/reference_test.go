package checks

import "testing"

func TestResolveDIDReference(t *testing.T) {
	const base = "did:example:123456789abcdefghi"
	for ref, want := range map[string]string{
		"#key-1":               base + "#key-1",
		"?service=agent":       base + "?service=agent",
		"?service=agent#frag":  base + "?service=agent#frag",
		"/path/to/resource":    base + "/path/to/resource",
		"path/to/resource":     base + "/path/to/resource",
		"/a/b/../c/./d":        base + "/a/c/d",
		"./key":                base + "/key",
		"../x":                 base + "/x",
		"":                     base,
		"/a/b/..":              base + "/a/",
		"/a/.":                 base + "/a/",
		".":                    base + "/",
		"did:other:xyz/a/../b": "did:other:xyz/b",
		"did:other:xyz?q=1#f":  "did:other:xyz?q=1#f",
		"/p?q=1#f":             base + "/p?q=1#f",
	} {
		got, err := ResolveDIDReference(base, ref)
		if err != nil || got != want {
			t.Errorf("%q = %q %v, want %q", ref, got, err, want)
		}
	}
	if _, err := ResolveDIDReference("not-a-did", "#k"); err == nil {
		t.Error("base that is not a DID accepted")
	}
	if _, err := ResolveDIDReference(base, "//host/p"); err == nil {
		t.Error("network-path reference accepted")
	}
}
