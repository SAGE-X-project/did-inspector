package sage

import (
	"encoding/json"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualLibraryValues(t *testing.T) {
	s, _ := identify(pinned)
	p, e := sageresolution.Profile("did-1.1")
	if e != nil {
		t.Fatal(e)
	}
	cases, calls := 0, 0
	for _, c := range p.Cases {
		if !strings.Contains(c.ID, "/remaining-value-") {
			continue
		}
		cases++
		for _, o := range c.Run(t.Context(), s) {
			if o.Verdict != core.Pass {
				t.Fatal(c.ID, o.Statement, o.Verdict)
			}
			var v []sageresolution.LibraryValueResult
			if json.Unmarshal([]byte(o.Observed), &v) != nil {
				t.Fatal("lost raw")
			}
			calls += len(v)
		}
	}
	if cases != 16 || calls != 51 {
		t.Fatal(cases, calls)
	}
}
func TestLibraryValueAdapterBoundaries(t *testing.T) {
	s, _ := identify(pinned)
	for _, q := range []sageresolution.LibraryValueRequest{{Kind: "unknown"}, {Kind: "document-metadata", Subject: "bad"}} {
		if _, e := s.InspectLibraryValue(t.Context(), q); e == nil {
			t.Fatal(q)
		}
	}
	for _, kind := range []string{"document-metadata", "resolution-metadata", "dereferencing-metadata", "resolution-options"} {
		q := sageresolution.LibraryValueRequest{Kind: kind, Subject: "did:sage:web:registry.example:agent-1", Input: []byte(`{`)}
		out, e := s.InspectLibraryValue(t.Context(), q)
		if e != nil || out.ReadError == "" || out.Validator != "" || out.Writer != "" {
			t.Fatal(kind, out, e)
		}
	}
}
