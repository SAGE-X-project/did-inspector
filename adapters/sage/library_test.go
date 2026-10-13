package sage

import (
	"github.com/sage-x-project/did-inspector/profiles/sageresolution"
	"strings"
	"testing"
)

func TestActualLibrarySyntax(t *testing.T) {
	s := &Subject{}
	for _, q := range []sageresolution.SyntaxRequest{{Kind: "did", Input: "did:example:123"}, {Kind: "url", Input: "did:example:123/a?q=1#f"}, {Kind: "reference", Input: "../c", Base: "did:example:123/a/b?q=1#f"}} {
		r, e := s.InspectSyntax(t.Context(), q)
		if e != nil || r.Error != "" || r.Operation == "" || r.Request != q {
			t.Fatal(r, e)
		}
		want := q.Input
		if q.Kind == "reference" {
			want = "did:example:123/c"
		}
		if r.Value != want {
			t.Fatal(r)
		}
		q.Input = "%zz"
		r, e = s.InspectSyntax(t.Context(), q)
		if e != nil || r.Error == "" {
			t.Fatal(r, e)
		}
	}
	for _, q := range []sageresolution.SyntaxRequest{{Kind: "other"}, {Kind: "reference", Base: "invalid"}} {
		if _, e := s.InspectSyntax(t.Context(), q); e == nil {
			t.Fatal("adapter dispatch accepted")
		}
	}
}
func TestActualLibraryCodec(t *testing.T) {
	s := &Subject{}
	q := sageresolution.CodecRequest{Name: "Ed25519", Key: make([]byte, 32), Encoded: "z"}
	r, e := s.InspectCodec(t.Context(), q)
	if e != nil || r.EncodeError != "" || r.DecodeError == "" || !strings.HasPrefix(r.Encoded, "z") {
		t.Fatal(r, e)
	}
	q.Encoded = r.Encoded
	r, e = s.InspectCodec(t.Context(), q)
	if e != nil || r.DecodeError != "" || len(r.Decoded) != 32 || r.DecodeName != "Ed25519" {
		t.Fatal(r, e)
	}
	q.Key = nil
	r, e = s.InspectCodec(t.Context(), q)
	if e != nil || r.EncodeError == "" || r.Encoded != "" {
		t.Fatal(r, e)
	}
	q.Secret = true
	q.Key = make([]byte, 32)
	r, e = s.InspectCodec(t.Context(), q)
	if e != nil || r.DecodeError == "" || !r.Secret {
		t.Fatal("cross-role", r, e)
	}
	q.Encoded = r.Encoded
	r, e = s.InspectCodec(t.Context(), q)
	if e != nil || r.DecodeError != "" || !r.DecodeSecret {
		t.Fatal(r, e)
	}
	q.Name = "unsupported"
	if _, e = s.InspectCodec(t.Context(), q); e == nil {
		t.Fatal("missing row")
	}
}
