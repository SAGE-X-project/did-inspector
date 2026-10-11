package didgo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/did11"
)

func TestRetrieveVerificationMethod(t *testing.T) {
	ctx := context.Background()
	s := New()
	if err := s.LoadFixtureRegistry(did11.LoadFixtures().Registry); err != nil {
		t.Fatal(err)
	}
	r, err := s.RetrieveVerificationMethod(ctx, "did:example:relationships#key-1", "authentication", nil)
	if err != nil || r.Error != nil || r.VerificationMethod == nil || str(*r.VerificationMethod, "id") != "did:example:relationships#key-1" {
		t.Fatalf("retrieve = %+v %v", r, err)
	}
	r, err = s.RetrieveVerificationMethod(ctx, "did:example:relationships#key-2", "authentication", map[string]any{"accept": "application/did"})
	if err != nil || r.Error == nil || !strings.HasSuffix(r.Error.Type, "#INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD") || r.Error.Title == "" {
		t.Fatalf("wrong relationship = %+v %v", r, err)
	}
	if r, _ := s.RetrieveVerificationMethod(ctx, "not a url", "authentication", nil); r.Error == nil || r.Error.Type != "" {
		t.Fatalf("not a URL = %+v", r)
	}
	if r, _ := s.RetrieveVerificationMethod(ctx, "#key-1", "authentication", nil); r.Error == nil || !strings.HasSuffix(r.Error.Type, "#INVALID_VERIFICATION_METHOD_URL") {
		t.Fatalf("relative = %+v", r)
	}
	if r, _ := s.RetrieveVerificationMethod(ctx, "did:example:deactivated#key-1", "authentication", nil); r.Error == nil || r.Error.Type != "" {
		t.Fatalf("deactivated = %+v", r)
	}
	if _, err := s.RetrieveVerificationMethod(ctx, "did:example:relationships#key-1", "signing", nil); err == nil {
		t.Fatal("unknown relationship accepted")
	}
	if _, err := s.RetrieveVerificationMethod(ctx, "did:example:relationships#key-1", "authentication", map[string]any{"verificationRelationship": "authentificación"}); err == nil {
		t.Fatal("invalid dereferencing options accepted")
	}
}

func TestProcessingError(t *testing.T) {
	if e := processingError(errors.New("plain")); e.Type != "" || e.Detail != "plain" {
		t.Fatalf("plain = %+v", e)
	}
}

func TestValidateVerificationMethod(t *testing.T) {
	s := New()
	secret, _ := checks.MultibaseEncode('z', append([]byte{0x80, 0x26}, make([]byte, 32)...))
	public, _ := checks.MultibaseEncode('z', append([]byte{0xed, 0x01}, make([]byte, 32)...))
	ok := mustDoc(t, `{"id":"did:example:vm#key-1","type":"Multikey","controller":"did:example:vm","secretKeyMultibase":"`+secret+`"}`)
	if f, err := s.ValidateVerificationMethod(ok, "1.1"); err != nil || len(f) != 0 {
		t.Fatalf("Ed25519 secret key: %+v %v", f, err)
	}
	pub := mustDoc(t, `{"id":"did:example:vm#key-1","type":"Multikey","controller":"did:example:vm","secretKeyMultibase":"`+public+`"}`)
	if f, _ := s.ValidateVerificationMethod(pub, "1.1"); len(f) != 1 || f[0].Path != "/secretKeyMultibase" {
		t.Fatalf("public key prefix as secret key: %+v", f)
	}
	for _, tc := range []struct{ vm, path string }{
		{`{"id":"did:example:vm#key-1","type":"JsonWebKey","controller":"did:example:vm","secretKeyJwk":"x"}`, "/secretKeyJwk"},
		{`{"id":"key-1","type":"Multikey","controller":"did:example:vm","secretKeyMultibase":"z0"}`, "/secretKeyMultibase"},
		{`{"id":"key-1","type":"Multikey","controller":"nope","secretKeyMultibase":"z0"}`, "/controller"},
		{`{"type":"Multikey","controller":"did:example:vm"}`, "/id"},
	} {
		f, err := s.ValidateVerificationMethod(mustDoc(t, tc.vm), "")
		if err != nil || len(f) != 1 || f[0].Path != tc.path {
			t.Errorf("%s: %+v %v", tc.vm, f, err)
		}
	}
	if _, err := s.ValidateVerificationMethod(ok, "9"); err == nil {
		t.Error("unknown version accepted")
	}
}

func TestInMethodAndHolder(t *testing.T) {
	for in, want := range map[string]string{
		"/verificationMethod/0/secretKeyJwk": "/secretKeyJwk",
		"/verificationMethod/secretKeyJwk":   "/secretKeyJwk",
		"/verificationMethod":                "",
		"/id":                                "/id",
	} {
		if got := inMethod(in); got != want {
			t.Errorf("inMethod(%q) = %q, want %q", in, got, want)
		}
	}
	if got := holderDID(mustDoc(t, `{"id":"#k","controller":"did:example:c"}`)); got != "did:example:c" {
		t.Errorf("controller holder = %q", got)
	}
	if got := holderDID(mustDoc(t, `{"id":"#k","controller":7}`)); got != vmHolder {
		t.Errorf("fallback holder = %q", got)
	}
}

func TestResolveDIDURLReference(t *testing.T) {
	s := New()
	got, err := s.ResolveDIDURLReference("did:example:123", "#key-1")
	if err != nil || got != "did:example:123#key-1" {
		t.Fatalf("resolve = %q %v", got, err)
	}
	if _, err := s.ResolveDIDURLReference("nope", "#k"); err == nil {
		t.Error("base that is not a DID accepted")
	}
	if _, err := s.ResolveDIDURLReference("did:example:123", "%zz"); err == nil {
		t.Error("malformed reference accepted")
	}
}

func TestProduceRepresentation(t *testing.T) {
	s := New()
	doc := mustDoc(t, `{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:123"}`)
	_, mt, err := s.ProduceRepresentation(doc, "1.0", "application/did+ld+json")
	if err != nil || mt != "application/did+ld+json" {
		t.Fatalf("JSON-LD = %q %v", mt, err)
	}
	if _, mt, err := s.ProduceRepresentation(mustDoc(t, `{"id":"did:example:123"}`), "", "application/did"); err != nil || mt != "application/did" {
		t.Fatalf("latest = %q %v", mt, err)
	}
	if _, _, err := s.ProduceRepresentation(doc, "1.0", "text/plain"); err == nil {
		t.Error("unknown media type accepted")
	}
	if _, _, err := s.ProduceRepresentation(doc, "7", "application/did"); err == nil {
		t.Error("unknown version accepted")
	}
	if _, _, err := s.ProduceRepresentation(mustDoc(t, `{"id":"nope"}`), "1.0", "application/did+json"); err == nil {
		t.Error("document did-go cannot hold accepted")
	}
	var _ core.RepresentationProducer = s
}
