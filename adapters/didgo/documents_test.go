package didgo

import (
	"errors"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/representation"
)

const fullDoc11 = `{"id":"did:example:123",
 "controller":["did:example:ctl"],"alsoKnownAs":["https://example.com/me"],
 "verificationMethod":[{"id":"did:example:123#key-1","type":"Multikey","controller":"did:example:123",
   "publicKeyMultibase":"z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu","expires":"2030-01-01T00:00:00Z","label":"main"}],
 "authentication":["did:example:123#key-1",{"id":"did:example:123#key-2","type":"JsonWebKey","controller":"did:example:123",
   "publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}}],
 "service":[{"id":"did:example:123#svc","type":["A","B"],"serviceEndpoint":[{"uri":"https://example.com/a"},"https://example.com/b"],"note":true}],
 "extString":"s","extInt":42,"extDouble":1.5,"extWhole":2.0,"extNull":null,"extList":[1,"two",{"x":false}]}`

// TestConsumeProduceRoundTrip consumes a document with every kind of entry,
// produces it again and checks that the data model survives both
// translations.
func TestConsumeProduceRoundTrip(t *testing.T) {
	s := New()
	doc, info, err := s.Consume([]byte(fullDoc11), "application/did", "1.1", true)
	if err != nil {
		t.Fatal(err)
	}
	if info.MediaType != "application/did" || info.Version != "1.1" || info.RepresentationEntries.Len() != 0 {
		t.Errorf("info = %+v", info)
	}
	if v, _ := doc.Get("extWhole"); v.Number != "2.0" {
		t.Errorf("a whole double lost its type: %q", v.Number)
	}
	if ok, at := checks.EqualJSON(doc.Value(), mustDoc(t, fullDoc11).Value()); !ok {
		t.Errorf("consumed document differs at %q: %s", at, compact(t, doc))
	}
	data, mt, err := s.Produce(doc, "1.1")
	if err != nil || mt != "application/did" {
		t.Fatalf("Produce = %q, %v", mt, err)
	}
	again, _, err := s.Consume(data, mt, "1.1", true)
	if err != nil {
		t.Fatal(err)
	}
	if ok, at := checks.EqualJSON(again.Value(), doc.Value()); !ok {
		t.Errorf("round trip changed the document at %q:\n%s\n%s", at, compact(t, again), compact(t, doc))
	}
}

func TestConsumeRepresentationEntries(t *testing.T) {
	s := New()
	in := `{"@context":["https://www.w3.org/ns/did/v1.1","https://example.com/ctx"],"id":"did:example:1"}`
	doc, info, err := s.Consume([]byte(in), "application/did", "1.1", true)
	if err != nil {
		t.Fatal(err)
	}
	if ctx, ok := info.RepresentationEntries.Get("@context"); !ok || len(ctx.Array) != 2 {
		t.Errorf("@context not in the representation-specific entries: %s", compact(t, info.RepresentationEntries))
	}
	if _, ok := doc.Get("@context"); ok {
		t.Error("@context in the data model entries")
	}
	full := core.NewDocument(append(info.RepresentationEntries.Members, doc.Members...)...)
	data, _, err := s.Produce(full, "1.1")
	if err != nil || !strings.Contains(string(data), "https://example.com/ctx") {
		t.Errorf("layered @context not produced: %s %v", data, err)
	}
}

func TestConsumeErrors(t *testing.T) {
	s := New()
	if _, _, err := s.Consume([]byte(`{"id":"did:example:1"}`), "application/did", "2.0", true); err == nil {
		t.Error("unknown version accepted")
	}
	if _, _, err := s.Consume([]byte(`{"id":"did:example:1"`), "application/did", "1.1", true); err == nil {
		t.Error("malformed JSON accepted")
	}
	_, info, err := s.Consume([]byte(`{"id":"did:example:1"}`), "application/json", "", false)
	if err != nil || len(info.Notes) == 0 {
		t.Errorf("low-precision input: %v, notes %v", err, info.Notes)
	}
	_, info, err = s.Consume([]byte(`{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:1","foo":1}`), "application/did+ld+json", "1.0", true)
	if err != nil || !strings.Contains(strings.Join(info.Notes, ";"), "dropped term foo") {
		t.Errorf("dropped term not reported: %v %v", err, info.Notes)
	}
}

func TestConsumeNotes(t *testing.T) {
	notes := consumeNotes(representation.ConsumeInfo{
		Assumed:           true,
		LowPrecision:      &representation.LowPrecision{Declared: "application/json", Detected: "application/did"},
		UnexpectedContext: "https://example.com",
		DroppedTerms:      []string{"x"},
	})
	if len(notes) != 4 {
		t.Errorf("notes = %v", notes)
	}
}

func TestProduce(t *testing.T) {
	s := New()
	data, mt, err := s.Produce(mustDoc(t, `{"id":"did:example:1"}`), "1.0")
	if err != nil || mt != "application/did+json" || strings.Contains(string(data), "@context") {
		t.Errorf("1.0 JSON: %s %q %v", data, mt, err)
	}
	data, mt, err = s.Produce(mustDoc(t, `{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:1"}`), "1.0")
	if err != nil || mt != "application/did+ld+json" || !strings.Contains(string(data), "@context") {
		t.Errorf("1.0 JSON-LD: %s %q %v", data, mt, err)
	}
	if _, mt, err := s.Produce(mustDoc(t, `{"id":"did:example:1"}`), ""); err != nil || mt != "application/did" {
		t.Errorf("no version: %q %v", mt, err)
	}
	if _, _, err := s.Produce(mustDoc(t, `{"id":"did:example:1"}`), "x"); err == nil {
		t.Error("unknown version accepted")
	}
	if _, _, err := s.Produce(mustDoc(t, `{"id":"not a did"}`), "1.1"); err == nil {
		t.Error("a document with an invalid id produced")
	}
	if _, _, err := s.Produce(mustDoc(t, `{"id":"did:example:1","service":[{"type":"X","serviceEndpoint":"https://example.com/"}]}`), "1.0"); err == nil {
		t.Error("a DID Core 1.0 service without id produced")
	}
	bad := core.NewDocument(core.M("id", core.Number("")))
	if _, _, err := s.Produce(bad, "1.1"); err == nil {
		t.Error("a document that cannot be written as JSON produced")
	}
}

func TestValidate(t *testing.T) {
	s := New()
	fs, err := s.Validate(mustDoc(t, `{"id":"did:example:1"}`), "")
	if err != nil || len(fs) != 0 {
		t.Errorf("valid document: %v %v", fs, err)
	}
	fs, err = s.Validate(mustDoc(t, `{"id":"did:example:1","controller":"not a did"}`), "1.1")
	if err != nil || len(fs) != 1 || fs[0].Message == "" {
		t.Errorf("invalid controller: %v %v", fs, err)
	}
	fs, err = s.Validate(mustDoc(t, `{"id":"did:example:1","service":[{"id":"#s","type":"X","serviceEndpoint":"https://example.com/"}]}`), "1.0")
	if err != nil || len(fs) == 0 {
		t.Errorf("DID Core 1.0 relative service id: %v %v", fs, err)
	}
	if _, err := s.Validate(mustDoc(t, `{"id":"did:example:1"}`), "3"); err == nil {
		t.Error("unknown version accepted")
	}
}

func TestErrorFinding(t *testing.T) {
	cases := []struct {
		err  error
		code string
		path string
	}{
		{&document.ConformanceError{Code: document.CodeInvalidVerificationMethod, Property: "verificationMethod[0].type", Statement: "s#1"}, "s#1", "/verificationMethod/0/type"},
		{&document.ConformanceError{Code: document.CodeInvalidVerificationMethod}, "INVALID_VERIFICATION_METHOD", ""},
		{&consumer.Error{Property: "service[1]", Reason: "r"}, "consumer", "/service/1"},
		{&representation.DetectError{Step: 3, Reason: "r"}, "detect-step-3", ""},
		{errors.New("other"), "did-go", ""},
	}
	for _, c := range cases {
		f := errorFinding(c.err)
		if f.Code != c.code || f.Path != c.path || f.Message == "" {
			t.Errorf("errorFinding(%v) = %+v", c.err, f)
		}
	}
}

func TestPointer(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"id":                     "/id",
		"service[0].id":          "/service/0/id",
		"a[1][2].b~c/d":          "/a/1/2/b~0c~1d",
		"verificationMethod[10]": "/verificationMethod/10",
	}
	for in, want := range cases {
		if got := pointer(in); got != want {
			t.Errorf("pointer(%q) = %q, want %q", in, got, want)
		}
	}
}
