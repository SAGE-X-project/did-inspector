package coretest

import (
	"context"
	"errors"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

var ctx = context.Background()

func TestFixtureConfiguration(t *testing.T) {
	f := New()
	g := f.With(core.CapResolver, Wrong).Without(core.CapDIDParser)
	if f.Behavior[core.CapResolver] != Correct || !f.Supports("p", core.CapDIDParser) {
		t.Fatal("With/Without mutated the original")
	}
	if g.Behavior[core.CapResolver] != Wrong || g.Supports("p", core.CapDIDParser) || !g.Supports("p", core.CapResolver) {
		t.Fatal("With/Without did not apply")
	}
	if g.Describe().Name != "fixture" {
		t.Fatal("Describe lost the info")
	}
	b := Bare{Info: core.SubjectInfo{Name: "bare"}}
	if b.Supports("p", core.CapResolver) || b.Describe().Name != "bare" || !(Bare{DeclareAll: true}).Supports("p", core.CapResolver) {
		t.Fatal("Bare misbehaves")
	}
}

func TestParse(t *testing.T) {
	f := New()
	p, err := f.ParseDID(ExampleDID)
	if err != nil || p.Method != "example" || p.MethodSpecificID != "123" {
		t.Fatalf("ParseDID = %+v %v", p, err)
	}
	for _, bad := range []string{"x:example:1", "did:example", "did::1", "did:x:"} {
		if _, err := f.ParseDID(bad); err == nil {
			t.Errorf("ParseDID(%q) succeeded", bad)
		}
	}
	u, err := f.ParseDIDURL("did:example:123/a/b?x=1#frag")
	if err != nil || u.Path != "/a/b" || u.Query != "x=1" || !u.HasQuery || u.Fragment != "frag" || !u.HasFragment || u.DID.Method != "example" {
		t.Fatalf("ParseDIDURL = %+v %v", u, err)
	}
	if u, err := f.ParseDIDURL(ExampleDID); err != nil || u.HasQuery || u.HasFragment || u.Path != "" {
		t.Fatalf("ParseDIDURL plain = %+v %v", u, err)
	}
	if _, err := f.ParseDIDURL("nope/x"); err == nil {
		t.Fatal("ParseDIDURL accepted a non-DID")
	}
	w, _ := f.With(core.CapDIDParser, Wrong).ParseDID(ExampleDID)
	if w.Method != "123" {
		t.Fatalf("wrong ParseDID = %+v", w)
	}
	if _, err := f.With(core.CapDIDParser, Fails).ParseDIDURL(ExampleDID); !errors.Is(err, ErrFixture) {
		t.Fatalf("failing ParseDIDURL err = %v", err)
	}
}

func TestPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	_, _ = New().With(core.CapDIDParser, Panics).ParseDID(ExampleDID)
}

func TestProduceConsumeValidate(t *testing.T) {
	f := New()
	doc := core.NewDocument(core.M("id", core.String(ExampleDID)))
	data, mt, err := f.Produce(doc, "1.0")
	if err != nil || mt != "application/did+json" || string(data) != `{"id":"did:example:123"}` {
		t.Fatalf("Produce = %s %s %v", data, mt, err)
	}
	if _, mt, _ := f.Produce(doc, "1.1"); mt != "application/did" {
		t.Fatalf("1.1 media type = %s", mt)
	}
	if _, mt, _ := f.With(core.CapDocumentProducer, Wrong).Produce(doc, "1.1"); mt != "application/json" {
		t.Fatalf("wrong media type = %s", mt)
	}
	if _, _, err := f.With(core.CapDocumentProducer, Fails).Produce(doc, "1.1"); err == nil {
		t.Fatal("failing Produce succeeded")
	}
	if _, _, err := f.Produce(core.NewDocument(core.M("n", core.Number("x"))), "1.1"); err == nil {
		t.Fatal("Produce marshalled an invalid number")
	}
	got, info, err := f.Consume(data, "application/did", "1.1", true)
	if err != nil || got.Len() != 1 || info.MediaType != "application/did" || info.Version != "1.1" {
		t.Fatalf("Consume = %+v %+v %v", got, info, err)
	}
	if got, _, _ := f.With(core.CapDocumentConsumer, Wrong).Consume(data, "", "", false); got.Len() != 0 {
		t.Fatal("wrong Consume returned the document")
	}
	if _, _, err := f.Consume([]byte("[]"), "", "", false); err == nil {
		t.Fatal("Consume accepted an array")
	}
	if _, _, err := f.With(core.CapDocumentConsumer, Fails).Consume(data, "", "", false); err == nil {
		t.Fatal("failing Consume succeeded")
	}
	if fs, err := f.Validate(doc, "1.1"); err != nil || len(fs) != 0 {
		t.Fatalf("Validate(valid) = %v %v", fs, err)
	}
	if fs, _ := f.Validate(core.NewDocument(), "1.1"); len(fs) != 1 || fs[0].Code != "missing-id" {
		t.Fatalf("Validate(no id) = %v", fs)
	}
	if fs, _ := f.With(core.CapDocumentValidator, Wrong).Validate(core.NewDocument(), "1.1"); len(fs) != 0 {
		t.Fatal("wrong Validate reported findings")
	}
	if _, err := f.With(core.CapDocumentValidator, Fails).Validate(doc, "1.1"); err == nil {
		t.Fatal("failing Validate succeeded")
	}
}

func TestResolveAndDereference(t *testing.T) {
	f := New()
	r, err := f.Resolve(ctx, ExampleDID, nil)
	if err != nil || r.Document == nil || r.MediaType != "application/did" || len(r.Raw) == 0 {
		t.Fatalf("Resolve = %+v %v", r, err)
	}
	if id, _ := r.Document.Get("id"); id.Str != ExampleDID {
		t.Fatalf("id = %+v", id)
	}
	nf, _ := f.Resolve(ctx, "did:example:none", nil)
	if nf.Document != nil || nf.ResolutionMetadata.Len() != 1 {
		t.Fatalf("not found = %+v", nf)
	}
	w, _ := f.With(core.CapResolver, Wrong).Resolve(ctx, ExampleDID, nil)
	if id, _ := w.Document.Get("id"); id.Str == ExampleDID {
		t.Fatal("wrong Resolve returned the right id")
	}
	if _, err := f.With(core.CapResolver, Fails).Resolve(ctx, ExampleDID, nil); err == nil {
		t.Fatal("failing Resolve succeeded")
	}
	d, err := f.Dereference(ctx, ExampleDID+"#key-1", nil)
	if err != nil || len(d.Content) == 0 || d.MediaType != "application/did" {
		t.Fatalf("Dereference = %+v %v", d, err)
	}
	d, _ = f.Dereference(ctx, "did:example:none", nil)
	if d.Content != nil || d.DereferencingMetadata.Len() != 1 {
		t.Fatalf("Dereference not found = %+v", d)
	}
	if _, err := f.With(core.CapDereferencer, Fails).Dereference(ctx, ExampleDID, nil); err == nil {
		t.Fatal("failing Dereference succeeded")
	}
	r10, err := f.Resolve10(ctx, ExampleDID, nil)
	if err != nil || r10.Raw != nil || r10.Document == nil {
		t.Fatalf("Resolve10 = %+v %v", r10, err)
	}
	rr, err := f.ResolveRepresentation10(ctx, ExampleDID, nil)
	if err != nil || len(rr.Raw) == 0 {
		t.Fatalf("ResolveRepresentation10 = %+v %v", rr, err)
	}
	if d, err := f.Dereference10(ctx, ExampleDID, nil); err != nil || len(d.Content) == 0 {
		t.Fatalf("Dereference10 = %+v %v", d, err)
	}
	if _, err := f.With(core.CapV10Functions, Fails).Resolve10(ctx, ExampleDID, nil); err == nil {
		t.Fatal("failing Resolve10 succeeded")
	}
}

func TestLoadFixtureRegistry(t *testing.T) {
	f := New()
	reg := &fixtures.Registry{Format: fixtures.Format, Method: fixtures.Method}
	if err := f.LoadFixtureRegistry(reg); err != nil || f.Registry != reg {
		t.Fatalf("LoadFixtureRegistry = %v, registry %p", err, f.Registry)
	}
	if err := f.With(core.CapFixtureMethod, Fails).LoadFixtureRegistry(reg); !errors.Is(err, ErrFixture) {
		t.Fatalf("failing LoadFixtureRegistry err = %v", err)
	}
}

func TestExchange(t *testing.T) {
	ctx := context.Background()
	f := New()
	if f.Endpoint() != Endpoint {
		t.Fatalf("endpoint %q", f.Endpoint())
	}
	ex, err := f.Exchange(ctx, core.HTTPRequest{Method: "GET", Target: ExampleDID})
	if err != nil || ex.Status != 200 || !ex.TLS || ex.Header.Get("Content-Type") != "application/did" || ex.URL != Endpoint+ExampleDID {
		t.Fatalf("Exchange = %+v %v", ex, err)
	}
	if ex, _ := f.Exchange(ctx, core.HTTPRequest{Method: "GET", Target: "did:example:none"}); ex.Status != 404 {
		t.Fatalf("not found = %+v", ex)
	}
	if ex, _ := f.With(core.CapHTTPBinding, Wrong).Exchange(ctx, core.HTTPRequest{Target: ExampleDID}); ex.Status != 500 {
		t.Fatalf("wrong = %+v", ex)
	}
	if _, err := f.With(core.CapHTTPBinding, Fails).Exchange(ctx, core.HTTPRequest{}); !errors.Is(err, ErrFixture) {
		t.Fatalf("failing Exchange err = %v", err)
	}
}
