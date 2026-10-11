package didgo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/producer"
	"github.com/sage-x-project/did-go/vm"
)

func TestResolutionOptions(t *testing.T) {
	o := resolutionOptions(map[string]any{
		"accept": "application/did", "expandRelativeUrls": true, "versionId": "1",
		"versionTime": "2021-05-10T17:00:00Z", "noCache": true, "ext": 1.0,
	})
	if o.Accept != "application/did" || !o.ExpandRelativeURLs || o.VersionID != "1" || !o.NoCache ||
		o.VersionTime == nil || !o.VersionTime.Equal(time.Date(2021, 5, 10, 17, 0, 0, 0, time.UTC)) || o.Extra["ext"] != 1.0 {
		t.Errorf("translated options %+v", o)
	}
	bad := resolutionOptions(map[string]any{
		"accept": 1, "expandRelativeUrls": "yes", "versionId": false, "noCache": "no",
		"versionTime": "2021-05-10 17:00:00",
	})
	if len(bad.Extra) != 5 {
		t.Errorf("wrongly typed options not kept in Extra: %+v", bad.Extra)
	}
	if o := resolutionOptions(map[string]any{"versionTime": 3}); o.Extra["versionTime"] != 3 {
		t.Errorf("non-string versionTime: %+v", o)
	}
	offset := resolutionOptions(map[string]any{"versionTime": "2021-05-10T19:00:00+02:00"})
	if _, off := offset.VersionTime.Zone(); off != 7200 {
		t.Error("the offset of versionTime was not kept for did-go to check")
	}
	d := dereferenceOptions(map[string]any{"accept": "text/uri-list", "verificationRelationship": "authentication", "x": "y", "accept2": 1})
	if d.Accept != "text/uri-list" || d.VerificationRelationship != "authentication" || len(d.Extra) != 2 {
		t.Errorf("dereference options %+v", d)
	}
}

func TestResolve(t *testing.T) {
	s := loaded(t)
	ctx := context.Background()
	res, err := s.Resolve(ctx, "did:example:a", map[string]any{})
	if err != nil || res.Document == nil || res.MediaType != "application/did" || len(res.Raw) == 0 {
		t.Fatalf("found: %+v %v", res, err)
	}
	if str(res.ResolutionMetadata, "contentType") != "application/did" || str(res.DocumentMetadata, "versionId") != "2" {
		t.Errorf("metadata %s %s", compact(t, res.ResolutionMetadata), compact(t, res.DocumentMetadata))
	}
	if _, ok := res.Document.Get("@context"); !ok {
		t.Error("the resolved document lost its representation-specific entries")
	}
	res, _ = s.Resolve(ctx, "did:example:a", map[string]any{"expandRelativeUrls": true})
	vms, _ := res.Document.Get("verificationMethod")
	if id, _ := vms.Array[0].Get("id"); id.Str != "did:example:a#key-1" {
		t.Errorf("expandRelativeUrls: %s", compact(t, *res.Document))
	}
	res, _ = s.Resolve(ctx, "did:example:gone", nil)
	if res.Document != nil || compact(t, res.DocumentMetadata) != `{"created":"2021-01-01T00:00:00Z","deactivated":true}` {
		t.Errorf("deactivated: %s", compact(t, res.DocumentMetadata))
	}
	for in, want := range map[string]string{
		"did:example:nothing": "NOT_FOUND",
		"did:Example:1":       "INVALID_DID",
		"did:example:broken":  "INTERNAL_ERROR",
		"did:other:1":         "METHOD_NOT_SUPPORTED",
	} {
		res, err := s.Resolve(ctx, in, nil)
		if err != nil || !strings.HasSuffix(errorType(res.ResolutionMetadata), "#"+want) || res.Document != nil {
			t.Errorf("%s: %s %v, want %s", in, compact(t, res.ResolutionMetadata), err, want)
		}
	}
	res, _ = s.Resolve(ctx, "did:example:a", map[string]any{"expandRelativeUrls": "yes"})
	if !strings.HasSuffix(errorType(res.ResolutionMetadata), "#INVALID_OPTIONS") {
		t.Errorf("wrongly typed option: %s", compact(t, res.ResolutionMetadata))
	}
}

func TestDereference(t *testing.T) {
	s := loaded(t)
	ctx := context.Background()
	res, err := s.Dereference(ctx, "did:example:a", nil)
	if err != nil || res.MediaType != "application/did" || !strings.Contains(string(res.Content), `"did:example:a"`) {
		t.Fatalf("document: %+v %v", res, err)
	}
	res, err = s.Dereference(ctx, "did:example:a#key-1", nil)
	if err != nil || !strings.Contains(string(res.Content), `"type":"Multikey"`) {
		t.Errorf("fragment: %s %v", res.Content, err)
	}
	res, err = s.Dereference(ctx, "did:example:a#files", nil)
	if err != nil || !strings.Contains(string(res.Content), `"FileService"`) {
		t.Errorf("service fragment: %s %v", res.Content, err)
	}
	res, err = s.Dereference(ctx, "did:example:a?service=files&relativeRef=x.pdf", map[string]any{"accept": "text/uri-list"})
	if err != nil || string(res.Content) != "https://example.com/files/x.pdf\r\n" || res.MediaType != "text/uri-list" {
		t.Errorf("uri list: %q %q %v", res.Content, res.MediaType, err)
	}
	res, _ = s.Dereference(ctx, "did:example:a/pa th", nil)
	if !strings.HasSuffix(errorType(res.DereferencingMetadata), "#INVALID_DID_URL") || len(res.Content) != 0 {
		t.Errorf("invalid DID URL: %s", compact(t, res.DereferencingMetadata))
	}
	res, _ = s.Dereference(ctx, "did:example:gone", nil)
	if v, _ := res.ContentMetadata.Get("deactivated"); !v.Bool {
		t.Errorf("deactivated: %s", compact(t, res.ContentMetadata))
	}
}

func TestV10Functions(t *testing.T) {
	s := loaded(t)
	ctx := context.Background()
	res, err := s.Resolve10(ctx, "did:example:v10", map[string]any{"accept": "application/did+json"})
	if err != nil || res.Document == nil || res.Raw != nil {
		t.Fatalf("resolve: %+v %v", res, err)
	}
	if _, ok := res.ResolutionMetadata.Get("contentType"); ok {
		t.Error("resolve reported contentType")
	}
	res, err = s.ResolveRepresentation10(ctx, "did:example:v10", nil)
	if err != nil || res.Document != nil || res.MediaType != "application/did+json" || len(res.Raw) == 0 {
		t.Errorf("resolveRepresentation: %+v %v", res, err)
	}
	for _, f := range []func(context.Context, string, map[string]any) (core.ResolutionResult, error){s.Resolve10, s.ResolveRepresentation10} {
		res, err := f(ctx, "did:example:v10#x", nil)
		if err != nil || errorType(res.ResolutionMetadata) != "invalidDid" || res.DocumentMetadata.Len() != 0 {
			t.Errorf("invalid DID: %s %v", compact(t, res.ResolutionMetadata), err)
		}
		res, _ = f(ctx, "did:example:nothing", nil)
		if errorType(res.ResolutionMetadata) != "notFound" {
			t.Errorf("not found: %s", compact(t, res.ResolutionMetadata))
		}
	}
	dr, err := s.Dereference10(ctx, "did:example:v10#key-1", nil)
	if err != nil || !strings.Contains(string(dr.Content), "publicKeyJwk") || dr.MediaType == "" {
		t.Errorf("dereference fragment: %s %q %v", dr.Content, dr.MediaType, err)
	}
	dr, err = s.Dereference10(ctx, "did:example:v10/pa th", nil)
	if err != nil || errorType(dr.DereferencingMetadata) != "invalidDidUrl" || dr.Content != nil {
		t.Errorf("invalid DID URL: %s %v", compact(t, dr.DereferencingMetadata), err)
	}
}

func TestContentBytes(t *testing.T) {
	p := producer.New()
	for _, c := range []struct {
		content any
		want    string
	}{
		{nil, ""},
		{[]byte("b"), "b"},
		{"s", "s"},
		{[]string{}, ""},
		{[]string{"https://a/", "https://b/"}, "https://a/\r\nhttps://b/\r\n"},
		{vm.Service{Type: []string{"T"}, ServiceEndpoint: []vm.Endpoint{{URL: "https://a/"}}}, `{"type":"T","serviceEndpoint":"https://a/"}`},
		{document.Map{}, `{}`},
	} {
		got, err := contentBytes(p, c.content, "")
		if err != nil || string(got) != c.want {
			t.Errorf("contentBytes(%v) = %q, %v", c.content, got, err)
		}
	}
	if _, err := contentBytes(p, 42, ""); err == nil {
		t.Error("an int written")
	}
	s := loaded(t)
	res := s.current().resolver.ResolveString(context.Background(), "did:example:a", resolutionOptions(nil))
	if _, err := contentBytes(p, res.Document, "image/png"); err == nil {
		t.Error("a document written as image/png")
	}
	bad := []any{
		vm.Method{Extra: map[string]any{"x": struct{}{}}},
		vm.Service{Extra: map[string]any{"x": struct{}{}}},
	}
	for _, b := range bad {
		if _, err := contentBytes(p, b, ""); err == nil {
			t.Errorf("%T with an untranslatable value written", b)
		}
	}
	if _, err := dereferenceResult(p, core.DocumentJSON{}, "", 42, document.Metadata{}); err == nil {
		t.Error("a result with untranslatable content translated")
	}
	r, err := dereferenceResult(p, core.DocumentJSON{}, "", nil, document.Metadata{Extra: map[string]any{"contentType": "text/plain"}})
	if err != nil || r.MediaType != "text/plain" {
		t.Errorf("contentType from the content metadata: %q %v", r.MediaType, err)
	}
	if _, err := dereferenceResult(p, core.DocumentJSON{}, "", nil, document.Metadata{Extra: map[string]any{"x": struct{}{}}}); err == nil {
		t.Error("untranslatable content metadata translated")
	}
}
