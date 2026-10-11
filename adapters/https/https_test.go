package https_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/adapters/https"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
	"github.com/sage-x-project/did-inspector/profiles/did11"
)

const prefix = "/1.0/identifiers/"

// canned answers a request by the target after the prefix, as written.
type canned map[string]func(w http.ResponseWriter, r *http.Request)

func (c canned) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimPrefix(r.URL.EscapedPath(), prefix)
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	h, ok := c[target]
	if !ok {
		http.Error(w, "no such target "+target, http.StatusTeapot)
		return
	}
	h(w, r)
}

func reply(status int, ct, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

const resultBody = `{"didDocument":{"id":"did:example:1"},"didResolutionMetadata":{"contentType":"application/did"},"didDocumentMetadata":{"created":"2020-01-01T00:00:00Z"}}`

func server(t *testing.T, c canned) (*httptest.Server, *https.Subject) {
	t.Helper()
	srv := httptest.NewTLSServer(c)
	t.Cleanup(srv.Close)
	s, err := https.New(srv.URL+prefix, https.WithClient(srv.Client()), https.WithInfo(core.SubjectInfo{Name: "remote"}))
	if err != nil {
		t.Fatal(err)
	}
	return srv, s
}

func TestNewAndSupports(t *testing.T) {
	for _, bad := range []string{"", "ftp://x/", "/relative/", "https://", "::"} {
		if _, err := https.New(bad); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
	s, err := https.New("http://resolver.example/1.0/identifiers/", https.WithClient(nil))
	if err != nil {
		t.Fatal(err)
	}
	if s.Endpoint() != "http://resolver.example/1.0/identifiers/" || s.Describe().Name == "" {
		t.Fatalf("subject = %+v", s.Describe())
	}
	if https.Profile != did11.Name {
		t.Fatalf("Profile %q is not the did-1.1 profile name %q", https.Profile, did11.Name)
	}
	for _, c := range []core.Capability{core.CapHTTPBinding, core.CapResolver, core.CapDereferencer} {
		if !s.Supports(https.Profile, c) || s.Supports("did-core-1.0", c) || !core.Implements(s, c) {
			t.Errorf("capability %s", c)
		}
	}
	if s.Supports(https.Profile, core.CapFixtureMethod) || s.Supports(https.Profile, core.CapDIDParser) {
		t.Error("declares a capability it lacks")
	}
	if err := s.LoadFixtureRegistry(&fixtures.Registry{}); err == nil {
		t.Error("LoadFixtureRegistry without a loader succeeded")
	}
	var loaded *fixtures.Registry
	s, _ = https.New("https://resolver.example/", https.WithFixtureLoader(func(r *fixtures.Registry) error { loaded = r; return nil }))
	reg := &fixtures.Registry{}
	if !s.Supports(https.Profile, core.CapFixtureMethod) || s.LoadFixtureRegistry(reg) != nil || loaded != reg {
		t.Error("fixture loader not used")
	}
}

func TestExchange(t *testing.T) {
	_, s := server(t, canned{
		"did:example:1": func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Accept", r.Header.Get("Accept"))
			w.Header().Set("X-Method", r.Method)
			w.Header().Set("X-Body", string(body))
			w.WriteHeader(http.StatusOK)
		},
		"did:example:redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/target", http.StatusSeeOther)
		},
		"did:example:big": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, https.MaxBody+1))
		},
	})
	ctx := context.Background()
	ex, err := s.Exchange(ctx, core.HTTPRequest{Method: "POST", Target: "did:example:1", Header: http.Header{"Accept": {"x/y"}}, Body: []byte(`{"a":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !ex.TLS || ex.Status != 200 || ex.Header.Get("X-Accept") != "x/y" || ex.Header.Get("X-Method") != "POST" || ex.Header.Get("X-Body") != `{"a":1}` ||
		!strings.HasSuffix(ex.URL, prefix+"did:example:1") || ex.RequestHeader.Get("Accept") != "x/y" || string(ex.RequestBody) != `{"a":1}` {
		t.Fatalf("exchange = %+v", ex)
	}
	ex, err = s.Exchange(ctx, core.HTTPRequest{Method: "GET", Target: "did:example:redirect"})
	if err != nil || ex.Status != http.StatusSeeOther || ex.Header.Get("Location") != "https://example.com/target" {
		t.Fatalf("redirect was followed or lost: %+v %v", ex, err)
	}
	if _, err := s.Exchange(ctx, core.HTTPRequest{Method: "GET", Target: "did:example:big"}); err == nil {
		t.Error("oversized body accepted")
	}
	if _, err := s.Exchange(ctx, core.HTTPRequest{Method: "BAD METHOD", Target: "x"}); err == nil {
		t.Error("invalid method accepted")
	}
	plain, _ := https.New("https://127.0.0.1:1/")
	if _, err := plain.Exchange(ctx, core.HTTPRequest{Method: "GET", Target: "x"}); err == nil {
		t.Error("unreachable endpoint gave a response")
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("broken") }
func (brokenBody) Close() error             { return nil }

type brokenTransport struct{}

func (brokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: brokenBody{}, Header: http.Header{}, Request: r}, nil
}

func TestExchangeBrokenBody(t *testing.T) {
	s, _ := https.New("https://resolver.example/", https.WithClient(&http.Client{Transport: brokenTransport{}}))
	if _, err := s.Exchange(context.Background(), core.HTTPRequest{Method: "GET", Target: "x"}); err == nil {
		t.Fatal("unreadable body accepted")
	}
}

func TestResolve(t *testing.T) {
	var seen []string
	record := func(h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.Header.Get("Accept"))
			h(w, r)
		}
	}
	_, s := server(t, canned{
		"did:example:1":                    record(reply(200, "application/did-resolution", resultBody)),
		"did%3Aexample%3A1?versionId=2":    reply(200, "application/did-resolution", `{"didDocument":null,"didResolutionMetadata":{},"didDocumentMetadata":{}}`),
		"did:example:missing":              reply(404, "application/problem+json", `{"type":"https://www.w3.org/ns/did#NOT_FOUND","title":"Not found"}`),
		"did:example:html":                 reply(500, "text/html", "<p>oops</p>"),
		"did:example:broken":               reply(200, "application/did-resolution", `[]`),
		"did:example:repr":                 record(reply(200, "application/did", `{"id":"did:example:repr"}`)),
		"did:example:text":                 reply(200, "text/plain", `not json`),
		"did%3Aexample%3Arepr?versionId=1": reply(200, "application/did", `{"id":"did:example:repr"}`),
	})
	ctx := context.Background()
	r, err := s.Resolve(ctx, "did:example:1", nil)
	if err != nil || r.Document == nil || r.MediaType != "application/did" || string(r.Raw) != `{"id":"did:example:1"}` {
		t.Fatalf("full result = %+v %v", r, err)
	}
	if v, _ := r.DocumentMetadata.Get("created"); v.Str == "" {
		t.Fatalf("document metadata lost: %+v", r.DocumentMetadata)
	}
	if r, err = s.Resolve(ctx, "did:example:1", map[string]any{"versionId": "2"}); err != nil || r.Document != nil || r.Raw != nil {
		t.Fatalf("null document = %+v %v", r, err)
	}
	r, err = s.Resolve(ctx, "did:example:missing", nil)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := r.ResolutionMetadata.Get("error"); e.Kind != core.KindObject {
		t.Fatalf("problem details not translated: %+v", r)
	}
	for _, in := range []string{"did:example:html", "did:example:broken"} {
		if _, err := s.Resolve(ctx, in, nil); err == nil {
			t.Errorf("%s translated", in)
		}
	}
	r, err = s.Resolve(ctx, "did:example:repr", map[string]any{"accept": "application/did"})
	if err != nil || r.Document == nil || r.MediaType != "application/did" || len(r.Raw) == 0 {
		t.Fatalf("representation = %+v %v", r, err)
	}
	if ct, _ := r.ResolutionMetadata.Get("contentType"); ct.Str != "application/did" {
		t.Fatalf("contentType = %+v", r.ResolutionMetadata)
	}
	if strings.Join(seen, ",") != "application/did-resolution,application/did" {
		t.Fatalf("Accept headers = %v", seen)
	}
	if r, err = s.Resolve(ctx, "did:example:text", map[string]any{"accept": 7}); err != nil || r.Document != nil || string(r.Raw) != "not json" {
		t.Fatalf("non-JSON representation = %+v %v", r, err)
	}
	if _, err := s.Resolve(ctx, "did:example:repr", map[string]any{"accept": "application/did", "versionId": "1"}); err != nil {
		t.Fatalf("representation with options: %v", err)
	}
	if _, err := s.Resolve(ctx, "did:example:1", map[string]any{"x": func() {}}); err == nil {
		t.Error("unencodable option accepted")
	}
	if _, err := s.Resolve(ctx, "did:example:none", nil); err == nil {
		t.Error("418 translated")
	}
}

const derefBody = `{"content":["https://a.example/x","https://b.example/y"],"dereferencingMetadata":{"contentType":"text/uri-list"},"contentMetadata":{}}`

func TestDereference(t *testing.T) {
	_, s := server(t, canned{
		"did:example:1?service=files": reply(200, "application/did-url-dereferencing", derefBody),
		"did:example:1?service=x":     reply(200, "application/did-url-dereferencing", `{"contentStream":"text","didUrlDereferencingMetadata":{},"contentMetadata":{"contentType":"text/plain"}}`),
		"did:example:1?service=obj":   reply(200, "application/did-url-dereferencing", `{"content":{"id":"x"},"dereferencingMetadata":{"contentType":"application/did"},"contentMetadata":{}}`),
		"did:example:1?service=mixed": reply(200, "application/did-url-dereferencing", `{"content":["a",1],"dereferencingMetadata":{"contentType":"text/uri-list"},"contentMetadata":{}}`),
		"did:example:1?service=empty": reply(200, "application/did-url-dereferencing", `{"content":[],"dereferencingMetadata":{"contentType":"text/uri-list"},"contentMetadata":{}}`),
		"did:example:1?service=none":  reply(200, "application/did-url-dereferencing", `{"content":null,"dereferencingMetadata":{},"contentMetadata":{}}`),
		"did:example:1?service=bad":   reply(200, "application/did-url-dereferencing", `{"content":null,"contentMetadata":{}}`),
		"did:example:1?service=redirect": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://a.example/x")
			w.WriteHeader(303)
		},
		"did:example:1?service=nolocation": reply(303, "", ""),
		"did%3Aexample%3A1%23key-1":        reply(200, "application/did", `{"id":"did:example:1#key-1"}`),
		"did:example:1/path":               reply(404, "application/json", `{"type":"https://www.w3.org/ns/did#NOT_FOUND"}`),
		"did:example:1/plain":              reply(404, "application/json", `"not found"`),
		"did%3Aexample%3A1%23k?x=1":        reply(200, "application/did", `{}`),
	})
	ctx := context.Background()
	d, err := s.Dereference(ctx, "did:example:1?service=files", nil)
	if err != nil || d.MediaType != "text/uri-list" || string(d.Content) != "https://a.example/x\r\nhttps://b.example/y\r\n" {
		t.Fatalf("uri list = %+v %v", d, err)
	}
	if d, err = s.Dereference(ctx, "did:example:1?service=x", nil); err != nil || string(d.Content) != "text" || d.MediaType != "text/plain" {
		t.Fatalf("string content = %+v %v", d, err)
	}
	if d, err = s.Dereference(ctx, "did:example:1?service=obj", nil); err != nil || string(d.Content) != `{"id":"x"}` {
		t.Fatalf("object content = %+v %v", d, err)
	}
	if d, err = s.Dereference(ctx, "did:example:1?service=mixed", nil); err != nil || string(d.Content) != `["a",1]` {
		t.Fatalf("mixed list = %+v %v", d, err)
	}
	if d, err = s.Dereference(ctx, "did:example:1?service=empty", nil); err != nil || d.Content != nil {
		t.Fatalf("empty list = %+v %v", d, err)
	}
	if d, err = s.Dereference(ctx, "did:example:1?service=none", nil); err != nil || d.Content != nil {
		t.Fatalf("no content = %+v %v", d, err)
	}
	if _, err = s.Dereference(ctx, "did:example:1?service=bad", nil); err == nil {
		t.Fatal("result without metadata translated")
	}
	d, err = s.Dereference(ctx, "did:example:1?service=redirect", map[string]any{"accept": "text/uri-list"})
	if err != nil || string(d.Content) != "https://a.example/x\r\n" || d.MediaType != "text/uri-list" {
		t.Fatalf("303 = %+v %v", d, err)
	}
	if _, err = s.Dereference(ctx, "did:example:1?service=nolocation", map[string]any{"accept": "text/uri-list"}); err == nil {
		t.Fatal("303 without Location translated")
	}
	if d, err = s.Dereference(ctx, "did:example:1#key-1", map[string]any{"accept": "application/did"}); err != nil || d.MediaType != "application/did" {
		t.Fatalf("fragment = %+v %v", d, err)
	}
	if d, err = s.Dereference(ctx, "did:example:1/path", nil); err != nil {
		t.Fatal(err)
	} else if e, _ := d.DereferencingMetadata.Get("error"); e.Kind != core.KindObject {
		t.Fatalf("problem = %+v", d)
	}
	if _, err = s.Dereference(ctx, "did:example:1/plain", nil); err == nil {
		t.Fatal("non-object error body translated")
	}
	if _, err = s.Dereference(ctx, "did:example:1#k", map[string]any{"x": func() {}}); err == nil {
		t.Fatal("unencodable option accepted")
	}
	if _, err = s.Dereference(ctx, "did:example:1#k", map[string]any{"x": 1, "accept": "application/did"}); err != nil {
		t.Fatal(err)
	}
}
