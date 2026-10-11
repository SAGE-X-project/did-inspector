package didgo

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

func bindingGet(t *testing.T, s *Subject, input, accept string, opts map[string]any) core.HTTPExchange {
	t.Helper()
	req, err := checks.BindingRequest(http.MethodGet, input, accept, opts)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := s.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

func TestBinding(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	if err := s.LoadFixtureRegistry(registry(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Endpoint(), "https://") || !strings.HasSuffix(s.Endpoint(), "/1.0/identifiers/") {
		t.Fatalf("endpoint %q", s.Endpoint())
	}
	ex := bindingGet(t, s, "did:example:a", checks.MediaTypeDIDResolution, nil)
	if !ex.TLS || ex.Status != http.StatusOK || checks.MediaTypeEssence(ex.Header.Get("Content-Type")) != checks.MediaTypeDIDResolution {
		t.Fatalf("complete result: %d %v %s", ex.Status, ex.Header, ex.Body)
	}
	r, err := checks.ParseResolutionResult(ex.Body)
	if err != nil || !r.HasContent {
		t.Fatalf("result %+v %v", r, err)
	}
	ex = bindingGet(t, s, "did:example:a", checks.MediaTypeDIDResolution, map[string]any{"versionId": "1"})
	if r, _ := checks.ParseResolutionResult(ex.Body); ex.Status != http.StatusOK || !strings.Contains(string(ex.Body), `"versionId":"1"`) {
		t.Fatalf("versionId 1: %d %+v %s", ex.Status, r, ex.Body)
	}
	if ex = bindingGet(t, s, "did:example:missing", "application/did", nil); ex.Status != http.StatusNotFound {
		t.Fatalf("not found: %d %s", ex.Status, ex.Body)
	}
	if ex = bindingGet(t, s, "did:example:a?service=files", "text/uri-list", nil); ex.Status != http.StatusSeeOther || ex.Header.Get("Location") != "https://example.com/files/" {
		t.Fatalf("service: %d %v %s", ex.Status, ex.Header, ex.Body)
	}
	// The handler follows a registry loaded after the server started.
	if err := s.LoadFixtureRegistry(registry(t)); err != nil {
		t.Fatal(err)
	}
	if ex = bindingGet(t, s, "did:example:gone", checks.MediaTypeDIDResolution, nil); ex.Status != http.StatusGone {
		t.Fatalf("deactivated: %d %s", ex.Status, ex.Body)
	}
}

func TestBindingErrors(t *testing.T) {
	if err := (&Subject{}).Close(); err != nil {
		t.Fatal(err)
	}
	s := New()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s.binding.once.Do(func() {})
	s.binding.err = errors.New("no server")
	if s.Endpoint() != "" {
		t.Error("endpoint without a server")
	}
	if _, err := s.Exchange(context.Background(), core.HTTPRequest{Method: "GET"}); err == nil {
		t.Error("exchange without a server")
	}
}
