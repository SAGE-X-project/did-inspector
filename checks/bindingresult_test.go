package checks

import (
	"net/http"
	"testing"

	"github.com/sage-x-project/did-inspector/core"
)

func TestParseResolutionResult(t *testing.T) {
	r, err := ParseResolutionResult([]byte(`{"didDocument":{"id":"did:example:1"},"didResolutionMetadata":{"contentType":"application/did"},"didDocumentMetadata":{}}`))
	if err != nil || !r.HasContent || r.Metadata.Len() != 1 || r.ContentMetadata.Len() != 0 {
		t.Fatalf("result = %+v %v", r, err)
	}
	r, err = ParseResolutionResult([]byte(`{"didDocument":null,"didResolutionMetadata":{},"didDocumentMetadata":{}}`))
	if err != nil || r.HasContent {
		t.Fatalf("null document = %+v %v", r, err)
	}
	for _, bad := range []string{
		`[]`,
		`{"didDocument":"x","didResolutionMetadata":{},"didDocumentMetadata":{}}`,
		`{"didDocument":{},"didDocumentMetadata":{}}`,
		`{"didDocument":{},"didResolutionMetadata":[],"didDocumentMetadata":{}}`,
		`{"didDocument":{},"didResolutionMetadata":{}}`,
	} {
		if _, err := ParseResolutionResult([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParseDereferencingResult(t *testing.T) {
	for _, body := range []string{
		`{"content":"text","dereferencingMetadata":{},"contentMetadata":{}}`,
		`{"contentStream":["a"],"didUrlDereferencingMetadata":{},"contentMetadata":{}}`,
	} {
		r, err := ParseDereferencingResult([]byte(body))
		if err != nil || !r.HasContent {
			t.Errorf("%s: %+v %v", body, r, err)
		}
	}
	if _, err := ParseDereferencingResult([]byte(`"x"`)); err == nil {
		t.Error("string accepted")
	}
	if _, err := ParseDereferencingResult([]byte(`{"content":1,"dereferencingMetadata":{}}`)); err == nil {
		t.Error("missing contentMetadata accepted")
	}
}

func ex(status int, ct, body string) core.HTTPExchange {
	h := http.Header{}
	h.Set("Content-Type", ct)
	return core.HTTPExchange{Status: status, Header: h, Body: []byte(body)}
}

func TestBindingError(t *testing.T) {
	nf := "https://www.w3.org/ns/did#NOT_FOUND"
	for _, c := range []struct {
		ex   core.HTTPExchange
		want string
		ok   bool
	}{
		{ex(404, MediaTypeDIDResolution, `{"didResolutionMetadata":{"error":{"type":"`+nf+`"}},"didDocumentMetadata":{}}`), nf, true},
		{ex(404, MediaTypeDIDURLDereferencing, `{"dereferencingMetadata":{"error":{"type":"`+nf+`"}},"contentMetadata":{}}`), nf, true},
		{ex(404, MediaTypeProblem, `{"type":"`+nf+`"}`), nf, true},
		{ex(404, "application/json", `{"type":"`+nf+`"}`), nf, true},
		{ex(200, MediaTypeProblem, `{"type":"`+nf+`"}`), "", false},
		{ex(404, "text/plain", `not found`), "", false},
		{ex(200, MediaTypeDIDResolution, `{"didResolutionMetadata":{},"didDocumentMetadata":{}}`), "", false},
		{ex(404, MediaTypeDIDResolution, `{"didResolutionMetadata":{"error":"notFound"},"didDocumentMetadata":{}}`), "", false},
		{ex(404, MediaTypeDIDResolution, `[]`), "", false},
		{ex(404, MediaTypeDIDURLDereferencing, `[]`), "", false},
	} {
		_, got, err := BindingError(c.ex)
		if got != c.want || (err == nil) != c.ok {
			t.Errorf("%d %s: %q %v", c.ex.Status, c.ex.Body, got, err)
		}
	}
}
