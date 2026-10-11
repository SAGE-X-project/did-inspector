package checks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

// Media types of the HTTP(S) binding (DID Resolution §9, §10, §12.1) and of
// RFC 9457 problem details.
const (
	MediaTypeDIDResolution       = "application/did-resolution"
	MediaTypeDIDURLDereferencing = "application/did-url-dereferencing"
	MediaTypeProblem             = "application/problem+json"
)

// BindingStatus is the table of DID Resolution §12.1: the HTTP status code
// that corresponds to each error type.
var BindingStatus = map[string]int{
	"https://www.w3.org/ns/did#INVALID_DID":                  http.StatusBadRequest,
	"https://www.w3.org/ns/did#INVALID_DID_URL":              http.StatusBadRequest,
	"https://www.w3.org/ns/did#INVALID_OPTIONS":              http.StatusBadRequest,
	"https://www.w3.org/ns/did#NOT_FOUND":                    http.StatusNotFound,
	"https://www.w3.org/ns/did#REPRESENTATION_NOT_SUPPORTED": http.StatusNotAcceptable,
	"https://www.w3.org/ns/did#INVALID_DID_DOCUMENT":         http.StatusInternalServerError,
	"https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED":         http.StatusNotImplemented,
	"https://www.w3.org/ns/did#FEATURE_NOT_SUPPORTED":        http.StatusNotImplemented,
	"https://www.w3.org/ns/did#INTERNAL_ERROR":               http.StatusInternalServerError,
}

// BindingRequest builds the request of DID Resolution §12.1 for an input
// DID (resolution) or DID URL (dereferencing):
//
//   - the Accept header is accept: application/did-resolution or
//     application/did-url-dereferencing for the complete result, or the
//     value of the accept option for the didDocument or contentStream
//     alone;
//   - GET: when options other than accept are given, the target is the
//     input percent-encoded (RFC 3986 §2.1) followed by "?" and the
//     options as query parameters (Example 26, 27); otherwise it is the
//     input as written (Example 24, 25);
//   - POST: the target is the input as written and the options other than
//     accept are a JSON object in the body (Example 28, 29).
//
// A fragment cannot travel in a request target (RFC 9110 §7.1), so an
// input with "#" is always percent-encoded; the binding does not say how a
// DID URL with a fragment is sent. Query parameters are sorted by name;
// a string option is written as it is and any other value as its JSON text.
// An accept member of opts is ignored: the accept option travels in the
// Accept header.
func BindingRequest(method, input, accept string, opts map[string]any) (core.HTTPRequest, error) {
	other := map[string]any{}
	for k, v := range opts {
		if k != "accept" {
			other[k] = v
		}
	}
	req := core.HTTPRequest{Method: method, Target: input, Header: http.Header{}}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	encode := strings.Contains(input, "#")
	switch method {
	case http.MethodGet:
		if len(other) == 0 {
			break
		}
		q := url.Values{}
		for k, v := range other {
			s, err := queryValue(v)
			if err != nil {
				return core.HTTPRequest{}, fmt.Errorf("checks: option %q: %w", k, err)
			}
			q.Set(k, s)
		}
		req.Target = PercentEncode(input) + "?" + q.Encode()
		return req, nil
	case http.MethodPost:
		if len(other) > 0 {
			body, err := json.Marshal(other)
			if err != nil {
				return core.HTTPRequest{}, fmt.Errorf("checks: options: %w", err)
			}
			req.Body = body
			req.Header.Set("Content-Type", "application/json")
		}
	default:
		return core.HTTPRequest{}, fmt.Errorf("checks: the binding has no %q request", method)
	}
	if encode {
		req.Target = PercentEncode(input)
	}
	return req, nil
}

func queryValue(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	data, err := json.Marshal(v)
	return string(data), err
}
