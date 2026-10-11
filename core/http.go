package core

import (
	"context"
	"net/http"
)

// HTTPRequest is one request the inspector sends to a DID resolver HTTP(S)
// endpoint (DID Resolution v1.0 §12.1). The inspector builds it from the
// specification text: Target is what it appends to the endpoint, already
// percent-encoded where the binding says so, and Header carries the Accept
// header.
type HTTPRequest struct {
	// Method is GET or POST.
	Method string
	// Target is appended to the DID resolver HTTP(S) endpoint as written: a
	// DID or DID URL, optionally followed by "?" and query parameters.
	Target string
	// Header holds the request headers, for example Accept.
	Header http.Header
	// Body is the request body (the options of a POST request).
	Body []byte
}

// HTTPExchange is one request and the response to it, as raw as HTTP
// allows, so that a case can judge the binding rules (status code, headers,
// body) without trusting anyone's parsing of the response.
type HTTPExchange struct {
	// Method and URL are those of the request sent; URL is the complete
	// request URL.
	Method string `json:"method"`
	URL    string `json:"url"`
	// RequestHeader and RequestBody are the headers and body sent.
	RequestHeader http.Header `json:"request_header,omitempty"`
	RequestBody   []byte      `json:"request_body,omitempty"`
	// TLS reports whether the response arrived over a TLS connection.
	TLS bool `json:"tls"`
	// Status is the HTTP response status code.
	Status int `json:"status"`
	// Header holds the response headers.
	Header http.Header `json:"header,omitempty"`
	// Body is the response body.
	Body []byte `json:"body,omitempty"`
}

// HTTPBinding exposes the raw HTTP exchanges of a subject that implements
// the HTTP(S) binding of DID Resolution v1.0 §12.1.
type HTTPBinding interface {
	// Endpoint returns the DID resolver HTTP(S) endpoint, the URL that
	// requests are built on.
	Endpoint() string
	// Exchange sends req to the endpoint without following redirects and
	// returns the exchange. It returns an error only when no response
	// arrived.
	Exchange(ctx context.Context, req HTTPRequest) (HTTPExchange, error)
}
