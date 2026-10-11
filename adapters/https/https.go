// Package https is the did-inspector adapter for any DID resolver that
// exposes the HTTP(S) binding of DID Resolution v1.0 (§12.1). It reaches the
// resolver over the network only, so implementations in any language can be
// inspected.
//
// The subject has three capabilities under the did-1.1 profile:
//
//   - core.HTTPBinding: the raw exchange. The inspector builds each request
//     itself and judges the status code, headers and body of the response,
//     without trusting any parsing of it;
//   - core.Resolver and core.Dereferencer: DID resolution and DID URL
//     dereferencing through the binding, so that the profile's resolution
//     and dereferencing cases can run against a remote resolver. Requests
//     are built by checks.BindingRequest with the GET version, which every
//     conforming resolver implements; responses are translated as
//     ResolveResponse and DereferenceResponse describe.
//
// With WithFixtureLoader the subject also has core.FixtureMethod: the loader
// wires the inspector's fixture registry into the resolver behind the
// endpoint, which only an operator of that resolver can do.
package https

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// Profile is the profile whose capabilities the subject declares: the
// HTTP(S) binding is part of DID Resolution v1.0, which belongs to the
// did-1.1 profile.
const Profile = "did-1.1"

// MaxBody is the largest response body the subject reads.
const MaxBody = 16 << 20

// Subject is a remote DID resolver reached through the HTTP(S) binding.
// The zero value is not usable; call New.
type Subject struct {
	endpoint string
	client   *http.Client
	info     core.SubjectInfo
	loader   func(*fixtures.Registry) error
}

// Option configures a Subject.
type Option func(*Subject)

// WithClient sets the HTTP client, for example one that trusts the
// resolver's certificate. The subject uses a copy that never follows
// redirects, so that a 303 response reaches the inspector as it was sent.
func WithClient(c *http.Client) Option {
	return func(s *Subject) {
		if c != nil {
			s.client = c
		}
	}
}

// WithInfo sets the subject information the subject reports.
func WithInfo(info core.SubjectInfo) Option {
	return func(s *Subject) { s.info = info }
}

// WithFixtureLoader gives the subject the fixture-method capability:
// LoadFixtureRegistry calls load, which must wire the registry into the
// resolver behind the endpoint as the driver of the method "example".
func WithFixtureLoader(load func(*fixtures.Registry) error) Option {
	return func(s *Subject) { s.loader = load }
}

// New returns a subject for the DID resolver HTTP(S) endpoint, an absolute
// http or https URL to which the inspector appends DIDs and DID URLs (for
// example https://resolver.example/1.0/identifiers/). An http endpoint is
// accepted so that a resolver that does not use TLS can be inspected and
// judged for it.
func New(endpoint string, opts ...Option) (*Subject, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("https adapter: endpoint %q is not an absolute http(s) URL", endpoint)
	}
	s := &Subject{
		endpoint: endpoint,
		client:   http.DefaultClient,
		info:     core.SubjectInfo{Name: "https:" + endpoint},
	}
	for _, o := range opts {
		o(s)
	}
	c := *s.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.client = &c
	return s, nil
}

// Interface checks.
var (
	_ core.Subject       = (*Subject)(nil)
	_ core.HTTPBinding   = (*Subject)(nil)
	_ core.Resolver      = (*Subject)(nil)
	_ core.Dereferencer  = (*Subject)(nil)
	_ core.FixtureMethod = (*Subject)(nil)
)

// Describe returns the subject information given with WithInfo.
func (s *Subject) Describe() core.SubjectInfo { return s.info }

var capabilities = []core.Capability{core.CapHTTPBinding, core.CapResolver, core.CapDereferencer}

// Supports reports the binding, resolver and dereferencer capabilities
// under Profile, and the fixture method when a loader was given.
func (s *Subject) Supports(profile string, c core.Capability) bool {
	if profile != Profile {
		return false
	}
	if c == core.CapFixtureMethod {
		return s.loader != nil
	}
	return slices.Contains(capabilities, c)
}

// LoadFixtureRegistry calls the loader given with WithFixtureLoader.
func (s *Subject) LoadFixtureRegistry(r *fixtures.Registry) error {
	if s.loader == nil {
		return errors.New("https adapter: no fixture loader for the remote resolver")
	}
	return s.loader(r)
}

// Endpoint returns the DID resolver HTTP(S) endpoint.
func (s *Subject) Endpoint() string { return s.endpoint }

// Exchange sends req to the endpoint followed by req.Target and returns the
// raw exchange. Redirects are not followed.
func (s *Subject) Exchange(ctx context.Context, req core.HTTPRequest) (core.HTTPExchange, error) {
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, s.endpoint+req.Target, body)
	if err != nil {
		return core.HTTPExchange{}, fmt.Errorf("https adapter: request: %w", err)
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	ex := core.HTTPExchange{Method: req.Method, URL: hr.URL.String(), RequestHeader: hr.Header.Clone(), RequestBody: req.Body}
	resp, err := s.client.Do(hr)
	if err != nil {
		return core.HTTPExchange{}, fmt.Errorf("https adapter: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return core.HTTPExchange{}, fmt.Errorf("https adapter: response body: %w", err)
	}
	if len(data) > MaxBody {
		return core.HTTPExchange{}, fmt.Errorf("https adapter: response body larger than %d bytes", MaxBody)
	}
	ex.TLS, ex.Status, ex.Header, ex.Body = resp.TLS != nil, resp.StatusCode, resp.Header.Clone(), data
	return ex, nil
}
