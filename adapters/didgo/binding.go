package didgo

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"

	"github.com/sage-x-project/did-inspector/adapters/https"
	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/universal"
)

// binding is did-go's HTTP(S) binding as an inspection target: did-go's
// resolution/universal Handler over the subject's resolver and
// dereferencer, served by an httptest TLS server inside the adapter and
// reached through the inspector's adapters/https subject. The server starts
// on the first exchange and stops on Close.
type binding struct {
	once   sync.Once
	server *httptest.Server
	remote *https.Subject
	err    error
}

// currentResolver resolves with the subject's resolver of the moment, so
// that the handler follows LoadFixtureRegistry.
type currentResolver struct{ s *Subject }

func (c currentResolver) Resolve(ctx context.Context, d did.DID, opts resolution.ResolutionOptions) resolution.Result {
	return c.s.current().resolver.Resolve(ctx, d, opts)
}

// currentDereferencer dereferences with the subject's dereferencer of the
// moment.
type currentDereferencer struct{ s *Subject }

func (c currentDereferencer) Dereference(ctx context.Context, u did.DIDURL, opts resolution.DereferenceOptions) resolution.DereferenceResult {
	return c.s.current().dereferencer.Dereference(ctx, u, opts)
}

// remote starts the binding server once and returns the adapters/https
// subject that reaches it. The handler is did-go's universal.NewHandler
// with did-go's producer, served under universal.DefaultPathPrefix, with
// its default options: TLS required and the POST version on.
func (s *Subject) remote() (*https.Subject, error) {
	b := s.binding
	b.once.Do(func() {
		h := universal.NewHandler(currentResolver{s}, currentDereferencer{s}, universal.WithProducer(s.producer))
		b.server = httptest.NewTLSServer(h)
		b.remote, b.err = https.New(b.server.URL+universal.DefaultPathPrefix, https.WithClient(b.server.Client()), https.WithInfo(s.info))
	})
	if b.err != nil {
		return nil, fmt.Errorf("didgo adapter: binding: %w", b.err)
	}
	return b.remote, nil
}

// Endpoint returns the DID resolver HTTP(S) endpoint of did-go's binding
// server, starting the server if needed; it is empty when the server
// cannot start.
func (s *Subject) Endpoint() string {
	r, err := s.remote()
	if err != nil {
		return ""
	}
	return r.Endpoint()
}

// Exchange sends one request to did-go's binding server and returns the
// raw exchange.
func (s *Subject) Exchange(ctx context.Context, req core.HTTPRequest) (core.HTTPExchange, error) {
	r, err := s.remote()
	if err != nil {
		return core.HTTPExchange{}, err
	}
	return r.Exchange(ctx, req)
}

// Close stops the binding server, if it was started.
func (s *Subject) Close() error {
	if s.binding != nil && s.binding.server != nil {
		s.binding.server.Close()
	}
	return nil
}
