// Package didgo is the did-inspector adapter for did-go
// (github.com/sage-x-project/did-go). It implements core.Subject and every
// capability interface of the inspector core by translating the
// inspector's neutral types to and from did-go's public types, and it wires
// the inspector's fixture registry into did-go as the driver of the DID
// method "example".
//
// The adapter only translates. It never calls did-go to judge a result:
// the inspector's cases judge what did-go returns against the specification
// text. Where did-go offers no public entry point for a translation step,
// the adapter uses the did-go player that owns that step (for example the
// consumer to read a document's JSON into did-go's data model, or the
// producer to write a dereferenced document in the representation the
// dereferencer named) and says so on the method.
//
// The adapter lives in its own Go module so that the inspector core builds
// without did-go.
package didgo

import (
	"sync"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/core10"
	"github.com/sage-x-project/did-inspector/profiles/did11"

	"github.com/sage-x-project/did-go/consumer"
	"github.com/sage-x-project/did-go/producer"
)

// Name is the subject name the adapter reports.
const Name = "did-go"

// ModulePath is the module path of did-go.
const ModulePath = "github.com/sage-x-project/did-go"

// Subject is did-go as an inspection subject. The zero value is not usable;
// call New.
type Subject struct {
	info core.SubjectInfo

	consumer *consumer.Consumer
	producer *producer.Producer

	// mu guards players, which LoadFixtureRegistry replaces.
	mu      sync.RWMutex
	players *players

	binding *binding
}

// New returns the subject. Before LoadFixtureRegistry is called, the
// resolver knows no DID method.
func New() *Subject {
	s := &Subject{
		info:     describe(readBuildInfo),
		consumer: consumer.New(),
		producer: producer.New(),
		binding:  &binding{},
	}
	p, err := newPlayers(nil, s.consumer, s.producer)
	if err != nil {
		// newPlayers fails only for nil arguments, which New never passes.
		panic(err)
	}
	s.players = p
	return s
}

// Interface checks: the subject implements every capability of the core.
var (
	_ core.Subject           = (*Subject)(nil)
	_ core.DIDParser         = (*Subject)(nil)
	_ core.DocumentProducer  = (*Subject)(nil)
	_ core.DocumentConsumer  = (*Subject)(nil)
	_ core.DocumentValidator = (*Subject)(nil)
	_ core.Resolver          = (*Subject)(nil)
	_ core.Dereferencer      = (*Subject)(nil)
	_ core.V10Functions      = (*Subject)(nil)
	_ core.FixtureMethod     = (*Subject)(nil)
	_ core.HTTPBinding       = (*Subject)(nil)
)

// Describe returns did-go's module version and revision from the build
// information of the running binary.
func (s *Subject) Describe() core.SubjectInfo {
	return s.info
}

// support declares, per profile, what did-go implements:
//
//   - did-core-1.0: DID and DID URL parsing, production and consumption of
//     the DID Core 1.0 representations (spec.V10), validation against DID
//     Core 1.0, and the abstract functions of DID Core 1.0 §7 through
//     resolution/compat. The DID Resolution v1.0 resolver and dereferencer
//     are not DID Core 1.0 functions, so the profile does not get them.
//   - did-1.1: parsing, production, consumption and validation for DID 1.1
//     (spec.V11), the resolver and dereferencer of DID Resolution v1.0, and
//     the HTTP(S) binding of DID Resolution v1.0 §12.1 (resolution/universal,
//     see binding.go). resolution/compat is the DID Core 1.0 path, so the
//     profile does not get it.
//
// Both profiles get the fixture method, which every resolution case needs.
var support = map[string][]core.Capability{
	core10.Name: {
		core.CapDIDParser, core.CapDocumentProducer, core.CapDocumentConsumer,
		core.CapDocumentValidator, core.CapV10Functions, core.CapFixtureMethod,
	},
	did11.Name: {
		core.CapDIDParser, core.CapDocumentProducer, core.CapDocumentConsumer,
		core.CapDocumentValidator, core.CapResolver, core.CapDereferencer, core.CapFixtureMethod, core.CapHTTPBinding,
	},
}

// Supports reports whether did-go implements capability c under profile.
// An unknown profile supports nothing.
func (s *Subject) Supports(profile string, c core.Capability) bool {
	for _, have := range support[profile] {
		if have == c {
			return true
		}
	}
	return false
}

// Capabilities returns the capabilities the subject declares under a
// profile, in the order of core.Capabilities.
func Capabilities(profile string) []core.Capability {
	var out []core.Capability
	s := &Subject{}
	for _, c := range core.Capabilities() {
		if s.Supports(profile, c) {
			out = append(out, c)
		}
	}
	return out
}

func (s *Subject) current() *players {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.players
}
