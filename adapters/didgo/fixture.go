package didgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/sage-x-project/did-inspector/fixtures"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/spec"
)

// fixtureMethod is the driver of the fixture DID method "example": a
// did-go method.Method whose Read is fixtures.Registry.Read. It does
// nothing else (design §5.1): consuming the bytes, checking the document
// and building the resolution result are did-go's resolver's work.
type fixtureMethod struct {
	reg      *fixtures.Registry
	produces []string
}

var _ method.Method = (*fixtureMethod)(nil)

func newFixtureMethod(reg *fixtures.Registry) *fixtureMethod {
	var mts []string
	for _, d := range reg.DIDs() {
		for _, v := range reg.Entries[d].Versions {
			if !slices.Contains(mts, v.MediaType) {
				mts = append(mts, v.MediaType)
			}
		}
	}
	slices.Sort(mts)
	return &fixtureMethod{reg: reg, produces: mts}
}

// Name returns fixtures.Method.
func (m *fixtureMethod) Name() string { return fixtures.Method }

// Produces returns the media types the registry stores bytes under.
func (m *fixtureMethod) Produces() []string { return slices.Clone(m.produces) }

// Read looks the DID up in the registry and maps the outcome to did-go's
// driver contract:
//
//   - a record becomes a method.ReadResult with the stored bytes, their
//     media type and the stored DID document metadata, decoded with
//     document.Metadata's own JSON decoding; a deactivated DID sets
//     Metadata.Deactivated, where did-go's drivers report deactivation;
//   - fixtures.ErrNotFound and fixtures.ErrVersionNotFound become
//     method.ErrNotFound (the requested DID document does not exist);
//   - fixtures.ErrMethodNotSupported becomes method.ErrNotSupported;
//   - an *fixtures.InjectedError, fixtures.ErrInvalidVersionTime and stored
//     metadata did-go cannot decode stay plain errors: an unexpected
//     failure of the driver.
//
// The versionId and versionTime the resolver passes become the request's
// version selectors; versionTime is written in the datetime format of DID
// Resolution v1.0 §3.1.
func (m *fixtureMethod) Read(_ context.Context, d did.DID, opts method.ReadOptions) (*method.ReadResult, error) {
	req := fixtures.Request{DID: d.String(), VersionID: opts.VersionID}
	if opts.VersionTime != nil {
		req.VersionTime = spec.FormatTimestamp(*opts.VersionTime)
	}
	rec, err := m.reg.Read(req)
	switch {
	case errors.Is(err, fixtures.ErrNotFound), errors.Is(err, fixtures.ErrVersionNotFound):
		return nil, fmt.Errorf("fixture method: %w: %w", method.ErrNotFound, err)
	case errors.Is(err, fixtures.ErrMethodNotSupported):
		return nil, fmt.Errorf("fixture method: %w: %w", method.ErrNotSupported, err)
	case err != nil:
		return nil, fmt.Errorf("fixture method: %w", err)
	}
	var md document.Metadata
	if err := json.Unmarshal(rec.Metadata, &md); err != nil {
		return nil, fmt.Errorf("fixture method: stored metadata of %s: %w", rec.DID, err)
	}
	md.Deactivated = rec.Deactivated
	return &method.ReadResult{Data: rec.Bytes, ContentType: rec.MediaType, Metadata: md}, nil
}

// Create is not an operation of the fixture method.
func (m *fixtureMethod) Create(context.Context, *document.Document, method.CreateOptions) (*method.CreateResult, error) {
	return nil, method.ErrNotSupported
}

// Update is not an operation of the fixture method.
func (m *fixtureMethod) Update(context.Context, did.DID, *document.Document, method.UpdateOptions) (*method.UpdateResult, error) {
	return nil, method.ErrNotSupported
}

// Deactivate is not an operation of the fixture method.
func (m *fixtureMethod) Deactivate(context.Context, did.DID, method.DeactivateOptions) (*method.DeactivateResult, error) {
	return nil, method.ErrNotSupported
}

// LoadFixtureRegistry wires reg into did-go as the driver of the method
// "example": the resolver, the dereferencer and the DID Core 1.0 functions
// are rebuilt over a method.Registry that holds the fixture driver only.
// A later call replaces the registry.
func (s *Subject) LoadFixtureRegistry(reg *fixtures.Registry) error {
	if reg == nil {
		return errors.New("didgo adapter: nil fixture registry")
	}
	if err := reg.Validate(); err != nil {
		return fmt.Errorf("didgo adapter: %w", err)
	}
	p, err := newPlayers(newFixtureMethod(reg), s.consumer, s.producer)
	if err != nil {
		return fmt.Errorf("didgo adapter: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.players = p
	return nil
}
