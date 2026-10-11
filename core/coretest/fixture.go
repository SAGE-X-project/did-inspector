// Package coretest provides a configurable fixture subject for testing the
// inspector itself: the runner, verdict aggregation, reports and the CLI.
//
// The fixture implements every capability with a small, deliberately simple
// behavior on well-formed inputs. Each capability can be declared
// unsupported or switched to a faulty behavior: a wrong result, an error or a
// panic. It is not a DID implementation and is never a subject of a real
// inspection.
package coretest

import (
	"context"
	"errors"
	"strings"

	"github.com/sage-x-project/did-inspector/core"
)

// Behavior selects how the fixture behaves for one capability.
type Behavior int

// Behaviors.
const (
	// Correct returns the expected result.
	Correct Behavior = iota
	// Wrong returns a well-formed but incorrect result.
	Wrong
	// Fails returns ErrFixture.
	Fails
	// Panics panics.
	Panics
)

// ErrFixture is the error a capability returns under Fails.
var ErrFixture = errors.New("coretest: fixture failure")

// ExampleDID is the one DID the fixture resolves.
const ExampleDID = "did:example:123"

// Fixture is a configurable subject.
type Fixture struct {
	Info core.SubjectInfo
	// Unsupported capabilities are declared unsupported under every profile.
	Unsupported map[core.Capability]bool
	// Behavior per capability; a missing entry means Correct.
	Behavior map[core.Capability]Behavior
}

// New returns a fixture that supports every capability and behaves
// correctly.
func New() *Fixture {
	return &Fixture{
		Info:        core.SubjectInfo{Name: "fixture", Version: "0.0.0", Revision: "fixture"},
		Unsupported: map[core.Capability]bool{},
		Behavior:    map[core.Capability]Behavior{},
	}
}

// With returns a copy of f with capability c set to behavior b.
func (f *Fixture) With(c core.Capability, b Behavior) *Fixture {
	g := f.clone()
	g.Behavior[c] = b
	return g
}

// Without returns a copy of f that declares capability c unsupported.
func (f *Fixture) Without(c core.Capability) *Fixture {
	g := f.clone()
	g.Unsupported[c] = true
	return g
}

func (f *Fixture) clone() *Fixture {
	g := &Fixture{Info: f.Info, Unsupported: map[core.Capability]bool{}, Behavior: map[core.Capability]Behavior{}}
	for k, v := range f.Unsupported {
		g.Unsupported[k] = v
	}
	for k, v := range f.Behavior {
		g.Behavior[k] = v
	}
	return g
}

// Describe implements core.Subject.
func (f *Fixture) Describe() core.SubjectInfo { return f.Info }

// Supports implements core.Subject.
func (f *Fixture) Supports(_ string, c core.Capability) bool { return !f.Unsupported[c] }

// enter applies the Fails and Panics behaviors and reports whether the
// result should be wrong.
func (f *Fixture) enter(c core.Capability) (wrong bool, err error) {
	switch f.Behavior[c] {
	case Wrong:
		return true, nil
	case Fails:
		return false, ErrFixture
	case Panics:
		panic("coretest: fixture panic in " + string(c))
	}
	return false, nil
}

// ParseDID implements core.DIDParser by splitting at the first two colons.
func (f *Fixture) ParseDID(s string) (core.DIDParts, error) {
	wrong, err := f.enter(core.CapDIDParser)
	if err != nil {
		return core.DIDParts{}, err
	}
	rest, ok := strings.CutPrefix(s, "did:")
	if !ok {
		return core.DIDParts{}, errors.New("coretest: not a DID")
	}
	method, msid, ok := strings.Cut(rest, ":")
	if !ok || method == "" || msid == "" {
		return core.DIDParts{}, errors.New("coretest: not a DID")
	}
	if wrong {
		method, msid = msid, method
	}
	return core.DIDParts{DID: s, Method: method, MethodSpecificID: msid}, nil
}

// ParseDIDURL implements core.DIDParser.
func (f *Fixture) ParseDIDURL(s string) (core.DIDURLParts, error) {
	if _, err := f.enter(core.CapDIDParser); err != nil {
		return core.DIDURLParts{}, err
	}
	out := core.DIDURLParts{DIDURL: s}
	rest := s
	if before, frag, ok := strings.Cut(rest, "#"); ok {
		rest, out.Fragment, out.HasFragment = before, frag, true
	}
	if before, q, ok := strings.Cut(rest, "?"); ok {
		rest, out.Query, out.HasQuery = before, q, true
	}
	did := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		did, out.Path = rest[:i], rest[i:]
	}
	parts, err := f.ParseDID(did)
	if err != nil {
		return core.DIDURLParts{}, err
	}
	out.DID = parts
	return out, nil
}

// MediaType returns the media type the fixture produces for a DID version.
func MediaType(version string) string {
	if version == "1.0" {
		return "application/did+json"
	}
	return "application/did"
}

// Produce implements core.DocumentProducer.
func (f *Fixture) Produce(doc core.DocumentJSON, version string) ([]byte, string, error) {
	wrong, err := f.enter(core.CapDocumentProducer)
	if err != nil {
		return nil, "", err
	}
	data, err := doc.MarshalJSON()
	if err != nil {
		return nil, "", err
	}
	if wrong {
		return data, "application/json", nil
	}
	return data, MediaType(version), nil
}

// Consume implements core.DocumentConsumer.
func (f *Fixture) Consume(data []byte, mediaType, requireVersion string, _ bool) (core.DocumentJSON, core.ConsumeInfo, error) {
	wrong, err := f.enter(core.CapDocumentConsumer)
	if err != nil {
		return core.DocumentJSON{}, core.ConsumeInfo{}, err
	}
	doc, err := core.ParseDocumentJSON(data)
	if err != nil {
		return core.DocumentJSON{}, core.ConsumeInfo{}, err
	}
	if wrong {
		doc = core.DocumentJSON{}
	}
	return doc, core.ConsumeInfo{MediaType: mediaType, Version: requireVersion}, nil
}

// Validate implements core.DocumentValidator: it reports a missing id.
func (f *Fixture) Validate(doc core.DocumentJSON, _ string) ([]core.Finding, error) {
	wrong, err := f.enter(core.CapDocumentValidator)
	if err != nil {
		return nil, err
	}
	if _, ok := doc.Get("id"); ok || wrong {
		return nil, nil
	}
	return []core.Finding{{Code: "missing-id", Path: "", Message: "the document has no id"}}, nil
}

func (f *Fixture) resolve(c core.Capability, did string) (core.ResolutionResult, error) {
	wrong, err := f.enter(c)
	if err != nil {
		return core.ResolutionResult{}, err
	}
	if did != ExampleDID {
		return core.ResolutionResult{
			ResolutionMetadata: core.NewDocument(core.M("error", core.Object(core.M("type", core.String("https://www.w3.org/ns/did#NOT_FOUND"))))),
		}, nil
	}
	id := did
	if wrong {
		id = did + "-wrong"
	}
	doc := core.NewDocument(core.M("id", core.String(id)))
	raw, err := doc.MarshalJSON()
	if err != nil {
		return core.ResolutionResult{}, err
	}
	mt := MediaType("1.1")
	return core.ResolutionResult{
		ResolutionMetadata: core.NewDocument(core.M("contentType", core.String(mt))),
		Document:           &doc,
		DocumentMetadata:   core.NewDocument(),
		Raw:                raw,
		MediaType:          mt,
	}, nil
}

// Resolve implements core.Resolver.
func (f *Fixture) Resolve(_ context.Context, did string, _ map[string]any) (core.ResolutionResult, error) {
	return f.resolve(core.CapResolver, did)
}

func (f *Fixture) dereference(c core.Capability, didURL string) (core.DereferenceResult, error) {
	r, err := f.resolve(c, strings.SplitN(didURL, "#", 2)[0])
	if err != nil {
		return core.DereferenceResult{}, err
	}
	if r.Document == nil {
		return core.DereferenceResult{DereferencingMetadata: r.ResolutionMetadata}, nil
	}
	return core.DereferenceResult{
		DereferencingMetadata: core.NewDocument(core.M("contentType", core.String(r.MediaType))),
		Content:               r.Raw,
		MediaType:             r.MediaType,
		ContentMetadata:       r.DocumentMetadata,
	}, nil
}

// Dereference implements core.Dereferencer.
func (f *Fixture) Dereference(_ context.Context, didURL string, _ map[string]any) (core.DereferenceResult, error) {
	return f.dereference(core.CapDereferencer, didURL)
}

// Resolve10 implements core.V10Functions.
func (f *Fixture) Resolve10(_ context.Context, did string, _ map[string]any) (core.ResolutionResult, error) {
	r, err := f.resolve(core.CapV10Functions, did)
	r.Raw, r.MediaType = nil, ""
	return r, err
}

// ResolveRepresentation10 implements core.V10Functions.
func (f *Fixture) ResolveRepresentation10(_ context.Context, did string, _ map[string]any) (core.ResolutionResult, error) {
	return f.resolve(core.CapV10Functions, did)
}

// Dereference10 implements core.V10Functions.
func (f *Fixture) Dereference10(_ context.Context, didURL string, _ map[string]any) (core.DereferenceResult, error) {
	return f.dereference(core.CapV10Functions, didURL)
}

// Bare is a subject that implements no capability interface. With
// DeclareAll it nevertheless declares every capability supported, which
// models an adapter bug.
type Bare struct {
	Info       core.SubjectInfo
	DeclareAll bool
}

// Describe implements core.Subject.
func (b Bare) Describe() core.SubjectInfo { return b.Info }

// Supports implements core.Subject.
func (b Bare) Supports(string, core.Capability) bool { return b.DeclareAll }

// Compile-time checks that Fixture implements every capability.
var (
	_ core.DIDParser         = (*Fixture)(nil)
	_ core.DocumentProducer  = (*Fixture)(nil)
	_ core.DocumentConsumer  = (*Fixture)(nil)
	_ core.DocumentValidator = (*Fixture)(nil)
	_ core.Resolver          = (*Fixture)(nil)
	_ core.Dereferencer      = (*Fixture)(nil)
	_ core.V10Functions      = (*Fixture)(nil)
)
