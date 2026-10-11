package didgo

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/compat"
)

// The DID Core 1.0 §7 functions go through resolution/compat, whose
// functions take a parsed did.DID or did.DIDURL. For a string that did-go
// does not parse, the adapter asks did-go's own string entry point
// (ResolveString, DereferenceString) for the result and converts its error
// with compat.ErrorString, the conversion resolution/compat applies to every
// error; the result then has no document or content and empty metadata, as
// compat returns for every failure.

// Resolve10 is resolve of DID Core 1.0 §7.1 through compat.V10Resolver.
func (s *Subject) Resolve10(ctx context.Context, in string, opts map[string]any) (core.ResolutionResult, error) {
	p := s.current()
	ro := resolutionOptions(opts)
	d, err := did.Parse(in)
	if err != nil {
		return v10Failure(p.resolver.ResolveString(ctx, in, ro).ResolutionMetadata.Error)
	}
	md, doc, dm := p.v10Resolver.Resolve(ctx, d, ro)
	meta, err := marshalJSON(md)
	if err != nil {
		return core.ResolutionResult{}, fmt.Errorf("didgo adapter: resolution metadata: %w", err)
	}
	return withDocument(core.ResolutionResult{ResolutionMetadata: meta}, doc, dm)
}

// ResolveRepresentation10 is resolveRepresentation of DID Core 1.0 §7.1
// through compat.V10Resolver; the byte stream is Raw and its contentType
// the media type.
func (s *Subject) ResolveRepresentation10(ctx context.Context, in string, opts map[string]any) (core.ResolutionResult, error) {
	p := s.current()
	ro := resolutionOptions(opts)
	d, err := did.Parse(in)
	if err != nil {
		return v10Failure(p.resolver.ResolveString(ctx, in, ro).ResolutionMetadata.Error)
	}
	md, stream, dm := p.v10Resolver.ResolveRepresentation(ctx, d, ro)
	meta, err := marshalJSON(md)
	if err != nil {
		return core.ResolutionResult{}, fmt.Errorf("didgo adapter: resolution metadata: %w", err)
	}
	return withDocument(core.ResolutionResult{ResolutionMetadata: meta, Raw: stream, MediaType: md.ContentType}, nil, dm)
}

// Dereference10 is dereference of DID Core 1.0 §7.2 through
// compat.V10Dereferencer; the content is written as contentBytes
// describes.
func (s *Subject) Dereference10(ctx context.Context, didURL string, opts map[string]any) (core.DereferenceResult, error) {
	p := s.current()
	do := dereferenceOptions(opts)
	u, err := did.ParseURL(didURL)
	if err != nil {
		e := p.dereferencer.DereferenceString(ctx, didURL, do).DereferencingMetadata.Error
		meta, err := marshalJSON(compat.V10DereferencingMetadata{Error: compat.ErrorString(e)})
		if err != nil {
			return core.DereferenceResult{}, err
		}
		return dereferenceResult(p.producer, meta, "", nil, document.Metadata{})
	}
	md, content, cm := p.v10Deref.Dereference(ctx, u, do)
	meta, err := marshalJSON(md)
	if err != nil {
		return core.DereferenceResult{}, fmt.Errorf("didgo adapter: dereferencing metadata: %w", err)
	}
	return dereferenceResult(p.producer, meta, md.ContentType, content, cm)
}

// v10Failure returns the DID Core 1.0 result of a failure that did-go
// reported as e.
func v10Failure(e *resolution.Error) (core.ResolutionResult, error) {
	meta, err := marshalJSON(compat.V10ResolutionMetadata{Error: compat.ErrorString(e)})
	if err != nil {
		return core.ResolutionResult{}, err
	}
	return withDocument(core.ResolutionResult{ResolutionMetadata: meta}, nil, document.Metadata{})
}
