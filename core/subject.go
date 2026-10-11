// Package core defines what the inspector inspects and how it judges it: the
// subject and its capabilities, the neutral data types adapters exchange with
// the inspector, cases and observations, verdicts and their aggregation, and
// the runner that executes the cases of one profile against one subject.
//
// The core imports no subject implementation. Adapters, in their own
// modules, implement Subject and the capability interfaces they support.
package core

import (
	"context"
	"fmt"
	"slices"
)

// SubjectInfo identifies the implementation under inspection.
type SubjectInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

// Subject is an implementation under inspection. It declares, per profile,
// which capabilities it supports; each supported capability is reached
// through the corresponding capability interface, which the same value must
// implement.
type Subject interface {
	Describe() SubjectInfo
	Supports(profile string, c Capability) bool
}

// Capability names one optional operation group of a subject.
type Capability string

// Capabilities.
const (
	CapDIDParser         Capability = "did-parser"
	CapDocumentProducer  Capability = "document-producer"
	CapDocumentConsumer  Capability = "document-consumer"
	CapDocumentValidator Capability = "document-validator"
	CapResolver          Capability = "resolver"
	CapDereferencer      Capability = "dereferencer"
	CapV10Functions      Capability = "v10-functions"
)

var allCapabilities = []Capability{
	CapDIDParser, CapDocumentProducer, CapDocumentConsumer, CapDocumentValidator,
	CapResolver, CapDereferencer, CapV10Functions,
}

// Capabilities returns every known capability in a fixed order.
func Capabilities() []Capability {
	return slices.Clone(allCapabilities)
}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	return slices.Contains(allCapabilities, c)
}

// DIDParser parses DIDs and DID URLs into their components.
type DIDParser interface {
	ParseDID(s string) (DIDParts, error)
	ParseDIDURL(s string) (DIDURLParts, error)
}

// DocumentProducer serializes a DID document under a DID version ("1.0",
// "1.1") and returns the bytes and the media type it produced.
type DocumentProducer interface {
	Produce(doc DocumentJSON, version string) (data []byte, mediaType string, err error)
}

// DocumentConsumer deserializes a representation of a DID document.
// requireVersion, when not empty, asks the subject to accept only that DID
// version; strict asks it to apply every consumption rule it implements.
type DocumentConsumer interface {
	Consume(data []byte, mediaType, requireVersion string, strict bool) (DocumentJSON, ConsumeInfo, error)
}

// DocumentValidator checks a DID document against a DID version and reports
// what it found.
type DocumentValidator interface {
	Validate(doc DocumentJSON, version string) ([]Finding, error)
}

// Resolver implements DID resolution.
type Resolver interface {
	Resolve(ctx context.Context, did string, opts map[string]any) (ResolutionResult, error)
}

// Dereferencer implements DID URL dereferencing.
type Dereferencer interface {
	Dereference(ctx context.Context, didURL string, opts map[string]any) (DereferenceResult, error)
}

// V10Functions implements the abstract functions of DID Core 1.0 §7:
// resolve, resolveRepresentation and dereference.
type V10Functions interface {
	Resolve10(ctx context.Context, did string, opts map[string]any) (ResolutionResult, error)
	ResolveRepresentation10(ctx context.Context, did string, opts map[string]any) (ResolutionResult, error)
	Dereference10(ctx context.Context, didURL string, opts map[string]any) (DereferenceResult, error)
}

// Implements reports whether s implements the interface of capability c.
func Implements(s Subject, c Capability) bool {
	var ok bool
	switch c {
	case CapDIDParser:
		_, ok = s.(DIDParser)
	case CapDocumentProducer:
		_, ok = s.(DocumentProducer)
	case CapDocumentConsumer:
		_, ok = s.(DocumentConsumer)
	case CapDocumentValidator:
		_, ok = s.(DocumentValidator)
	case CapResolver:
		_, ok = s.(Resolver)
	case CapDereferencer:
		_, ok = s.(Dereferencer)
	case CapV10Functions:
		_, ok = s.(V10Functions)
	}
	return ok
}

// CapabilityError reports a capability a case needs and the subject lacks.
type CapabilityError struct {
	Profile     string
	Capability  Capability
	Unsupported bool
}

func (e *CapabilityError) Error() string {
	if e.Unsupported {
		return fmt.Sprintf("subject does not support %s under profile %s", e.Capability, e.Profile)
	}
	return fmt.Sprintf("subject declares %s under profile %s but does not implement it", e.Capability, e.Profile)
}
