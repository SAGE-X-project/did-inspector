package didgo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/did"
	"github.com/sage-x-project/did-go/relyingparty"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/spec"
	"github.com/sage-x-project/did-go/vm"
)

// RetrieveVerificationMethod runs CID 1.0 §3.3 with did-go's relying party
// (relyingparty.RelyingParty.VerificationMethod) over did-go's
// dereferencer, which resolves the fixture method, under DID 1.1 rules and
// with the options translated as Dereference translates them
// (WithDereferenceOptions). The vmIdentifier is read with
// did.ParseReference, so that a relative reference reaches the relying
// party, which refuses it itself; a string did-go cannot read as a DID URL
// reference is reported as an error did-go raised, without a type. The
// returned vm.Method is written as its JSON object, and an error the relying
// party raises is reported with the type, title and detail of the
// *resolution.Error it wraps.
func (s *Subject) RetrieveVerificationMethod(ctx context.Context, vmIdentifier, relationship string, opts map[string]any) (core.RetrievalResult, error) {
	purpose, err := vm.ParsePurpose(relationship)
	if err != nil {
		return core.RetrievalResult{}, fmt.Errorf("didgo adapter: %w", err)
	}
	ref, err := did.ParseReference(vmIdentifier)
	if err != nil {
		return core.RetrievalResult{Error: &core.ProcessingError{Detail: "did-go cannot read the identifier as a DID URL reference: " + err.Error()}}, nil
	}
	rp, err := relyingparty.New(s.current().dereferencer, relyingparty.WithVersion(spec.V11), relyingparty.WithDereferenceOptions(dereferenceOptions(opts)))
	if err != nil {
		return core.RetrievalResult{}, fmt.Errorf("didgo adapter: %w", err)
	}
	m, err := rp.VerificationMethod(ctx, ref, purpose)
	if err != nil {
		return core.RetrievalResult{Error: processingError(err)}, nil
	}
	v, err := methodJSON(*m)
	if err != nil {
		return core.RetrievalResult{}, fmt.Errorf("didgo adapter: verification method: %w", err)
	}
	doc, err := core.DocumentFromValue(v)
	if err != nil {
		return core.RetrievalResult{}, fmt.Errorf("didgo adapter: verification method: %w", err)
	}
	return core.RetrievalResult{VerificationMethod: &doc}, nil
}

// processingError translates an error of the relying party.
func processingError(err error) *core.ProcessingError {
	var re *resolution.Error
	if errors.As(err, &re) {
		return &core.ProcessingError{Type: re.Type, Title: re.Title, Detail: err.Error()}
	}
	return &core.ProcessingError{Detail: err.Error()}
}

// vmHolder is the DID of the document the adapter wraps a standalone
// verification method in when neither its id nor its controller names one.
const vmHolder = "did:example:inspector-verification-method"

// ValidateVerificationMethod reads the verification method into did-go's
// vm.Method and runs vm.Method.Validate, which holds the same checks in
// every DID version. did-go's only public way from JSON to a vm.Method is
// its consumer, so the adapter wraps the method in a document whose id is
// the DID of the method's id or controller and reads that document with
// the translator (see toDocument). A value did-go cannot read is reported
// as one finding with did-go's reason, located in the method.
func (s *Subject) ValidateVerificationMethod(m core.DocumentJSON, ver string) ([]core.Finding, error) {
	v, err := version(ver)
	if err != nil {
		return nil, err
	}
	if v == spec.VUnknown {
		v = spec.Latest
	}
	holder := core.NewDocument(core.M("id", core.String(holderDID(m))), core.M("verificationMethod", core.Array(m.Value())))
	d, err := toDocument(holder, v)
	if err != nil {
		f := errorFinding(err)
		f.Path = inMethod(f.Path)
		return []core.Finding{f}, nil
	}
	methods := d.VerificationMethods()
	if len(methods) != 1 {
		return nil, fmt.Errorf("didgo adapter: did-go read %d verification methods from one", len(methods))
	}
	err = methods[0].Validate()
	var ve *vm.Error
	switch {
	case err == nil:
		return nil, nil
	case errors.As(err, &ve):
		return []core.Finding{{Code: codeOr(ve.Statement, "did-go"), Path: pointer(ve.Property), Message: ve.Error()}}, nil
	}
	return []core.Finding{{Code: "did-go", Message: err.Error()}}, nil
}

// inMethod turns a JSON Pointer into the wrapping document
// ("/verificationMethod/0/secretKeyJwk", or "/verificationMethod/secretKeyJwk"
// as did-go's consumer reports a property of a method) into a pointer into
// the method ("/secretKeyJwk").
func inMethod(p string) string {
	rest, ok := strings.CutPrefix(p, "/verificationMethod")
	if !ok {
		return p
	}
	if next, after, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/"); next != "" && strings.Trim(next, "0123456789") == "" {
		return "/" + after
	}
	return rest
}

// holderDID returns the DID of the method's id or controller, or vmHolder.
func holderDID(m core.DocumentJSON) string {
	if id, ok := m.Get("id"); ok && id.Kind == core.KindString {
		if u, err := did.ParseURL(id.Str); err == nil {
			return u.DID().String()
		}
	}
	if c, ok := m.Get("controller"); ok && c.Kind == core.KindString {
		if d, err := did.Parse(c.Str); err == nil {
			return d.String()
		}
	}
	return vmHolder
}

// ResolveDIDURLReference reads ref with did.ParseReference and base with
// did.Parse and resolves the reference with did.DIDURL.Resolve.
func (s *Subject) ResolveDIDURLReference(base, ref string) (string, error) {
	b, err := did.Parse(base)
	if err != nil {
		return "", err
	}
	u, err := did.ParseReference(ref)
	if err != nil {
		return "", err
	}
	out, err := u.Resolve(b.URL())
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// ProduceRepresentation serializes doc with did-go's producer in the
// representation the media type names: ProduceOptions.JSONLD is set as
// representation.OptionsFor sets it for that media type, and the version
// is the requested one.
func (s *Subject) ProduceRepresentation(doc core.DocumentJSON, ver, mediaType string) ([]byte, string, error) {
	v, err := version(ver)
	if err != nil {
		return nil, "", err
	}
	if v == spec.VUnknown {
		v = spec.Latest
	}
	popts, err := representation.OptionsFor(mediaType)
	if err != nil {
		return nil, "", err
	}
	d, err := toDocument(doc, v)
	if err != nil {
		return nil, "", fmt.Errorf("did-go cannot hold the document: %w", err)
	}
	return s.producer.Produce(d, representation.ProduceOptions{Version: v, JSONLD: popts.JSONLD})
}
