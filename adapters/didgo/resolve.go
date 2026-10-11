package didgo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sage-x-project/did-inspector/core"

	"github.com/sage-x-project/did-go/dereferencer"
	"github.com/sage-x-project/did-go/document"
	"github.com/sage-x-project/did-go/method"
	"github.com/sage-x-project/did-go/representation"
	"github.com/sage-x-project/did-go/resolution"
	"github.com/sage-x-project/did-go/resolution/compat"
	"github.com/sage-x-project/did-go/resolver"
	"github.com/sage-x-project/did-go/vm"
)

// players are did-go's resolution players over one method registry.
type players struct {
	resolver     *resolver.DefaultResolver
	dereferencer *dereferencer.Dereferencer
	v10Resolver  *compat.V10Resolver
	v10Deref     *compat.V10Dereferencer
	producer     representation.Producer
}

// newPlayers builds did-go's DefaultResolver over a registry that holds the
// fixture driver (or no driver when m is nil), its Dereferencer, and the
// DID Core 1.0 functions of resolution/compat over both.
func newPlayers(m *fixtureMethod, c representation.Consumer, p representation.Producer) (*players, error) {
	var drivers []method.Method
	if m != nil {
		drivers = append(drivers, m)
	}
	reg, err := method.NewRegistry(drivers...)
	if err != nil {
		return nil, err
	}
	r, err := resolver.New(reg, c, p)
	if err != nil {
		return nil, err
	}
	d, err := dereferencer.New(r, p)
	if err != nil {
		return nil, err
	}
	return &players{
		resolver:     r,
		dereferencer: d,
		v10Resolver:  &compat.V10Resolver{Inner: r},
		v10Deref:     &compat.V10Dereferencer{Inner: d},
		producer:     p,
	}, nil
}

// Resolution options with a model in did-go.
const (
	optAccept         = "accept"
	optExpand         = "expandRelativeUrls"
	optVersionID      = "versionId"
	optVersionTime    = "versionTime"
	optNoCache        = "noCache"
	optVerificationRe = "verificationRelationship"
)

// resolutionOptions translates resolution options. An option that
// resolution.ResolutionOptions models is put in its field when its value
// has the field's type (versionTime: a string that time.RFC3339Nano reads,
// with its offset and fraction kept for did-go to check). An option of the
// wrong type, and every other option, goes to Extra under its name, where
// did-go treats a modeled name as an invalid option and any other name as
// an extension option.
func resolutionOptions(opts map[string]any) resolution.ResolutionOptions {
	var o resolution.ResolutionOptions
	for name, v := range opts {
		if !setResolutionOption(&o, name, v) {
			if o.Extra == nil {
				o.Extra = map[string]any{}
			}
			o.Extra[name] = v
		}
	}
	return o
}

func setResolutionOption(o *resolution.ResolutionOptions, name string, v any) bool {
	switch name {
	case optAccept:
		s, ok := v.(string)
		o.Accept = s
		return ok
	case optExpand:
		b, ok := v.(bool)
		o.ExpandRelativeURLs = b
		return ok
	case optVersionID:
		s, ok := v.(string)
		o.VersionID = s
		return ok
	case optNoCache:
		b, ok := v.(bool)
		o.NoCache = b
		return ok
	case optVersionTime:
		s, ok := v.(string)
		if !ok {
			return false
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return false
		}
		o.VersionTime = &t
		return true
	}
	return false
}

// dereferenceOptions translates dereferencing options as
// resolutionOptions does, for the options resolution.DereferenceOptions
// models: accept and verificationRelationship.
func dereferenceOptions(opts map[string]any) resolution.DereferenceOptions {
	var o resolution.DereferenceOptions
	for name, v := range opts {
		s, isString := v.(string)
		switch {
		case name == optAccept && isString:
			o.Accept = s
		case name == optVerificationRe && isString:
			o.VerificationRelationship = s
		default:
			if o.Extra == nil {
				o.Extra = map[string]any{}
			}
			o.Extra[name] = v
		}
	}
	return o
}

// Resolve resolves did with did-go's DefaultResolver (ResolveString, which
// reports a string that is not a DID as INVALID_DID) and translates the
// result: both metadata structures through their own JSON encoding, the
// document with its representation-specific entries, and the returned
// bytes with didResolutionMetadata.contentType as their media type.
func (s *Subject) Resolve(ctx context.Context, in string, opts map[string]any) (core.ResolutionResult, error) {
	res := s.current().resolver.ResolveString(ctx, in, resolutionOptions(opts))
	md, err := marshalJSON(res.ResolutionMetadata)
	if err != nil {
		return core.ResolutionResult{}, fmt.Errorf("didgo adapter: resolution metadata: %w", err)
	}
	out := core.ResolutionResult{ResolutionMetadata: md, Raw: res.Raw, MediaType: res.ResolutionMetadata.ContentType}
	return withDocument(out, res.Document, res.DocumentMetadata)
}

func withDocument(out core.ResolutionResult, d *document.Document, md document.Metadata) (core.ResolutionResult, error) {
	if d != nil {
		doc, err := fullDocumentJSON(d)
		if err != nil {
			return core.ResolutionResult{}, fmt.Errorf("didgo adapter: document: %w", err)
		}
		out.Document = &doc
	}
	dm, err := marshalJSON(md)
	if err != nil {
		return core.ResolutionResult{}, fmt.Errorf("didgo adapter: document metadata: %w", err)
	}
	out.DocumentMetadata = dm
	return out, nil
}

// Dereference dereferences didURL with did-go's Dereferencer
// (DereferenceString, which reports a string that is not a DID URL as
// INVALID_DID_URL) and translates the result; contentStream is written as
// contentBytes describes.
func (s *Subject) Dereference(ctx context.Context, didURL string, opts map[string]any) (core.DereferenceResult, error) {
	p := s.current()
	res := p.dereferencer.DereferenceString(ctx, didURL, dereferenceOptions(opts))
	md, err := marshalJSON(res.DereferencingMetadata)
	if err != nil {
		return core.DereferenceResult{}, fmt.Errorf("didgo adapter: dereferencing metadata: %w", err)
	}
	return dereferenceResult(p.producer, md, res.DereferencingMetadata.ContentType, res.ContentStream, res.ContentMetadata)
}

func dereferenceResult(p representation.Producer, md core.DocumentJSON, ct string, content any, cm document.Metadata) (core.DereferenceResult, error) {
	if ct == "" {
		if s, ok := cm.Extra["contentType"].(string); ok {
			ct = s
		}
	}
	data, err := contentBytes(p, content, ct)
	if err != nil {
		return core.DereferenceResult{}, fmt.Errorf("didgo adapter: content stream: %w", err)
	}
	cmd, err := marshalJSON(cm)
	if err != nil {
		return core.DereferenceResult{}, fmt.Errorf("didgo adapter: content metadata: %w", err)
	}
	return core.DereferenceResult{DereferencingMetadata: md, Content: data, MediaType: ct, ContentMetadata: cmd}, nil
}

// contentBytes writes the content stream did-go's dereferencer returned as
// bytes in the representation its contentType names:
//
//   - a *document.Document is produced by did-go's producer with the
//     options representation.OptionsFor gives for the contentType, as the
//     dereferencer documents ("whose representation is
//     dereferencingMetadata.contentType");
//   - a vm.Method, vm.Service or document.Map (a fragment) is written as
//     its JSON object, with the properties did-go holds;
//   - a []string of URLs (text/uri-list) is written one URL per line with
//     CRLF line ends (RFC 2483 §5), as did-go's HTTPS binding writes it;
//   - bytes and strings are passed on unchanged.
func contentBytes(p representation.Producer, content any, ct string) ([]byte, error) {
	switch c := content.(type) {
	case nil:
		return nil, nil
	case []byte:
		return c, nil
	case string:
		return []byte(c), nil
	case []string:
		if len(c) == 0 {
			return nil, nil
		}
		return []byte(strings.Join(c, "\r\n") + "\r\n"), nil
	case *document.Document:
		popts, err := representation.OptionsFor(ct)
		if err != nil {
			return nil, err
		}
		data, _, err := p.Produce(c, popts)
		return data, err
	case vm.Method:
		v, err := methodJSON(c)
		if err != nil {
			return nil, err
		}
		return v.MarshalJSON()
	case vm.Service:
		v, err := serviceJSON(c)
		if err != nil {
			return nil, err
		}
		return v.MarshalJSON()
	case document.Map:
		v, err := mapJSON(c)
		if err != nil {
			return nil, err
		}
		return v.MarshalJSON()
	}
	return nil, fmt.Errorf("content of type %T has no byte form", content)
}
