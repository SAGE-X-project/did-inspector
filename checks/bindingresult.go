package checks

import (
	"errors"
	"fmt"

	"github.com/sage-x-project/did-inspector/core"
)

// BindingResult is the content of a DID resolution result (DID Resolution
// §9) or a DID URL dereferencing result (§10) sent as an HTTP body.
type BindingResult struct {
	// Content is the didDocument, or the content of a dereferencing
	// result; HasContent is false when the member is absent or null.
	Content    core.Value
	HasContent bool
	// Metadata is the didResolutionMetadata or the dereferencing metadata.
	Metadata core.DocumentJSON
	// ContentMetadata is the didDocumentMetadata or the contentMetadata.
	ContentMetadata core.DocumentJSON
}

// ParseResolutionResult reads a DID resolution result: a JSON object with
// the members didDocument (a map, null or absent when there is no document),
// didResolutionMetadata and didDocumentMetadata (maps), as in Example 21
// and Example 31.
func ParseResolutionResult(body []byte) (BindingResult, error) {
	d, err := core.ParseDocumentJSON(body)
	if err != nil {
		return BindingResult{}, fmt.Errorf("not a JSON object: %w", err)
	}
	return bindingResult(d, []string{"didDocument"}, []string{"didResolutionMetadata"}, "didDocumentMetadata", true)
}

// ParseDereferencingResult reads a DID URL dereferencing result: a JSON
// object with the content (any JSON value, null or absent when there is no
// content), the dereferencing metadata and contentMetadata (maps). The
// specification's examples disagree on member names: §10 Example 22 uses
// content and didUrlDereferencingMetadata, §12.3 Example 35 content and
// dereferencingMetadata, and §5 calls the content contentStream; each of
// these names is accepted.
func ParseDereferencingResult(body []byte) (BindingResult, error) {
	d, err := core.ParseDocumentJSON(body)
	if err != nil {
		return BindingResult{}, fmt.Errorf("not a JSON object: %w", err)
	}
	return bindingResult(d, []string{"content", "contentStream"}, []string{"dereferencingMetadata", "didUrlDereferencingMetadata"}, "contentMetadata", false)
}

func bindingResult(d core.DocumentJSON, content, metadata []string, contentMetadata string, contentIsMap bool) (BindingResult, error) {
	var r BindingResult
	for _, name := range content {
		if v, ok := d.Get(name); ok && v.Kind != core.KindNull {
			if contentIsMap && v.Kind != core.KindObject {
				return BindingResult{}, fmt.Errorf("%s is a JSON %s, not a map", name, v.Kind)
			}
			r.Content, r.HasContent = v, true
			break
		}
	}
	md, err := mapMember(d, metadata...)
	if err != nil {
		return BindingResult{}, err
	}
	cm, err := mapMember(d, contentMetadata)
	if err != nil {
		return BindingResult{}, err
	}
	r.Metadata, r.ContentMetadata = md, cm
	return r, nil
}

func mapMember(d core.DocumentJSON, names ...string) (core.DocumentJSON, error) {
	for _, name := range names {
		v, ok := d.Get(name)
		if !ok {
			continue
		}
		m, err := core.DocumentFromValue(v)
		if err != nil {
			return core.DocumentJSON{}, fmt.Errorf("%s is a JSON %s, not a map", name, v.Kind)
		}
		return m, nil
	}
	return core.DocumentJSON{}, fmt.Errorf("no %s member", names[0])
}

// errNoError reports a body that carries no error type.
var errNoError = errors.New("no error type in the response")

// BindingError returns the error object a binding response carries and
// its type: the error property of the metadata of a complete result
// (application/did-resolution or application/did-url-dereferencing), or the
// body itself when it is an RFC 9457 problem details object
// (application/problem+json, or any JSON object with a type member in a
// response whose status is 4xx or 5xx).
func BindingError(ex core.HTTPExchange) (core.Value, string, error) {
	var md core.DocumentJSON
	switch MediaTypeEssence(ex.Header.Get("Content-Type")) {
	case MediaTypeDIDResolution:
		r, err := ParseResolutionResult(ex.Body)
		if err != nil {
			return core.Value{}, "", err
		}
		md = r.Metadata
	case MediaTypeDIDURLDereferencing:
		r, err := ParseDereferencingResult(ex.Body)
		if err != nil {
			return core.Value{}, "", err
		}
		md = r.Metadata
	default:
		v, err := core.ParseJSON(ex.Body)
		if err != nil || v.Kind != core.KindObject || ex.Status < 400 {
			return core.Value{}, "", errNoError
		}
		md = core.NewDocument(core.M("error", v))
	}
	e, ok := md.Get("error")
	if !ok {
		return core.Value{}, "", errNoError
	}
	t, _ := e.Get("type")
	if t.Kind != core.KindString {
		return e, "", errNoError
	}
	return e, t.Str, nil
}
