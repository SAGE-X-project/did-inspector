package https

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

const mediaTypeURIList = "text/uri-list"

// acceptOf returns the Accept header for a call: the accept option when one
// is given, which asks for the didDocument or contentStream alone, or the
// media type of the complete result.
func acceptOf(opts map[string]any, full string) (string, bool) {
	v, ok := opts["accept"]
	if !ok {
		return full, true
	}
	if s, isString := v.(string); isString {
		return s, false
	}
	data, _ := json.Marshal(v) // option values come from JSON fixtures
	return string(data), false
}

// Resolve resolves did through the GET version of the binding and
// translates the response with ResolveResponse.
func (s *Subject) Resolve(ctx context.Context, did string, opts map[string]any) (core.ResolutionResult, error) {
	accept, full := acceptOf(opts, checks.MediaTypeDIDResolution)
	ex, err := s.call(ctx, did, accept, opts)
	if err != nil {
		return core.ResolutionResult{}, err
	}
	return ResolveResponse(ex, full)
}

// Dereference dereferences didURL through the GET version of the binding
// and translates the response with DereferenceResponse.
func (s *Subject) Dereference(ctx context.Context, didURL string, opts map[string]any) (core.DereferenceResult, error) {
	accept, full := acceptOf(opts, checks.MediaTypeDIDURLDereferencing)
	ex, err := s.call(ctx, didURL, accept, opts)
	if err != nil {
		return core.DereferenceResult{}, err
	}
	return DereferenceResponse(ex, full)
}

func (s *Subject) call(ctx context.Context, input, accept string, opts map[string]any) (core.HTTPExchange, error) {
	req, err := checks.BindingRequest(http.MethodGet, input, accept, opts)
	if err != nil {
		return core.HTTPExchange{}, fmt.Errorf("https adapter: %w", err)
	}
	return s.Exchange(ctx, req)
}

// untranslatable reports a response that is none of the forms the binding
// defines for the request.
func untranslatable(ex core.HTTPExchange) error {
	return fmt.Errorf("https adapter: status %d with Content-Type %q is not a response form of the binding", ex.Status, ex.Header.Get("Content-Type"))
}

// problem returns the error of a problem details response, if it is one.
func problem(ex core.HTTPExchange) (core.Value, bool) {
	ct := checks.MediaTypeEssence(ex.Header.Get("Content-Type"))
	if ct == checks.MediaTypeDIDResolution || ct == checks.MediaTypeDIDURLDereferencing {
		return core.Value{}, false
	}
	e, _, err := checks.BindingError(ex)
	return e, err == nil
}

// ResolveResponse translates a response of the binding to a resolution
// result:
//
//   - an application/did-resolution body is the complete result (§9): its
//     didDocument, didResolutionMetadata and didDocumentMetadata, with
//     the didDocument's JSON as the returned bytes and the contentType of
//     the metadata as their media type;
//   - an error response whose body is a problem details object (RFC 9457)
//     is a result whose didResolutionMetadata holds that object as error;
//   - when the didDocument alone was asked for, a 200 response is the
//     document in the representation of its Content-Type: the body is the
//     returned bytes, the Content-Type their media type and, as §12.1
//     makes them equal, the contentType of the didResolutionMetadata. The
//     binding carries no DID document metadata in this form.
//
// Any other response is an error: the adapter does not guess.
func ResolveResponse(ex core.HTTPExchange, full bool) (core.ResolutionResult, error) {
	ct := ex.Header.Get("Content-Type")
	switch {
	case checks.MediaTypeEssence(ct) == checks.MediaTypeDIDResolution:
		r, err := checks.ParseResolutionResult(ex.Body)
		if err != nil {
			return core.ResolutionResult{}, fmt.Errorf("https adapter: DID resolution result: %w", err)
		}
		out := core.ResolutionResult{ResolutionMetadata: r.Metadata, DocumentMetadata: r.ContentMetadata}
		if r.HasContent {
			doc, _ := core.DocumentFromValue(r.Content) // ParseResolutionResult checked it is a map
			raw, _ := doc.MarshalJSON()
			out.Document, out.Raw = &doc, raw
			if s, ok := r.Metadata.Get("contentType"); ok && s.Kind == core.KindString {
				out.MediaType = s.Str
			}
		}
		return out, nil
	case ex.Status >= 400:
		if e, ok := problem(ex); ok {
			return core.ResolutionResult{ResolutionMetadata: core.NewDocument(core.M("error", e)), DocumentMetadata: core.NewDocument()}, nil
		}
	case ex.Status == http.StatusOK && !full:
		out := core.ResolutionResult{
			ResolutionMetadata: core.NewDocument(core.M("contentType", core.String(ct))),
			DocumentMetadata:   core.NewDocument(),
			Raw:                ex.Body, MediaType: ct,
		}
		if doc, err := core.ParseDocumentJSON(ex.Body); err == nil {
			out.Document = &doc
		}
		return out, nil
	}
	return core.ResolutionResult{}, untranslatable(ex)
}

// DereferenceResponse translates a response of the binding to a
// dereferencing result:
//
//   - an application/did-url-dereferencing body is the complete result
//     (§10), read by checks.ParseDereferencingResult. Its content becomes
//     the content stream: a JSON string as its text, a JSON array of
//     strings whose contentType is text/uri-list as one URL per line with
//     CRLF line ends (RFC 2483 §5), any other JSON value as its JSON text.
//     The media type is the contentType of the dereferencing metadata, or
//     of the content metadata when only that has one;
//   - an error response whose body is a problem details object is a result
//     whose dereferencing metadata holds that object as error;
//   - when the content alone was asked for, a 303 response is the selected
//     service endpoint URL of its Location header as text/uri-list content
//     (§12.1), and a 200 response is the content in the representation of
//     its Content-Type, which is also the contentType of the metadata.
//
// Any other response is an error.
func DereferenceResponse(ex core.HTTPExchange, full bool) (core.DereferenceResult, error) {
	ct := ex.Header.Get("Content-Type")
	switch {
	case checks.MediaTypeEssence(ct) == checks.MediaTypeDIDURLDereferencing:
		r, err := checks.ParseDereferencingResult(ex.Body)
		if err != nil {
			return core.DereferenceResult{}, fmt.Errorf("https adapter: DID URL dereferencing result: %w", err)
		}
		out := core.DereferenceResult{DereferencingMetadata: r.Metadata, ContentMetadata: r.ContentMetadata}
		out.MediaType = contentType(r.Metadata, r.ContentMetadata)
		if r.HasContent {
			out.Content = contentBytes(r.Content, out.MediaType)
		}
		return out, nil
	case ex.Status >= 400:
		if e, ok := problem(ex); ok {
			return core.DereferenceResult{DereferencingMetadata: core.NewDocument(core.M("error", e)), ContentMetadata: core.NewDocument()}, nil
		}
	case ex.Status == http.StatusSeeOther && !full:
		if loc := ex.Header.Get("Location"); loc != "" {
			return core.DereferenceResult{
				DereferencingMetadata: core.NewDocument(core.M("contentType", core.String(mediaTypeURIList))),
				Content:               []byte(loc + "\r\n"), MediaType: mediaTypeURIList, ContentMetadata: core.NewDocument(),
			}, nil
		}
	case ex.Status == http.StatusOK && !full:
		return core.DereferenceResult{
			DereferencingMetadata: core.NewDocument(core.M("contentType", core.String(ct))),
			Content:               ex.Body, MediaType: ct, ContentMetadata: core.NewDocument(),
		}, nil
	}
	return core.DereferenceResult{}, untranslatable(ex)
}

func contentType(md, cm core.DocumentJSON) string {
	for _, d := range []core.DocumentJSON{md, cm} {
		if v, ok := d.Get("contentType"); ok && v.Kind == core.KindString {
			return v.Str
		}
	}
	return ""
}

func contentBytes(v core.Value, mediaType string) []byte {
	switch v.Kind {
	case core.KindString:
		return []byte(v.Str)
	case core.KindArray:
		if len(v.Array) == 0 {
			return nil
		}
		if checks.MediaTypeEssence(mediaType) == mediaTypeURIList {
			lines := make([]string, 0, len(v.Array))
			for _, x := range v.Array {
				if x.Kind != core.KindString {
					lines = nil
					break
				}
				lines = append(lines, x.Str)
			}
			if lines != nil {
				return []byte(strings.Join(lines, "\r\n") + "\r\n")
			}
		}
	}
	data, _ := v.MarshalJSON()
	return data
}
