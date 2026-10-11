package core10

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

// errResult is an unsuccessful result with a keyword error (DID Core 1.0
// §7.1.2), bent by the error faults.
func (m *mock) errResult(did, code string) core.ResolutionResult {
	var e core.Value
	switch {
	case m.on("error-object"):
		e = core.Object(core.M("type", core.String(code)))
	case m.on("error-not-keyword"):
		e = core.String(code + " error")
	case m.on("error-wrong-code"):
		e = core.String("internalError")
	default:
		e = core.String(code)
	}
	res := core.ResolutionResult{ResolutionMetadata: core.NewDocument(core.M("error", e)), DocumentMetadata: core.NewDocument()}
	if m.on("error-empty-metadata") {
		res.ResolutionMetadata = core.NewDocument()
	}
	if m.on("error-with-document") {
		doc := core.NewDocument(core.M("id", core.String(did)))
		res.Document, res.Raw = &doc, []byte(`{"id":"`+did+`"}`)
	}
	if m.on("error-with-metadata") {
		res.DocumentMetadata = core.NewDocument(core.M("created", core.String("2020-01-01T00:00:00Z")))
	}
	return res
}

// read resolves a DID through the registry and consumes the stored
// representation.
func (m *mock) read(did, versionID string) (fixtures.Record, core.DocumentJSON, string) {
	if !checks.IsDID(did) {
		return fixtures.Record{}, core.DocumentJSON{}, "invalidDid"
	}
	req := fixtures.Request{DID: did, VersionID: versionID}
	if m.on("wrong-current-version") && versionID == "" {
		req.VersionID = "1"
	}
	rec, err := m.reg.Read(req)
	var injected *fixtures.InjectedError
	switch {
	case errors.Is(err, fixtures.ErrMethodNotSupported):
		return rec, core.DocumentJSON{}, "methodNotSupported"
	case errors.As(err, &injected):
		return rec, core.DocumentJSON{}, "internalError"
	case err != nil:
		return rec, core.DocumentJSON{}, "notFound"
	}
	doc, err := core.ParseDocumentJSON(rec.Bytes)
	if m.on("accept-malformed") {
		if err != nil {
			doc = core.NewDocument(core.M("id", core.String(did)))
		}
		return rec, doc, ""
	}
	id, _ := doc.Get("id")
	if err != nil || id.Str != did || (rec.MediaType != MediaTypeJSON && rec.MediaType != MediaTypeJSONLD) {
		return rec, core.DocumentJSON{}, "invalidDidDocument"
	}
	return rec, doc, ""
}

func (m *mock) metadata(did string, rec fixtures.Record) core.DocumentJSON {
	if m.on("drop-metadata") {
		return core.NewDocument()
	}
	meta, _ := core.ParseDocumentJSON(rec.Metadata)
	var out core.DocumentJSON
	for _, mem := range meta.Members {
		v := mem.Value
		switch {
		case m.on("metadata-fraction") && (mem.Name == "created" || mem.Name == "updated" || mem.Name == "nextUpdate"):
			v = core.String(strings.TrimSuffix(v.Str, "Z") + ".000Z")
		case m.on("metadata-non-ascii") && (mem.Name == "versionId" || mem.Name == "nextVersionId"):
			v = core.String(v.Str + "é")
		case m.on("metadata-other-method") && mem.Name == "equivalentId":
			v = core.Array(core.String("did:other:x"))
		case m.on("metadata-other-method") && mem.Name == "canonicalId":
			v = core.String("did:other:y")
		case m.on("metadata-malformed-ids") && mem.Name == "equivalentId":
			v = core.String("did:example:x")
		case m.on("metadata-malformed-ids") && mem.Name == "canonicalId":
			v = core.Bool(true)
		}
		out.Members = append(out.Members, core.M(mem.Name, v))
	}
	if rec.Deactivated && !m.on("deactivated-no-flag") {
		out.Members = append(out.Members, core.M("deactivated", core.Bool(true)))
	}
	if !rec.Deactivated && m.on("deactivated-flag-on-active") {
		out.Members = append(out.Members, core.M("deactivated", core.String("no")))
	}
	if m.on("metadata-number") {
		out.Members = append(out.Members, core.M("duration", core.Number("12")))
	}
	if m.on("metadata-nested-number") {
		out.Members = append(out.Members, core.M("method", core.Object(core.M("seqNo", core.Number("11")))))
	}
	return out
}

func (m *mock) Resolve10(_ context.Context, did string, _ map[string]any) (core.ResolutionResult, error) {
	rec, doc, code := m.read(did, "")
	if code != "" {
		return m.errResult(did, code), nil
	}
	meta := core.NewDocument()
	if m.on("resolve-content-type") {
		meta = core.NewDocument(core.M("contentType", core.String(rec.MediaType)))
	}
	return core.ResolutionResult{ResolutionMetadata: meta, Document: &doc, DocumentMetadata: m.metadata(did, rec)}, nil
}

func (m *mock) ResolveRepresentation10(_ context.Context, did string, opts map[string]any) (core.ResolutionResult, error) {
	rec, doc, code := m.read(did, "")
	if code != "" {
		return m.errResult(did, code), nil
	}
	data, mt := m.represent(rec, doc, opts)
	return core.ResolutionResult{
		ResolutionMetadata: m.contentType(mt),
		DocumentMetadata:   m.metadata(did, rec),
		Raw:                data,
		MediaType:          mt,
	}, nil
}

// represent returns the stored representation, or the JSON representation
// (the document without @context) when the accept option asks for it and
// the fault accept-ignored is off.
func (m *mock) represent(rec fixtures.Record, doc core.DocumentJSON, opts map[string]any) ([]byte, string) {
	if a, _ := opts["accept"].(string); a != MediaTypeJSON || rec.MediaType == MediaTypeJSON || m.on("accept-ignored") {
		return rec.Bytes, rec.MediaType
	}
	var out core.DocumentJSON
	for _, mem := range doc.Members {
		if mem.Name != "@context" {
			out.Members = append(out.Members, mem)
		}
	}
	data, _ := out.MarshalJSON()
	return data, MediaTypeJSON
}

func (m *mock) contentType(mt string) core.DocumentJSON {
	switch {
	case m.on("representation-no-content-type"):
		return core.NewDocument()
	case m.on("content-type-wrong"):
		return core.NewDocument(core.M("contentType", core.String("application/json")))
	case m.on("content-type-not-ascii"):
		return core.NewDocument(core.M("contentType", core.String("application/dïd+json")))
	}
	return core.NewDocument(core.M("contentType", core.String(mt)))
}

func (m *mock) derefError(didURL, code string) core.DereferenceResult {
	r := m.errResult(didURL, code)
	return core.DereferenceResult{DereferencingMetadata: r.ResolutionMetadata, Content: r.Raw, ContentMetadata: r.DocumentMetadata}
}

func (m *mock) Dereference10(_ context.Context, didURL string, opts map[string]any) (core.DereferenceResult, error) {
	u, err := checks.ParseDIDURL(didURL)
	if err != nil {
		if m.on("deref-invalid-accepted") {
			return m.derefError(didURL, "notFound"), nil
		}
		return m.derefError(didURL, "invalidDidUrl"), nil
	}
	params, _ := url.ParseQuery(u.Query)
	rec, doc, code := m.read(u.DID.DID, params.Get("versionId"))
	switch {
	case code != "":
		return m.derefError(didURL, code), nil
	case u.Path != "":
		return m.derefError(didURL, "notFound"), nil
	case u.HasFragment && !m.on("fragment-whole-document"):
		for _, item := range append(listOf(doc, "verificationMethod"), listOf(doc, "service")...) {
			if id, _ := item.Get("id"); id.Str == u.DID.DID+"#"+u.Fragment {
				data, _ := item.MarshalJSON()
				return core.DereferenceResult{DereferencingMetadata: m.contentType(rec.MediaType), Content: data, MediaType: rec.MediaType, ContentMetadata: core.NewDocument()}, nil
			}
		}
		return m.derefError(didURL, "notFound"), nil
	}
	data, mt := m.represent(rec, doc, opts)
	md := m.contentType(mt)
	if m.on("deref-no-content-type") {
		md = core.NewDocument()
	}
	return core.DereferenceResult{
		DereferencingMetadata: md,
		Content:               data, MediaType: mt,
		ContentMetadata: m.metadata(u.DID.DID, rec),
	}, nil
}

func listOf(doc core.DocumentJSON, name string) []core.Value {
	v, _ := doc.Get(name)
	return v.Array
}
