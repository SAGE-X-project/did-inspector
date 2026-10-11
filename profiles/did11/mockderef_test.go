package did11

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

func (m *mock) derefError(didURL, name string) core.DereferenceResult {
	r := m.errResult(didURL, name)
	out := core.DereferenceResult{DereferencingMetadata: r.ResolutionMetadata, ContentMetadata: r.DocumentMetadata}
	if r.Document != nil {
		out.Content, _ = r.Document.MarshalJSON()
	}
	return out
}

// Dereference follows DID Resolution §5.4.
func (m *mock) Dereference(ctx context.Context, didURL string, opts map[string]any) (core.DereferenceResult, error) {
	u, err := checks.ParseDIDURL(didURL)
	if err != nil {
		if m.on("deref-invalid-accepted") {
			return m.derefError(didURL, "NOT_FOUND"), nil
		}
		return m.derefError(didURL, "INVALID_DID_URL"), nil
	}
	params, _ := url.ParseQuery(u.Query)
	resOpts := map[string]any{}
	for _, k := range []string{"versionId", "versionTime"} {
		if v := params.Get(k); v != "" {
			resOpts[k] = v
		}
	}
	if a, ok := opts["accept"]; ok {
		resOpts["accept"] = a
	}
	res, _ := m.Resolve(ctx, u.DID.DID, resOpts)
	if e, ok := res.ResolutionMetadata.Get("error"); ok {
		t, _ := e.Get("type")
		return m.derefError(didURL, strings.TrimPrefix(t.Str, nsDID)), nil
	}
	if res.Document == nil {
		return m.derefError(didURL, "NOT_FOUND"), nil
	}
	doc, meta := *res.Document, res.DocumentMetadata
	if m.on("deref-no-metadata") {
		meta = core.NewDocument()
	}
	onlyVersion := true
	for k := range params {
		onlyVersion = onlyVersion && (k == "versionId" || k == "versionTime")
	}
	switch {
	case params.Has("service") || params.Has("serviceType"):
		return m.services(didURL, u, params, doc, meta, opts), nil
	case u.Path != "" || (u.HasQuery && !onlyVersion):
		if m.on("path-error-type") {
			return m.derefError(didURL, "INVALID_DID_URL"), nil
		}
		return m.derefError(didURL, "NOT_FOUND"), nil
	case u.HasFragment && !m.on("fragment-whole-document"):
		return m.fragment(didURL, u, doc, opts), nil
	}
	return m.content(doc, meta), nil
}

func (m *mock) content(doc, meta core.DocumentJSON) core.DereferenceResult {
	data, _ := doc.MarshalJSON()
	mt := MediaType
	if m.on("content-type-not-ascii") {
		mt = "application/dïd"
	}
	return core.DereferenceResult{
		DereferencingMetadata: core.NewDocument(core.M("contentType", core.String(mt))),
		Content:               data, MediaType: MediaType, ContentMetadata: meta,
	}
}

// fragment dereferences a DID fragment from the resolved document (DID
// Resolution §5.4.2, CID §3.4).
func (m *mock) fragment(didURL string, u core.DIDURLParts, doc core.DocumentJSON, opts map[string]any) core.DereferenceResult {
	full := u.DID.DID + "#" + u.Fragment
	found, ok := m.find(doc.Value(), full, "#"+u.Fragment, 0)
	if rel, has := opts["verificationRelationship"].(string); has && !m.on("vr-ignored") {
		if m.on("vr-reject-all") {
			return m.derefError(didURL, "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD")
		}
		if !ok || !isVerificationMethod(found) {
			return m.derefError(didURL, "INVALID_VERIFICATION_METHOD")
		}
		if !authorized(doc, rel, u.DID.DID, full) {
			return m.derefError(didURL, "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD")
		}
	}
	if !ok {
		return m.derefError(didURL, "NOT_FOUND")
	}
	res := core.Object(append([]core.Member{core.M("@context", core.String(contextURL))}, found.Object...)...)
	data, _ := res.MarshalJSON()
	return core.DereferenceResult{
		DereferencingMetadata: core.NewDocument(core.M("contentType", core.String(MediaType))),
		Content:               data, MediaType: MediaType, ContentMetadata: core.NewDocument(),
	}
}

// find looks for a map whose id is full or rel, recursively.
func (m *mock) find(v core.Value, full, rel string, depth int) (core.Value, bool) {
	switch v.Kind {
	case core.KindObject:
		if id, ok := v.Get("id"); ok && depth > 0 && (id.Str == full || (id.Str == rel && !m.on("fragment-no-relative"))) {
			return v, true
		}
		for _, mem := range v.Object {
			if depth == 0 && m.on("fragment-shallow") && mem.Name != "verificationMethod" && mem.Name != "service" {
				continue
			}
			if f, ok := m.find(mem.Value, full, rel, depth+1); ok {
				return f, true
			}
		}
	case core.KindArray:
		for _, x := range v.Array {
			if f, ok := m.find(x, full, rel, depth+1); ok {
				return f, true
			}
		}
	}
	return core.Value{}, false
}

func isVerificationMethod(v core.Value) bool {
	_, t := v.Get("type")
	_, c := v.Get("controller")
	return t && c
}

func authorized(doc core.DocumentJSON, rel, did, full string) bool {
	arr, _ := doc.Get(rel)
	for _, x := range arr.Array {
		id := x.Str
		if x.Kind == core.KindObject {
			v, _ := x.Get("id")
			id = v.Str
		}
		if id == full || did+id == full {
			return true
		}
	}
	return false
}

// services selects services by the service and serviceType parameters and
// returns the document with them or their endpoint URLs (DID Resolution
// §5.4.1, §5.4.2).
func (m *mock) services(didURL string, u core.DIDURLParts, params url.Values, doc, meta core.DocumentJSON, opts map[string]any) core.DereferenceResult {
	did := u.DID.DID
	all, _ := doc.Get("service")
	var selected []core.Value
	for _, s := range all.Array {
		id, _ := s.Get("id")
		typ, _ := s.Get("type")
		if (params.Has("service") && absoluteRef(did, id.Str) != absoluteRef(did, "#"+params.Get("service"))) ||
			(params.Has("serviceType") && !typeMatches(typ, params.Get("serviceType"))) {
			if !m.on("service-ignore-selection") {
				continue
			}
		}
		selected = append(selected, s)
	}
	accept, _ := opts["accept"].(string)
	switch {
	case accept == "" || accept == MediaType:
		var out core.DocumentJSON
		for _, mem := range doc.Members {
			if mem.Name == "service" {
				mem = core.M("service", core.Array(selected...))
			}
			out.Members = append(out.Members, mem)
		}
		return m.content(out, meta)
	case accept == "text/uri-list":
		return m.uriList(didURL, u, params, selected)
	case m.on("accept-any-representation"):
		return m.content(doc, meta)
	}
	return m.derefError(didURL, "REPRESENTATION_NOT_SUPPORTED")
}

func absoluteRef(did, ref string) string {
	if strings.HasPrefix(ref, "#") {
		return did + ref
	}
	return ref
}

func typeMatches(t core.Value, want string) bool {
	if t.Kind == core.KindString {
		return t.Str == want
	}
	return slices.ContainsFunc(t.Array, func(v core.Value) bool { return v.Str == want })
}

func (m *mock) uriList(didURL string, u core.DIDURLParts, params url.Values, selected []core.Value) core.DereferenceResult {
	var urls []string
	for _, s := range selected {
		ep, _ := s.Get("serviceEndpoint")
		switch ep.Kind {
		case core.KindString:
			urls = append(urls, ep.Str)
		case core.KindArray:
			for _, x := range ep.Array {
				switch {
				case x.Kind == core.KindString:
					urls = append(urls, x.Str)
				case m.on("uri-list-include-maps"):
					urls = append(urls, checks.Compact(x))
				}
			}
		case core.KindObject:
			if m.on("uri-list-include-maps") {
				urls = append(urls, checks.Compact(ep))
			}
		}
	}
	for i, ep := range urls {
		if ref := params.Get("relativeRef"); ref != "" {
			if m.on("relative-ref-append") {
				urls[i] = ep + ref
			} else if r, err := relativeResolve(ep, ref); err == nil {
				urls[i] = r
			}
		}
		if u.HasFragment && !m.on("fragment-not-inherited") {
			if strings.Contains(urls[i], "#") && !m.on("fragment-overrides") {
				return m.derefError(didURL, "INVALID_DID_URL")
			}
			urls[i] = strings.SplitN(urls[i], "#", 2)[0] + "#" + u.Fragment
		}
	}
	content := strings.Join(urls, "\r\n")
	if content != "" {
		content += "\r\n"
	}
	meta := core.NewDocument()
	if !m.on("no-uri-list-content-type") {
		meta = core.NewDocument(core.M("contentType", core.String("text/uri-list")))
	}
	return core.DereferenceResult{DereferencingMetadata: meta, Content: []byte(content), MediaType: "text/uri-list", ContentMetadata: meta}
}
