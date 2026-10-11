package did11

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
)

const (
	nsDID = "https://www.w3.org/ns/did#"
	nsSec = "https://w3id.org/security#"
)

var resolutionOptions = []string{"accept", "expandRelativeUrls", "versionId", "versionTime", "noCache"}

// errResult is the error result of DID Resolution §4.4, bent by the error
// faults.
func (m *mock) errResult(did, name string) core.ResolutionResult {
	t := nsDID + name
	switch {
	case m.on("error-type-bare"):
		t = name
	case m.on("error-type-not-url"):
		t = strings.ToLower(strings.ReplaceAll(name, "_", " "))
	}
	if name == "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD" || name == "INVALID_VERIFICATION_METHOD" {
		t = nsSec + name
		if m.on("cid-error-prefix-wrong") {
			t = nsDID + name
		}
	}
	members := []core.Member{core.M("type", core.String(t))}
	if !m.on("error-no-title") {
		members = append(members, core.M("title", core.String(name)))
	}
	if !m.on("error-no-detail") {
		members = append(members, core.M("detail", core.String("the mock could not complete the request: "+name)))
	}
	e := core.Object(members...)
	if m.on("error-string") {
		e = core.String(t)
	}
	res := core.ResolutionResult{
		ResolutionMetadata: core.NewDocument(core.M("error", e)),
		DocumentMetadata:   core.NewDocument(),
	}
	if m.on("error-empty-metadata") {
		res.ResolutionMetadata = core.NewDocument()
	}
	if m.on("error-with-document") {
		doc := core.NewDocument(core.M("id", core.String(did)))
		res.Document = &doc
	}
	if m.on("error-with-metadata") {
		res.DocumentMetadata = core.NewDocument(core.M("created", core.String("2020-01-01T00:00:00Z")))
	}
	return res
}

func isAccept(s string) bool {
	for _, part := range strings.Split(s, ",") {
		if !checks.IsMediaType(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func optionString(opts map[string]any, name string) string {
	s, _ := opts[name].(string)
	return s
}

// invalidOption reports whether a known option has an invalid value.
func (m *mock) invalidOption(opts map[string]any) bool {
	if m.on("accept-invalid-options") {
		return false
	}
	for k, v := range opts {
		switch k {
		case "expandRelativeUrls", "noCache":
			if _, ok := v.(bool); !ok {
				return true
			}
		case "versionTime":
			if s, ok := v.(string); !ok || checks.CheckDatetime(s) != nil {
				return true
			}
		case "accept":
			if s, ok := v.(string); !ok || !isAccept(s) || m.on("reject-accept") {
				return true
			}
		case "versionId":
			if _, ok := v.(string); !ok {
				return true
			}
		}
	}
	return false
}

func (m *mock) Resolve(_ context.Context, did string, opts map[string]any) (core.ResolutionResult, error) {
	if !checks.IsDID(did) {
		return m.errResult(did, "INVALID_DID"), nil
	}
	if p, _ := checks.ParseDID(did); p.Method != fixtures.Method {
		return m.errResult(did, "METHOD_NOT_SUPPORTED"), nil
	}
	for k := range opts {
		if !slices.Contains(resolutionOptions, k) && !m.on("ignore-unknown-options") {
			return m.errResult(did, "FEATURE_NOT_SUPPORTED"), nil
		}
	}
	if m.invalidOption(opts) {
		return m.errResult(did, "INVALID_OPTIONS"), nil
	}
	if b, _ := opts["noCache"].(bool); b && m.on("no-cache-error") {
		return m.errResult(did, "INVALID_OPTIONS"), nil
	}
	req := fixtures.Request{DID: did}
	if !m.on("ignore-version") {
		req.VersionID, req.VersionTime = optionString(opts, "versionId"), optionString(opts, "versionTime")
	}
	if m.on("wrong-current-version") && req.VersionID == "" && req.VersionTime == "" {
		req.VersionID = "1"
	}
	rec, err := m.reg.Read(req)
	var injected *fixtures.InjectedError
	switch {
	case errors.As(err, &injected) && !m.on("failure-not-internal"):
		return m.errResult(did, "INTERNAL_ERROR"), nil
	case errors.Is(err, fixtures.ErrInvalidVersionTime):
		return m.errResult(did, "INVALID_OPTIONS"), nil
	case err != nil:
		return m.errResult(did, "NOT_FOUND"), nil
	}
	meta := m.documentMetadata(did, rec)
	if rec.Deactivated {
		return m.deactivated(did, meta), nil
	}
	doc, ok := m.parseStored(did, rec)
	if !ok {
		return m.errResult(did, "INVALID_DID_DOCUMENT"), nil
	}
	if b, _ := opts["expandRelativeUrls"].(bool); b && !m.on("no-expand") {
		doc = expand(did, doc)
	}
	res := m.success(did, doc, meta)
	if _, asked := opts["accept"]; asked && m.on("accept-ignored") {
		res.ResolutionMetadata = core.NewDocument(core.M("contentType", core.String("application/did+ld+json")))
	}
	return res, nil
}

func (m *mock) deactivated(did string, meta core.DocumentJSON) core.ResolutionResult {
	if !m.on("deactivated-no-flag") {
		meta.Members = append(meta.Members, core.M("deactivated", core.Bool(true)))
	}
	res := core.ResolutionResult{ResolutionMetadata: core.NewDocument(), DocumentMetadata: meta}
	if m.on("deactivated-as-error") {
		res.ResolutionMetadata = core.NewDocument(core.M("error", core.Object(core.M("type", core.String(nsDID+"NOT_FOUND")))))
	}
	if m.on("deactivated-returns-document") {
		doc := core.NewDocument(core.M("id", core.String(did)))
		res.Document = &doc
	}
	return res
}

func (m *mock) success(did string, doc core.DocumentJSON, meta core.DocumentJSON) core.ResolutionResult {
	resMeta := core.NewDocument()
	switch {
	case m.on("content-type-wrong"):
		resMeta.Members = append(resMeta.Members, core.M("contentType", core.String("application/json")))
	case !m.on("no-content-type"):
		resMeta.Members = append(resMeta.Members, core.M("contentType", core.String(MediaType)))
	}
	if did == "did:example:equivalent" {
		proof := core.Array(core.Object(core.M("type", core.String("ResolverProof"))))
		if m.on("proof-not-set") {
			proof = core.Object(core.M("type", core.String("ResolverProof")))
		}
		resMeta.Members = append(resMeta.Members, core.M("proof", proof))
	}
	raw, _ := doc.MarshalJSON()
	return core.ResolutionResult{ResolutionMetadata: resMeta, Document: &doc, DocumentMetadata: meta, Raw: raw, MediaType: MediaType}
}

// parseStored consumes the stored representation as a resolver must: the
// media type decides, the bytes must be a JSON object, and its id must be
// the DID.
func (m *mock) parseStored(did string, rec fixtures.Record) (core.DocumentJSON, bool) {
	doc, err := core.ParseDocumentJSON(rec.Bytes)
	if m.on("accept-malformed") {
		if err != nil {
			doc = core.NewDocument(core.M("id", core.String(did)))
		}
		return doc, true
	}
	if err != nil || rec.MediaType != MediaType {
		return core.DocumentJSON{}, false
	}
	if id, _ := doc.Get("id"); id.Str != did {
		return core.DocumentJSON{}, false
	}
	if m.on("reject-relative") && strings.Contains(string(rec.Bytes), `"#`) {
		return core.DocumentJSON{}, false
	}
	return doc, true
}

// documentMetadata returns the stored metadata, bent by the metadata
// faults.
func (m *mock) documentMetadata(did string, rec fixtures.Record) core.DocumentJSON {
	if m.on("drop-metadata") {
		return core.NewDocument()
	}
	meta, _ := core.ParseDocumentJSON(rec.Metadata)
	var out core.DocumentJSON
	for _, mem := range meta.Members {
		v := mem.Value
		switch {
		case m.on("metadata-fraction") && slices.Contains([]string{"created", "updated", "nextUpdate"}, mem.Name):
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
			v = core.Number("42")
		case m.on("proof-not-set") && mem.Name == "proof":
			v = v.Array[0]
		}
		out.Members = append(out.Members, core.M(mem.Name, v))
	}
	if m.on("deactivated-flag-on-active") && did != "did:example:deactivated" {
		out.Members = append(out.Members, core.M("deactivated", core.String("no")))
	}
	return out
}

// expand replaces relative DID URLs with absolute ones (DID Resolution
// §4.4 step 7): ids of maps and string items of verification relationships.
func expand(did string, doc core.DocumentJSON) core.DocumentJSON {
	var out core.DocumentJSON
	for _, mem := range doc.Members {
		out.Members = append(out.Members, core.M(mem.Name, expandValue(did, mem.Name, mem.Value)))
	}
	return out
}

func expandValue(did, name string, v core.Value) core.Value {
	switch v.Kind {
	case core.KindArray:
		items := make([]core.Value, len(v.Array))
		for i, x := range v.Array {
			items[i] = expandValue(did, name, x)
		}
		return core.Array(items...)
	case core.KindObject:
		members := make([]core.Member, len(v.Object))
		for i, mem := range v.Object {
			members[i] = mem
			if mem.Name == "id" && strings.HasPrefix(mem.Value.Str, "#") {
				members[i] = core.M("id", core.String(did+mem.Value.Str))
			}
		}
		return core.Object(members...)
	case core.KindString:
		if name != "service" && strings.HasPrefix(v.Str, "#") {
			return core.String(did + v.Str)
		}
	}
	return v
}

// relativeResolve resolves a reference against a base URI by RFC 3986 §5.
func relativeResolve(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}
