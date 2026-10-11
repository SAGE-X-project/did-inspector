package core10

import (
	"slices"
	"strconv"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// representationMediaTypes are the media types of the conformant
// representations of DID Core 1.0.
var representationMediaTypes = []string{MediaTypeJSON, MediaTypeJSONLD}

// resolutionInvariants are the rules every result of resolve,
// resolveRepresentation and dereference must satisfy (DID Core 1.0 §7.1,
// §7.3); the resolution scenarios include a dereference probe.
func resolutionInvariants(reg *fixtures.Registry) []kit.Invariant {
	return append([]kit.Invariant{
		failed(k("did-resolution.8"), kit.FnResolve10, "no didDocument", func(o kit.Outcome) bool { return o.Document == nil }),
		failed(k("did-resolution.10"), kit.FnResolveRepresentation10, "an empty didDocumentStream", func(o kit.Outcome) bool { return len(o.Stream) == 0 }),
		failed(k("did-resolution.12"), "", "an empty didDocumentMetadata", func(o kit.Outcome) bool { return o.ContentMetadata.Len() == 0 }),
		{Statement: k("did-resolution-metadata.2"), Check: func(o kit.Outcome) (bool, bool, string, string) {
			v, ok := o.Metadata.Get("contentType")
			return o.Function == kit.FnResolve10, !ok, "no contentType after resolve", "contentType " + checks.Compact(v)
		}},
		{Statement: k("did-resolution-metadata.1"), Check: func(o kit.Outcome) (bool, bool, string, string) {
			_, ok := o.Metadata.Get("contentType")
			return o.Function == kit.FnResolveRepresentation10 && o.Succeeded(), ok, "contentType after a successful resolveRepresentation", o.Summary()
		}},
		kit.MemberRule(k("did-resolution-metadata.3"), "", kit.PickMetadata, "contentType", "an ASCII string naming a DID Core 1.0 media type", func(v core.Value) bool {
			return kit.IsASCIIString(v) && slices.Contains(representationMediaTypes, checks.MediaTypeEssence(v.Str))
		}),
		keywordRule(k("did-resolution-metadata.6"), false),
	}, append(documentMetadataInvariants(reg), metadataStructureInvariants()...)...)
}

// dereferencingInvariants are the rules every result of dereference must
// satisfy (DID Core 1.0 §7.2, §7.3).
func dereferencingInvariants(reg *fixtures.Registry) []kit.Invariant {
	return append([]kit.Invariant{
		failed(k("did-url-dereferencing.8"), "", "an empty contentStream", func(o kit.Outcome) bool { return len(o.Stream) == 0 }),
		failed(k("did-url-dereferencing.11"), "", "an empty contentMetadata", func(o kit.Outcome) bool { return o.ContentMetadata.Len() == 0 }),
		kit.MemberRule(k("did-url-dereferencing-metadata.2"), "", kit.PickMetadata, "contentType", "an ASCII string", kit.IsASCIIString),
		keywordRule(k("did-url-dereferencing-metadata.4"), true),
	}, append(documentMetadataInvariants(reg), metadataStructureInvariants()...)...)
}

// failed returns an invariant on unsuccessful results of a function (any
// function when fn is empty).
func failed(st, fn, expected string, ok func(kit.Outcome) bool) kit.Invariant {
	return kit.Invariant{Statement: st, Check: func(o kit.Outcome) (bool, bool, string, string) {
		applies := o.Failed() && (fn == "" || o.Function == fn)
		return applies, ok(o), expected + " when the result has an error", o.Summary()
	}}
}

// keywordRule: an error is a single keyword ASCII string (DID Core 1.0
// §7.1.2, §7.2.2).
func keywordRule(st string, deref bool) kit.Invariant {
	return kit.Invariant{Statement: st, Check: func(o kit.Outcome) (bool, bool, string, string) {
		v, ok := o.ErrorValue()
		isDeref := o.Function == kit.FnDereference10
		if !ok || isDeref != deref {
			return false, false, "", ""
		}
		return true, v.Kind == core.KindString && checks.IsKeyword(v.Str), "error: a single keyword ASCII string", "error " + checks.Compact(v)
	}}
}

// documentMetadataInvariants are the formats of DID document metadata
// properties (DID Core 1.0 §7.1.3) wherever they appear.
func documentMetadataInvariants(reg *fixtures.Registry) []kit.Invariant {
	cm := kit.PickContentMetadata
	const dt = "an XML datetime normalized to UTC without sub-second precision"
	return []kit.Invariant{
		kit.MemberRule(k("did-document-metadata.3"), "", cm, "created", dt, kit.IsDatetime),
		kit.MemberRule(k("did-document-metadata.5"), "", cm, "updated", dt, kit.IsDatetime),
		kit.MemberRule(k("did-document-metadata.9"), "", cm, "nextUpdate", dt, kit.IsDatetime),
		kit.MemberRule(k("did-document-metadata.11"), "", cm, "versionId", "an ASCII string", kit.IsASCIIString),
		kit.MemberRule(k("did-document-metadata.13"), "", cm, "nextVersionId", "an ASCII string", kit.IsASCIIString),
		kit.MemberRule(k("did-document-metadata.15"), "", cm, "equivalentId", "a set of DIDs", func(v core.Value) bool {
			return kit.IsSetOf(v, kit.IsDIDString)
		}),
		kit.MethodRule(k("did-document-metadata.16"), "equivalentId", true),
		kit.MemberRule(k("did-document-metadata.20"), "", cm, "canonicalId", "a DID", kit.IsDIDString),
		kit.MethodRule(k("did-document-metadata.21"), "canonicalId", false),
		{Statement: k("did-document-metadata.7"), Check: func(o kit.Outcome) (bool, bool, string, string) {
			v, ok := o.ContentMetadata.Get("deactivated")
			did := strings.SplitN(strings.SplitN(o.Input, "#", 2)[0], "?", 2)[0]
			e, known := reg.Entries[did]
			if !ok || !known || e.Deactivated {
				return false, false, "", ""
			}
			return true, v.Kind == core.KindBool && !v.Bool, "deactivated false (the DID is not deactivated)", "deactivated " + checks.Compact(v)
		}},
	}
}

// metadataStructureInvariants: metadata values are strings, maps, lists,
// sets, booleans or null, at every depth (DID Core 1.0 §7.3). DID Core 1.0
// does not list numbers; DID Resolution later does.
func metadataStructureInvariants() []kit.Invariant {
	return []kit.Invariant{
		structureRule(k("metadata-structure.3"), false),
		structureRule(k("metadata-structure.4"), true),
	}
}

func structureRule(st string, nested bool) kit.Invariant {
	return kit.Invariant{Statement: st, Check: func(o kit.Outcome) (bool, bool, string, string) {
		for _, d := range []core.DocumentJSON{o.Metadata, o.ContentMetadata} {
			for _, m := range d.Members {
				path, found := m.Name, m.Value.Kind == core.KindNumber
				if nested {
					path, found = numberWithin(m.Value, m.Name)
				}
				if found {
					return true, false, "metadata values that are strings, maps, lists, sets, booleans or null", "a number at " + path
				}
			}
		}
		return true, true, "", ""
	}}
}

// numberWithin returns the path of a number within a list or map value.
func numberWithin(v core.Value, path string) (string, bool) {
	var items []core.Member
	for i, x := range v.Array {
		items = append(items, core.M(strconv.Itoa(i), x))
	}
	items = append(items, v.Object...)
	for _, m := range items {
		p := path + "/" + m.Name
		if m.Value.Kind == core.KindNumber {
			return p, true
		}
		if p, ok := numberWithin(m.Value, p); ok {
			return p, true
		}
	}
	return "", false
}
