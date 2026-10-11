package did11

import (
	"slices"
	"strings"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// Error type URLs (DID Resolution §11; CID §3.5).
const (
	didErrorPrefix = "https://www.w3.org/ns/did#"
	cidErrorPrefix = "https://w3id.org/security#"
)

// didErrors are the errors DID Resolution §11 lists without a URL of their
// own; their type is the name prefixed with didErrorPrefix.
var didErrors = []string{
	"INVALID_DID", "INVALID_DID_DOCUMENT", "NOT_FOUND", "REPRESENTATION_NOT_SUPPORTED", "INVALID_DID_URL",
	"METHOD_NOT_SUPPORTED", "INVALID_OPTIONS", "INTERNAL_ERROR", "FEATURE_NOT_SUPPORTED",
}

// cidErrors are the processing errors of CID §3.5, whose type is the name
// prefixed with cidErrorPrefix.
var cidErrors = []string{
	"INVALID_VERIFICATION_METHOD_URL", "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID", "INVALID_CONTROLLED_IDENTIFIER_DOCUMENT",
	"INVALID_VERIFICATION_METHOD", "INVALID_RELATIONSHIP_FOR_VERIFICATION_METHOD",
}

// representationMediaTypes are the media types a contentType of DID
// resolution metadata may name. DID Resolution §4.2 says "the Media Type of
// the conformant representations" and refers to DID v1.0 for them, so the
// DID 1.0 media types are accepted as well as application/did.
var representationMediaTypes = []string{MediaType, "application/did+json", "application/did+ld+json"}

// resolutionInvariants are the rules every result of resolve must satisfy.
func resolutionInvariants(reg *fixtures.Registry) []kit.Invariant {
	return append([]kit.Invariant{
		failedHasNoContent(r("resolving.8")),
		failedHasEmptyContentMetadata(r("resolving.10")),
		kit.MemberRule(r("did-resolution-metadata.3"), "", kit.PickMetadata, "contentType",
			"an ASCII string naming a DID document media type", func(v core.Value) bool {
				return kit.IsASCIIString(v) && slices.Contains(representationMediaTypes, checks.MediaTypeEssence(v.Str))
			}),
		kit.MemberRule(r("did-resolution-metadata.7"), "", kit.PickMetadata, "proof", "a set of maps", isProofSet),
	}, slices.Concat(documentMetadataInvariants(reg), errorInvariants(), errorRecommendations())...)
}

// dereferencingInvariants are the rules every result of dereference must
// satisfy.
func dereferencingInvariants(reg *fixtures.Registry) []kit.Invariant {
	return append([]kit.Invariant{
		failedHasNoContent(r("dereferencing.10")),
		failedHasEmptyContentMetadata(r("dereferencing.13")),
		kit.MemberRule(r("did-url-dereferencing-metadata.3"), "", kit.PickMetadata, "contentType", "an ASCII media type", func(v core.Value) bool {
			return kit.IsASCIIString(v) && checks.IsMediaType(v.Str)
		}),
		kit.MemberRule(r("did-url-dereferencing-metadata.7"), "", kit.PickMetadata, "proof", "a set of maps", isProofSet),
		dereferencedContentType(),
	}, slices.Concat(documentMetadataInvariants(reg), errorInvariants(), errorRecommendations())...)
}

func isProofSet(v core.Value) bool { return kit.IsSetOf(v, kit.IsMap) }

func failedHasNoContent(st string) kit.Invariant {
	return kit.Invariant{Statement: st, Check: func(o kit.Outcome) (bool, bool, string, string) {
		return o.Failed(), !o.HasContent(), "no content when the result has an error", o.Summary()
	}}
}

func failedHasEmptyContentMetadata(st string) kit.Invariant {
	return kit.Invariant{Statement: st, Check: func(o kit.Outcome) (bool, bool, string, string) {
		return o.Failed(), o.ContentMetadata.Len() == 0, "an empty metadata structure when the result has an error", checks.Compact(o.ContentMetadata.Value())
	}}
}

// documentMetadataInvariants are the formats of DID document metadata
// properties (DID Resolution §4.3) wherever they appear.
func documentMetadataInvariants(reg *fixtures.Registry) []kit.Invariant {
	cm := kit.PickContentMetadata
	return []kit.Invariant{
		kit.MemberRule(r("did-document-metadata.3"), "", cm, "created", "a datetime of §3.1", kit.IsDatetime),
		kit.MemberRule(r("did-document-metadata.5"), "", cm, "updated", "a datetime of §3.1", kit.IsDatetime),
		kit.MemberRule(r("did-document-metadata.9"), "", cm, "nextUpdate", "a datetime of §3.1", kit.IsDatetime),
		kit.MemberRule(r("did-document-metadata.11"), "", cm, "versionId", "an ASCII string", kit.IsASCIIString),
		kit.MemberRule(r("did-document-metadata.13"), "", cm, "nextVersionId", "an ASCII string", kit.IsASCIIString),
		kit.MemberRule(r("did-document-metadata.15"), "", cm, "equivalentId", "a set of DIDs", func(v core.Value) bool {
			return kit.IsSetOf(v, kit.IsDIDString)
		}),
		kit.MethodRule(r("did-document-metadata.16"), "equivalentId", true),
		kit.MemberRule(r("did-document-metadata.20"), "", cm, "canonicalId", "a DID", kit.IsDIDString),
		kit.MethodRule(r("did-document-metadata.21"), "canonicalId", false),
		kit.MemberRule(r("did-document-metadata.24"), "", cm, "proof", "a set of maps", isProofSet),
		deactivatedRule(r("did-document-metadata.7"), reg),
	}
}

// deactivatedRule: a DID that has not been deactivated has no deactivated
// property, or one with the value false.
func deactivatedRule(st string, reg *fixtures.Registry) kit.Invariant {
	return kit.Invariant{Statement: st, Check: func(o kit.Outcome) (bool, bool, string, string) {
		v, ok := o.ContentMetadata.Get("deactivated")
		did := strings.SplitN(strings.SplitN(o.Input, "#", 2)[0], "?", 2)[0]
		e, known := reg.Entries[did]
		if !ok || !known || e.Deactivated {
			return false, false, "", ""
		}
		return true, v.Kind == core.KindBool && !v.Bool, "deactivated false (the DID is not deactivated)", "deactivated " + checks.Compact(v)
	}}
}

// errorInvariants are the rules for error objects (DID Resolution §11; CID
// §3.5).
func errorInvariants() []kit.Invariant {
	return []kit.Invariant{
		{Statement: r("errors.2"), Partial: "applies to error objects (RFC 9457); an error that is not an object is not judged here", Check: func(o kit.Outcome) (bool, bool, string, string) {
			v, ok := o.ErrorValue()
			if !ok || v.Kind != core.KindObject {
				return false, false, "", ""
			}
			t, _ := v.Get("type")
			return true, t.Kind == core.KindString && checks.IsAbsoluteURI(t.Str), "an error type that is a URL", "error " + checks.Compact(v)
		}},
		{Statement: r("errors.3"), Check: func(o kit.Outcome) (bool, bool, string, string) {
			return prefixRule(o, didErrors, didErrorPrefix)
		}},
		{Statement: c("processing-errors.2"), Check: func(o kit.Outcome) (bool, bool, string, string) {
			return prefixRule(o, cidErrors, cidErrorPrefix)
		}},
	}
}

// prefixRule judges an error type that names one of the errors: it must be
// the name prefixed with prefix.
func prefixRule(o kit.Outcome, names []string, prefix string) (bool, bool, string, string) {
	code := o.ErrorCode()
	if code == "" {
		return false, false, "", ""
	}
	for _, name := range names {
		if code == name || strings.HasSuffix(code, "#"+name) || strings.HasSuffix(code, "/"+name) {
			return true, code == prefix+name, "error type " + prefix + name, "error type " + code
		}
	}
	return false, false, "", ""
}
