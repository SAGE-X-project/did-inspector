package did11

import (
	"strings"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// The cases of this file judge recommendations (SHOULD, SHOULD NOT,
// RECOMMENDED): statements of the recommendation level, whose FAIL is
// reported apart from requirement failures. The scenarios of
// resolution.json and dereferencing.json judge the rest: the metadata
// properties a resolver SHOULD include and the accept option a resolver
// SHOULD follow.

// undefinedTermCases: a producer of the JSON-LD representation SHOULD NOT
// produce terms not defined via @context, and a consumer SHOULD drop them
// (DID 1.1 §6.2.3).
func undefinedTermCases() []core.Case {
	return kit.UndefinedTermCases(kit.UndefinedTermConfig{
		Profile: Name, Version: Version, MediaType: MediaType, Context: contextURL,
		Producer: d("json-ld-processors.6"), Consumer: d("json-ld-processors.8"),
	})
}

// errorRecommendations are the recommendations on error objects (DID
// Resolution §11, CID §3.5).
func errorRecommendations() []kit.Invariant {
	return []kit.Invariant{
		kit.ErrorObjectRule(r("errors.1")),
		kit.ErrorMemberRule(r("errors.4"), "title", nil),
		kit.ErrorMemberRule(r("errors.5"), "detail", nil),
		kit.ErrorMemberRule(r("errors.7"), "detail", isError("FEATURE_NOT_SUPPORTED")),
		kit.ErrorMemberRule(c("processing-errors.3"), "title", isError(cidErrors...)),
		kit.ErrorMemberRule(c("processing-errors.4"), "detail", isError(cidErrors...)),
	}
}

// isError returns a filter for error types that name one of the errors,
// with or without a prefix.
func isError(names ...string) func(string) bool {
	return func(code string) bool {
		for _, n := range names {
			if code == n || strings.HasSuffix(code, "#"+n) || strings.HasSuffix(code, "/"+n) {
				return true
			}
		}
		return false
	}
}

// dereferencedContentType: the media type of the returned contentStream
// SHOULD be expressed in contentType if dereferencing is successful (DID
// Resolution §5.2).
func dereferencedContentType() kit.Invariant {
	return kit.Invariant{Statement: r("did-url-dereferencing-metadata.2"), Check: func(o kit.Outcome) (bool, bool, string, string) {
		_, ok := o.Metadata.Get("contentType")
		return o.Succeeded(), ok, "contentType in the dereferencing metadata of a successful result", o.Summary()
	}}
}
