package core10

import (
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
// produce terms not defined via @context (§6.3.1), and a consumer SHOULD
// drop them (§6.3.2).
func undefinedTermCases() []core.Case {
	return kit.UndefinedTermCases(kit.UndefinedTermConfig{
		Profile: Name, Version: Version, MediaType: MediaTypeJSONLD, Context: contextURL,
		Producer: k("production-0.5"), Consumer: k("consumption-0.2"),
	})
}

// dereferencedContentType: the media type of the returned contentStream
// SHOULD be expressed in contentType if dereferencing is successful
// (§7.2.2).
func dereferencedContentType() kit.Invariant {
	return kit.Invariant{Statement: k("did-url-dereferencing-metadata.1"), Check: func(o kit.Outcome) (bool, bool, string, string) {
		_, ok := o.Metadata.Get("contentType")
		return o.Function == kit.FnDereference10 && o.Succeeded(), ok, "contentType in the dereferencing metadata of a successful result", o.Summary()
	}}
}
