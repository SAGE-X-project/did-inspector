package kit

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
)

// UndefinedTerm is a member name that no JSON-LD context of the inspected
// specifications defines. The base contexts of DID Core 1.0
// (https://www.w3.org/ns/did/v1) and DID 1.1 (https://www.w3.org/ns/did/v1.1,
// SHA-256 ea216ecc1cb02cd39b693dba2250141e270ba0bf95890be107dd9a9e8e43de85 as
// pinned by DID 1.1 §6.2.4) have no @vocab, so with only the base context
// in @context a member of this name is a term not defined via the
// @context.
const UndefinedTerm = "inspectorUndefinedTerm"

// UndefinedTermConfig names what the undefined-term cases of a profile
// use.
type UndefinedTermConfig struct {
	Profile   string
	Version   string
	MediaType string
	// Context is the base context URL of the version.
	Context string
	// Producer is the statement that a producer of a JSON-LD
	// representation SHOULD NOT produce terms not defined via @context;
	// Consumer the statement that a consumer SHOULD drop them.
	Producer, Consumer string
}

// UndefinedTermDocument returns a DID document with only the base context
// and one member that the context does not define.
func UndefinedTermDocument(contextURL string) core.DocumentJSON {
	return core.NewDocument(
		core.M("@context", core.String(contextURL)),
		core.M("id", core.String("did:example:123456789abcdefghi")),
		core.M(UndefinedTerm, core.String("a value no context defines")),
	)
}

// UndefinedTermCases returns two recommendation cases: a producer given a
// document with an undefined term does not produce it (it drops the term or
// declines to produce), and a consumer drops it.
func UndefinedTermCases(cfg UndefinedTermConfig) []core.Case {
	doc := UndefinedTermDocument(cfg.Context)
	input := fmt.Sprintf("JSON-LD document with @context %s and the undefined term %s", cfg.Context, UndefinedTerm)
	return []core.Case{
		{
			ID: cfg.Profile + "/representation/producer-undefined-terms", Profile: cfg.Profile, Statements: []string{cfg.Producer},
			Needs: []core.Capability{core.CapDocumentProducer},
			Run: func(_ context.Context, s core.Subject) []core.Observation {
				got := Produce(s.(core.DocumentProducer), doc, cfg.Version)
				var r Recorder
				exp := "no member " + UndefinedTerm + " in the produced representation, or no production"
				if got.Err != nil {
					r.Judge([]string{cfg.Producer}, input, true, exp, "", "the producer declined to produce the document: "+got.Err.Error())
					return r.Observations()
				}
				out, isObject := got.Doc()
				_, has := out.Get(UndefinedTerm)
				r.Judge([]string{cfg.Producer}, input, isObject && !has, exp, "produced "+clip(got.Data), "")
				return r.Observations()
			},
		},
		{
			ID: cfg.Profile + "/representation/consumer-undefined-terms", Profile: cfg.Profile, Statements: []string{cfg.Consumer},
			Needs: []core.Capability{core.CapDocumentConsumer},
			Run: func(_ context.Context, s core.Subject) []core.Observation {
				data, _ := doc.MarshalJSON()
				got := Consume(s.(core.DocumentConsumer), data, cfg.MediaType, cfg.Version)
				return RunRules(input, got.Err, []Rule{{Statements: []string{cfg.Consumer}, Check: func() (bool, string, string) {
					_, inModel := got.Doc.Get(UndefinedTerm)
					_, inEntries := got.Info.RepresentationEntries.Get(UndefinedTerm)
					return !inModel && !inEntries, "the consumed document without " + UndefinedTerm,
						fmt.Sprintf("data model %s, representation-specific entries %s", checks.Compact(got.Doc.Value()), checks.Compact(got.Info.RepresentationEntries.Value()))
				}}})
			},
		},
	}
}

// ErrorObjectRule: an error is an RFC 9457 problem details object, a map
// with a string type member (DID Resolution §11, "Implementers SHOULD use
// [RFC9457] to encode the error data structure").
func ErrorObjectRule(statement string) Invariant {
	return Invariant{Statement: statement, Partial: "judged by the form of the error property: a map with a string type, as RFC 9457 §3.1 defines it",
		Check: func(o Outcome) (bool, bool, string, string) {
			v, ok := o.ErrorValue()
			if !ok {
				return false, false, "", ""
			}
			t, _ := v.Get("type")
			return true, v.Kind == core.KindObject && t.Kind == core.KindString, "an RFC 9457 problem details object", "error " + checks.Compact(v)
		}}
}

// ErrorMemberRule: an error object whose type the filter accepts (any
// type when filter is nil) has the named member with a non-empty string
// value. It judges presence only: whether the text is short, specific or
// longer, as the statements say, is for a human to read.
func ErrorMemberRule(statement, member string, filter func(code string) bool) Invariant {
	return Invariant{Statement: statement, Partial: "judged by the presence of a non-empty string; its wording is not judged",
		Check: func(o Outcome) (bool, bool, string, string) {
			v, ok := o.ErrorValue()
			if !ok || v.Kind != core.KindObject || (filter != nil && !filter(o.ErrorCode())) {
				return false, false, "", ""
			}
			m, _ := v.Get(member)
			return true, m.Kind == core.KindString && m.Str != "", "an error with a non-empty " + member, "error " + checks.Compact(v)
		}}
}
