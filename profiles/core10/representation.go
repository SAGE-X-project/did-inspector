package core10

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// jsonDoc is a DID document without @context with one entry of every data
// type of DID Core 1.0 §4. With no @context no JSON-LD processing applies,
// so a consumer that drops terms not defined via @context (§6.3.2) has no
// reason to drop any entry.
var jsonDoc = kit.MustDocument(`{
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{"id": "did:example:123456789abcdefghi#key-1", "type": "JsonWebKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}}],
  "authentication": ["did:example:123456789abcdefghi#key-1"],
  "extString": "text",
  "extInteger": 42,
  "extDouble": 1.5,
  "extBoolean": true,
  "extNull": null,
  "extList": [1, "two", {"three": false}],
  "extMap": {"nested": {"deeper": ["x"]}}
}`)

// ldDoc is a DID document with a layered @context and only core terms.
var ldDoc = kit.MustDocument(`{
  "@context": ["https://www.w3.org/ns/did/v1", "https://did-method-extension.example/v1"],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{"id": "did:example:123456789abcdefghi#key-1", "type": "JsonWebKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}}],
  "authentication": ["did:example:123456789abcdefghi#key-1"]
}`)

func representationCases() []core.Case {
	return []core.Case{consumerJSONCase(), consumerJSONLDCase(), producerJSONCase(), producerJSONLDCase(), producerRequestedJSONLDCase()}
}

func mustBytes(doc core.DocumentJSON) []byte {
	data, err := doc.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return data
}

// merge returns the data model entries followed by the representation-
// specific entries; an adapter may report @context in either.
func merge(doc, entries core.DocumentJSON) core.DocumentJSON {
	out := core.DocumentJSON{Members: append([]core.Member{}, doc.Members...)}
	for _, m := range entries.Members {
		if _, ok := out.Get(m.Name); !ok {
			out.Members = append(out.Members, m)
		}
	}
	return out
}

func consumerJSONCase() core.Case {
	sts := []string{k("production-and-consumption.17"), k("consumption.1"), k("consumption.2")}
	return core.Case{
		ID: Name + "/representation/consumer-keeps-entries", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentConsumer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Consume(s.(core.DocumentConsumer), mustBytes(jsonDoc), MediaTypeJSON, Version)
			merged := merge(got.Doc, got.Info.RepresentationEntries)
			return kit.RunRules("application/did+json document with every data type", got.Err, []kit.Rule{
				{Statements: sts, Check: func() (bool, string, string) { return kit.MembersKept(merged, jsonDoc) }},
			})
		},
	}
}

func consumerJSONLDCase() core.Case {
	entries := []string{k("production-and-consumption.16")}
	model := []string{k("production-and-consumption.17"), k("consumption-0.1")}
	media := []string{k("production-and-consumption.15")}
	sts := kit.Union(entries, model, media)
	return core.Case{
		ID: Name + "/representation/consumer-representation-entries", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentConsumer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Consume(s.(core.DocumentConsumer), mustBytes(ldDoc), MediaTypeJSONLD, Version)
			want, _ := ldDoc.Get("@context")
			return kit.RunRules("application/did+ld+json document with a layered @context", got.Err, []kit.Rule{
				{Statements: entries, Check: func() (bool, string, string) {
					v, ok := got.Info.RepresentationEntries.Get("@context")
					eq, _ := checks.EqualJSON(v, want)
					return ok && eq, "@context " + checks.Compact(want) + " in the representation-specific entries", "entries " + checks.Compact(got.Info.RepresentationEntries.Value())
				}},
				{Statements: model, Check: func() (bool, string, string) { return kit.MembersKept(got.Doc, ldDoc, "@context") }},
				{Statements: media, Partial: "judged by the media type the consumer reports it used", Check: func() (bool, string, string) {
					return checks.MediaTypeEssence(got.Info.MediaType) == MediaTypeJSONLD, "media type " + MediaTypeJSONLD, fmt.Sprintf("media type %q", got.Info.MediaType)
				}},
			})
		},
	}
}

// producerJSONCase produces a document without @context. The producer may
// produce JSON (application/did+json) or JSON-LD, in which case it must
// have added the @context entry (§6.3.1) and say application/did+ld+json.
func producerJSONCase() core.Case {
	entries := []string{k("production-and-consumption.10"), k("production.1"), k("production.2"), k("production.3")}
	media := []string{k("production-and-consumption.11"), k("production.4")}
	sts := kit.Union(entries, media)
	return core.Case{
		ID: Name + "/representation/producer-serializes-entries", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentProducer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Produce(s.(core.DocumentProducer), jsonDoc, Version)
			out, isObject := got.Doc()
			return kit.RunRules("document without @context with every data type", got.Err, []kit.Rule{
				{Statements: entries, Check: func() (bool, string, string) {
					if !isObject {
						return false, "a JSON object with every entry", rootText(got)
					}
					return kit.MembersKept(out, jsonDoc)
				}},
				{Statements: media, Partial: "application/did+ld+json is accepted when the producer added a conforming @context", Check: func() (bool, string, string) {
					ctx, _ := out.Get("@context")
					mt := checks.MediaTypeEssence(got.MediaType)
					ok := mt == MediaTypeJSON || (mt == MediaTypeJSONLD && kit.ContextFirst(ctx, contextURL))
					return ok, "media type " + MediaTypeJSON, fmt.Sprintf("media type %q, @context %s", got.MediaType, checks.Compact(ctx))
				}},
			})
		},
	}
}

// producerJSONLDCase produces a document with @context. When the producer
// says it produced JSON-LD, the JSON-LD production rules apply; a producer
// that produced the JSON representation instead (which serializes the
// @context entry too, §6.1) makes them NOT_APPLICABLE.
func producerJSONLDCase() core.Case {
	sts := []string{k("production-0.1"), k("production-0.2"), k("production-0.3")}
	return core.Case{
		ID: Name + "/representation/producer-json-ld", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentProducer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			p := s.(core.DocumentProducer)
			got := kit.Produce(p, ldDoc, Version)
			input := "document with a layered @context"
			mt := checks.MediaTypeEssence(got.MediaType)
			if got.Err == nil && mt != MediaTypeJSONLD {
				var r kit.Recorder
				detail := fmt.Sprintf("the producer produced %q, not the JSON-LD representation", got.MediaType)
				if mt != MediaTypeJSON {
					r.Judge(sts, input, false, "media type "+MediaTypeJSONLD+" or "+MediaTypeJSON, fmt.Sprintf("media type %q", got.MediaType), "")
					return r.Observations()
				}
				r.All(sts, core.NotApplicable, input, detail)
				return r.Observations()
			}
			out, isObject := got.Doc()
			ctx, hasCtx := out.Get("@context")
			want, _ := ldDoc.Get("@context")
			return kit.RunRules(input, got.Err, []kit.Rule{
				{Statements: sts[:1], Check: func() (bool, string, string) {
					if !isObject {
						return false, "a JSON object", rootText(got)
					}
					return kit.MembersKept(out, ldDoc)
				}},
				{Statements: sts[1:2], Check: func() (bool, string, string) {
					eq, _ := checks.EqualJSON(ctx, want)
					return hasCtx && eq, "@context " + checks.Compact(want), "@context " + checks.Compact(ctx)
				}},
				{Statements: sts[2:], Check: func() (bool, string, string) {
					return kit.ContextFirst(ctx, contextURL), "@context starting with " + contextURL, "@context " + checks.Compact(ctx)
				}},
			})
		},
	}
}

// producerRequestedJSONLDCase asks the producer for the JSON-LD
// representation of a document with @context, so that the representation
// is not the producer's choice, and checks the media type it specifies
// (§6.3.1).
func producerRequestedJSONLDCase() core.Case {
	sts := []string{k("production-0.6")}
	return core.Case{
		ID: Name + "/representation/producer-requested-json-ld", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapRepresentationProducer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			_, mt, err := s.(core.RepresentationProducer).ProduceRepresentation(ldDoc, Version, MediaTypeJSONLD)
			return kit.RunRules("document with a layered @context, "+MediaTypeJSONLD+" requested", err, []kit.Rule{
				{Statements: sts, Check: func() (bool, string, string) {
					return checks.MediaTypeEssence(mt) == MediaTypeJSONLD, "media type " + MediaTypeJSONLD, fmt.Sprintf("media type %q", mt)
				}},
			})
		},
	}
}

func rootText(p kit.Produced) string {
	if p.ParseErr != nil {
		return "output is not JSON: " + p.ParseErr.Error()
	}
	return "root " + p.Root.Kind.String()
}
