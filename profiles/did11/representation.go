package did11

import (
	"context"
	"fmt"

	"github.com/sage-x-project/did-inspector/checks"
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
)

// contextURL is the base context of DID 1.1 (DID 1.1 §6.2.3).
const contextURL = "https://www.w3.org/ns/did/v1.1"

// jsonDoc is a DID document without @context, so that no JSON-LD
// processing applies: it carries one entry of every data type of DID 1.1
// §4 and both forms of verification material. A consumer that processes
// JSON-LD SHOULD drop terms not defined via @context (DID 1.1 §6.2.3); this
// document has no @context, so every entry must survive.
var jsonDoc = kit.MustDocument(`{
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [
    {"id": "did:example:123456789abcdefghi#key-1", "type": "Multikey", "controller": "did:example:123456789abcdefghi",
     "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"},
    {"id": "did:example:123456789abcdefghi#key-2", "type": "JsonWebKey", "controller": "did:example:123456789abcdefghi",
     "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"}}
  ],
  "authentication": ["did:example:123456789abcdefghi#key-1"],
  "service": [{"id": "did:example:123456789abcdefghi#svc", "type": "ExampleService", "serviceEndpoint": "https://example.com/svc"}],
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
  "@context": ["https://www.w3.org/ns/did/v1.1", "https://did-method-extension.example/v1"],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{"id": "did:example:123456789abcdefghi#key-1", "type": "Multikey",
    "controller": "did:example:123456789abcdefghi", "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"}],
  "authentication": ["did:example:123456789abcdefghi#key-1"]
}`)

const keyMaterialPartial = "judged on the external representation of the key material only; internal conversions are not observable"

func representationCases() []core.Case {
	return []core.Case{
		consumerJSONCase(),
		consumerRepresentationEntriesCase(),
		producerJSONCase(),
		producerJSONLDCase(),
	}
}

func mustBytes(doc core.DocumentJSON) []byte {
	data, err := doc.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return data
}

// consumerJSONCase consumes a representation with an entry of every data
// type and checks that each entry reaches the data model unchanged.
func consumerJSONCase() core.Case {
	sts := []string{d("production-and-consumption.17"), d("consumption.1"), d("consumption.2"), c("verification-material.3")}
	return core.Case{
		ID: Name + "/representation/consumer-keeps-entries", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentConsumer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Consume(s.(core.DocumentConsumer), mustBytes(jsonDoc), MediaType, Version)
			merged := merge(got.Doc, got.Info.RepresentationEntries)
			return kit.RunRules("JSON document with every data type", got.Err, []kit.Rule{
				{Statements: sts[:3], Check: func() (bool, string, string) { return kit.MembersKept(merged, jsonDoc) }},
				{Statements: sts[3:], Partial: keyMaterialPartial, Check: func() (bool, string, string) {
					return sameMember(merged, jsonDoc, "verificationMethod")
				}},
			})
		},
	}
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

// consumerRepresentationEntriesCase consumes a representation with
// @context and checks that the consumer reports it as a
// representation-specific entry and keeps the other entries in the data
// model.
func consumerRepresentationEntriesCase() core.Case {
	sts := []string{d("production-and-consumption.16"), d("production-and-consumption.17"), d("production-and-consumption.15")}
	return core.Case{
		ID: Name + "/representation/consumer-representation-entries", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentConsumer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Consume(s.(core.DocumentConsumer), mustBytes(ldDoc), MediaType, Version)
			want, _ := ldDoc.Get("@context")
			return kit.RunRules("JSON-LD document with a layered @context", got.Err, []kit.Rule{
				{Statements: sts[:1], Check: func() (bool, string, string) {
					v, ok := got.Info.RepresentationEntries.Get("@context")
					eq, _ := checks.EqualJSON(v, want)
					return ok && eq, "@context " + checks.Compact(want) + " in the representation-specific entries", "entries " + checks.Compact(got.Info.RepresentationEntries.Value())
				}},
				{Statements: sts[1:2], Check: func() (bool, string, string) { return kit.MembersKept(got.Doc, ldDoc, "@context") }},
				{Statements: sts[2:], Partial: "judged by the media type the consumer reports it used", Check: func() (bool, string, string) {
					return checks.MediaTypeEssence(got.Info.MediaType) == MediaType, "media type " + MediaType, fmt.Sprintf("media type %q", got.Info.MediaType)
				}},
			})
		},
	}
}

// producerJSONCase produces a document with an entry of every data type
// and checks the serialization and the media type.
func producerJSONCase() core.Case {
	entries := []string{d("production-and-consumption.10"), d("production.1"), d("production.2"), d("production.3")}
	media := []string{d("production-and-consumption.11"), d("production.4")}
	key := []string{c("verification-material.3")}
	sts := kit.Union(entries, media, key)
	return core.Case{
		ID: Name + "/representation/producer-serializes-entries", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentProducer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Produce(s.(core.DocumentProducer), jsonDoc, Version)
			out, isObject := got.Doc()
			return kit.RunRules("JSON document with every data type", got.Err, []kit.Rule{
				{Statements: entries, Check: func() (bool, string, string) {
					if !isObject {
						return false, "a JSON object with every entry", rootText(got)
					}
					return kit.MembersKept(out, jsonDoc)
				}},
				{Statements: media, Check: func() (bool, string, string) {
					return checks.MediaTypeEssence(got.MediaType) == MediaType, "media type " + MediaType, fmt.Sprintf("media type %q", got.MediaType)
				}},
				{Statements: key, Partial: keyMaterialPartial, Check: func() (bool, string, string) {
					return sameMember(out, jsonDoc, "verificationMethod")
				}},
			})
		},
	}
}

// producerJSONLDCase produces a document with a layered @context and
// checks the @context entry and the media type of the JSON-LD production.
func producerJSONLDCase() core.Case {
	sts := []string{d("json-ld-processors.2"), d("json-ld-processors.3"), d("json-ld-processors.4"), d("json-ld-processors.7")}
	return core.Case{
		ID: Name + "/representation/producer-json-ld", Profile: Name, Statements: sts,
		Needs: []core.Capability{core.CapDocumentProducer},
		Run: func(_ context.Context, s core.Subject) []core.Observation {
			got := kit.Produce(s.(core.DocumentProducer), ldDoc, Version)
			out, isObject := got.Doc()
			ctx, hasCtx := out.Get("@context")
			want, _ := ldDoc.Get("@context")
			return kit.RunRules("JSON-LD document with a layered @context", got.Err, []kit.Rule{
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
				{Statements: sts[2:3], Check: func() (bool, string, string) {
					return kit.ContextFirst(ctx, contextURL), "@context starting with " + contextURL, "@context " + checks.Compact(ctx)
				}},
				{Statements: sts[3:], Check: func() (bool, string, string) {
					return checks.MediaTypeEssence(got.MediaType) == MediaType, "media type " + MediaType, fmt.Sprintf("media type %q", got.MediaType)
				}},
			})
		},
	}
}

// sameMember reports whether got has the member name of want with an equal
// value.
func sameMember(got, want core.DocumentJSON, name string) (bool, string, string) {
	w, _ := want.Get(name)
	v, ok := got.Get(name)
	eq, at := checks.EqualJSON(v, w)
	return ok && eq, name + " " + checks.Compact(w), fmt.Sprintf("%s (differs at %q)", checks.Compact(v), at)
}

func rootText(p kit.Produced) string {
	if p.ParseErr != nil {
		return "output is not JSON: " + p.ParseErr.Error()
	}
	return "root " + p.Root.Kind.String()
}
