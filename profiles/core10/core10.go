// Package core10 is the did-core-1.0 profile: DID Core 1.0 (W3C
// Recommendation 19 July 2022), including the resolution functions of its §7.
//
// The cases are grouped by specification area: DID and DID URL syntax with
// the DID parameters (syntax.json), the data model of DID documents
// (documents.json), production and consumption of the JSON and JSON-LD
// representations (representation.go), the resolve, resolveRepresentation
// and dereference functions of §7 against the fixture method "example"
// (registry.json, resolution.json, dereferencing.json), and the format rules
// every result of those functions must satisfy (invariants.go), and the
// observable recommendations (recommendations.go). Errors are
// the keyword strings of DID Core 1.0 (invalidDid, notFound, ...), not the
// error objects of DID Resolution. The fixtures are in testdata/ and are
// written from the specification text.
package core10

import (
	"embed"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
	"github.com/sage-x-project/did-inspector/statements"
)

// Name is the profile name.
const Name = "did-core-1.0"

// Version is the DID version the profile passes to producers, consumers
// and validators.
const Version = "1.0"

// Media types of the DID Core 1.0 representations (§6.2.1, §6.3.1).
const (
	MediaTypeJSON   = "application/did+json"
	MediaTypeJSONLD = "application/did+ld+json"
)

// contextURL is the base context of DID Core 1.0 (§6.3.1).
const contextURL = "https://www.w3.org/ns/did/v1"

//go:embed testdata/*.json
var testdata embed.FS

// Fixtures are the profile's decoded fixture files.
type Fixtures struct {
	Syntax        kit.SyntaxFile
	Documents     kit.DocFile
	Registry      *fixtures.Registry
	Resolution    kit.ScenarioFile
	Dereferencing kit.ScenarioFile
}

// LoadFixtures decodes the embedded fixture files.
func LoadFixtures() Fixtures {
	var f Fixtures
	kit.MustDecode("syntax.json", read("syntax.json"), &f.Syntax)
	kit.MustDecode("documents.json", read("documents.json"), &f.Documents)
	kit.MustDecode("resolution.json", read("resolution.json"), &f.Resolution)
	kit.MustDecode("dereferencing.json", read("dereferencing.json"), &f.Dereferencing)
	f.Registry = kit.MustRegistry("registry.json", read("registry.json"))
	return f
}

func read(name string) []byte {
	data, err := testdata.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return data
}

// Profile returns the profile with its cases.
func Profile() core.Profile {
	return core.Profile{
		Name:     Name,
		Title:    "DID Core 1.0 (W3C Recommendation 2022-07-19), including the resolution functions of §7",
		SpecKeys: []string{statements.KeyCore10},
		Cases:    cases(LoadFixtures()),
	}
}

func cases(f Fixtures) []core.Case {
	var out []core.Case
	out = append(out, kit.SyntaxCases(Name, f.Syntax)...)
	out = append(out, kit.DocCases(docConfig, f.Documents)...)
	out = append(out, representationCases()...)
	out = append(out, undefinedTermCases()...)
	out = append(out, kit.ScenarioCases(Name, "resolution", f.Registry, f.Resolution)...)
	out = append(out, kit.InvariantCase(Name+"/resolution/result-format", Name, f.Registry, resolutionInvariants(f.Registry), f.Resolution))
	out = append(out, kit.ScenarioCases(Name, "dereferencing", f.Registry, f.Dereferencing)...)
	out = append(out, kit.InvariantCase(Name+"/dereferencing/result-format", Name, f.Registry, dereferencingInvariants(f.Registry), f.Dereferencing))
	return out
}

// k returns the id of a DID Core 1.0 statement.
func k(s string) string { return statements.KeyCore10 + "#" + s }

// mediaTypeOf returns the media type a document fixture is consumed under:
// JSON-LD when it has @context, JSON otherwise.
func mediaTypeOf(f kit.DocFixture) string {
	if d, ok := f.Doc(); ok {
		if _, has := d.Get("@context"); has {
			return MediaTypeJSONLD
		}
	}
	return MediaTypeJSON
}

var docConfig = kit.DocConfig{
	Profile:               Name,
	Version:               Version,
	MediaType:             mediaTypeOf,
	ConsumerErrors:        []string{k("production-and-consumption.18")},
	ProducerNonConforming: []string{k("production-and-consumption.12")},
}
