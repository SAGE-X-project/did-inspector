// Package did11 is the did-1.1 profile: DID 1.1 (W3C Candidate
// Recommendation Snapshot 5 March 2026), Controlled Identifiers 1.0 (W3C
// Recommendation 15 May 2025) and DID Resolution v1.0 (W3C Candidate
// Recommendation Draft 1 October 2026).
//
// The cases are grouped by specification area: DID and DID URL syntax
// (syntax.json), the data model of DID and controlled identifier documents
// (documents.json), production and consumption of the JSON representation
// (representation.go), DID resolution (resolution.json) and DID URL
// dereferencing (dereferencing.json) against the fixture method "example"
// (registry.json), and the format rules every resolution and dereferencing
// result must satisfy (invariants.go). The fixtures are in testdata/ and are
// written from the specification text.
package did11

import (
	"embed"

	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/fixtures"
	"github.com/sage-x-project/did-inspector/profiles/internal/kit"
	"github.com/sage-x-project/did-inspector/statements"
)

// Name is the profile name.
const Name = "did-1.1"

// Version is the DID version the profile passes to producers, consumers
// and validators.
const Version = "1.1"

// MediaType is the media type of the DID 1.1 JSON representation (DID 1.1
// §6.2.1, §6.2.3).
const MediaType = "application/did"

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
		Title:    "DID 1.1 (CR Snapshot 2026-03-05), Controlled Identifiers 1.0 (REC 2025-05-15), DID Resolution v1.0 (CRD 2026-10-01)",
		SpecKeys: []string{statements.KeyDID11, statements.KeyCID10, statements.KeyRes10},
		Cases:    cases(LoadFixtures()),
	}
}

func cases(f Fixtures) []core.Case {
	var out []core.Case
	out = append(out, kit.SyntaxCases(Name, f.Syntax)...)
	out = append(out, kit.DocCases(docConfig, f.Documents)...)
	out = append(out, representationCases()...)
	out = append(out, kit.ScenarioCases(Name, "resolution", f.Registry, f.Resolution)...)
	out = append(out, kit.InvariantCase(Name+"/resolution/result-format", Name, f.Registry, resolutionInvariants(f.Registry), f.Resolution))
	out = append(out, kit.ScenarioCases(Name, "dereferencing", f.Registry, f.Dereferencing)...)
	out = append(out, kit.InvariantCase(Name+"/dereferencing/result-format", Name, f.Registry, dereferencingInvariants(f.Registry), f.Dereferencing))
	return out
}

// Statement id helpers.
func d(s string) string { return statements.KeyDID11 + "#" + s }
func c(s string) string { return statements.KeyCID10 + "#" + s }
func r(s string) string { return statements.KeyRes10 + "#" + s }

var docConfig = kit.DocConfig{
	Profile:               Name,
	Version:               Version,
	MediaType:             func(kit.DocFixture) string { return MediaType },
	ConsumerErrors:        []string{d("production-and-consumption.18"), c("conformance.2")},
	ProducerNonConforming: []string{d("production-and-consumption.12")},
}
