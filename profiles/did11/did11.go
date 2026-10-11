// Package did11 is the did-1.1 profile: DID 1.1 (W3C Candidate
// Recommendation Snapshot 5 March 2026), Controlled Identifiers 1.0 (W3C
// Recommendation 15 May 2025) and DID Resolution v1.0 (W3C Candidate
// Recommendation Draft 1 October 2026).
package did11

import (
	"github.com/sage-x-project/did-inspector/core"
	"github.com/sage-x-project/did-inspector/statements"
)

// Name is the profile name.
const Name = "did-1.1"

// Profile returns the profile with its cases.
func Profile() core.Profile {
	return core.Profile{
		Name:     Name,
		Title:    "DID 1.1 (CR Snapshot 2026-03-05), Controlled Identifiers 1.0 (REC 2025-05-15), DID Resolution v1.0 (CRD 2026-10-01)",
		SpecKeys: []string{statements.KeyDID11, statements.KeyCID10, statements.KeyRes10},
		Cases:    cases(),
	}
}

// cases returns the profile's cases. Cases are added statement by statement.
func cases() []core.Case {
	return nil
}
